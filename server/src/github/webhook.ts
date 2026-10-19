import type { RepoSnapshot, ReviewResult } from "@shipbrace/guardrails";
import type { ReviewHistory } from "../history.ts";
import { verifyWebhookSignature } from "./auth.ts";
import { installationClient, type AppCredentials, type GitHubClient } from "./client.ts";
import { checkOutput } from "./report.ts";
import { fetchRepository } from "./repository.ts";
import { ReviewStoppedError } from "../sandbox/stopped.ts";

/**
 * GitHub tells this server when someone pushes; the server reviews that commit
 * and posts the result back as a check.
 *
 * This is the seam that makes the product work with any AI tool: every one of
 * them ends up saving code to a repository, so watching the repository covers
 * all of them without integrating with any.
 *
 * The handler answers GitHub at once and does the review afterwards, because
 * GitHub gives up waiting after ten seconds and a review can take longer.
 */

/**
 * One push to review: everything needed to do it later, somewhere else. On a
 * laptop it is run right after GitHub is answered; on Cloudflare it goes onto
 * a queue. Plain data, so it can travel either way.
 */
export interface PushJob {
  installationId: number;
  githubId: number;
  /** GitHub id of the person who pushed or pasted the link, when known. */
  ranBy?: number;
  owner: string;
  repo: string;
  sha: string;
}

export interface WebhookDeps {
  secret: string;
  /** Takes the job after GitHub has been answered. */
  schedule: (job: PushJob) => void;
  /**
   * Whether this installation's pushes may be reviewed yet: someone signed in
   * and accepted the notices for it. Until then nothing is sent anywhere.
   * Omitted on a laptop, where the person running it is the one who agreed.
   */
  isSetUp?: (installationId: number) => Promise<boolean>;
  /** The App was uninstalled (`"all"`), or repositories were removed from it: delete what was kept. */
  forget?: (installationId: number, repositoryIds: number[] | "all") => Promise<void>;
}

interface InstallationEvent {
  action?: string;
  installation?: { id?: number };
  repositories_removed?: Array<{ id?: number }>;
}

export interface ReviewDeps {
  credentials: AppCredentials;
  review: (snapshot: RepoSnapshot) => Promise<ReviewResult>;
  fetchImpl?: typeof fetch;
  log?: (message: string, error?: unknown) => void;
  /** Where finished reviews are kept. Without it, the check is the only record. */
  history?: Pick<ReviewHistory, "record">;
  /** The dashboard's public address, for links from the check. Needs `history`. */
  publicUrl?: string;
}

interface PushEvent {
  after?: string;
  deleted?: boolean;
  repository?: { id?: number; name?: string; owner?: { login?: string; name?: string } };
  installation?: { id?: number };
  sender?: { id?: number };
}

const CHECK_NAME = "ShipBrace security review";
const NO_COMMIT = /^0+$/;
const ANNOTATIONS_PER_REQUEST = 50;

export async function handleWebhook(
  deps: WebhookDeps,
  headers: { signature?: string | undefined; event?: string | undefined },
  rawBody: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  // Refused before the body is parsed: an unsigned message is not from GitHub.
  if (!verifyWebhookSignature(deps.secret, rawBody, headers.signature)) {
    return { status: 401, body: { error: "Invalid signature." } };
  }

  if (headers.event === "ping") return { status: 200, body: { ok: true } };
  if (headers.event === "installation" || headers.event === "installation_repositories") {
    return forgetRemoved(deps, headers.event, rawBody);
  }
  if (headers.event !== "push") return { status: 204, body: {} };

  let event: PushEvent;
  try {
    event = JSON.parse(rawBody) as PushEvent;
  } catch {
    return { status: 400, body: { error: "Invalid request." } };
  }

  const sha = event.after;
  const owner = event.repository?.owner?.login ?? event.repository?.owner?.name;
  const repo = event.repository?.name;
  const installation = event.installation?.id;
  const githubId = event.repository?.id;

  // A deleted branch has no commit to review.
  if (event.deleted || !sha || NO_COMMIT.test(sha)) return { status: 204, body: {} };
  if (!owner || !repo || !installation || !Number.isSafeInteger(githubId) || !/^[0-9a-f]{40}$/.test(sha)) {
    return { status: 400, body: { error: "Invalid request." } };
  }

  if (deps.isSetUp && !(await deps.isSetUp(installation))) {
    return { status: 202, body: { accepted: false, reason: "This installation has not been set up yet." } };
  }

  const ranBy = event.sender?.id;
  deps.schedule({ installationId: installation, githubId: githubId!, owner, repo, sha, ...(typeof ranBy === "number" && Number.isSafeInteger(ranBy) ? { ranBy } : {}) });
  return { status: 202, body: { accepted: true } };
}

/** Uninstalls and removed repositories: what was kept about them is deleted. */
async function forgetRemoved(
  deps: WebhookDeps,
  event: "installation" | "installation_repositories",
  rawBody: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  let body: InstallationEvent;
  try {
    body = JSON.parse(rawBody) as InstallationEvent;
  } catch {
    return { status: 400, body: { error: "Invalid request." } };
  }
  const installation = body.installation?.id;
  if (!deps.forget || !Number.isSafeInteger(installation)) return { status: 204, body: {} };

  if (event === "installation" && body.action === "deleted") {
    await deps.forget(installation!, "all");
    return { status: 200, body: { forgotten: "installation" } };
  }
  if (event === "installation_repositories" && body.action === "removed") {
    const ids = (body.repositories_removed ?? []).map((r) => r.id).filter((id): id is number => Number.isSafeInteger(id));
    if (ids.length > 0) await deps.forget(installation!, ids);
    return { status: 200, body: { forgotten: ids.length } };
  }
  return { status: 204, body: {} };
}

/** Reviews one push and posts the result back as a check. */
export async function reviewPush(
  deps: ReviewDeps,
  { installationId, githubId, ranBy, owner, repo, sha }: PushJob,
): Promise<void> {
  const log = deps.log ?? ((message, error) => console.error(message, error));
  const where = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

  let client: GitHubClient;
  let checkId: number;
  try {
    client = await installationClient(deps.credentials, installationId, deps.fetchImpl);
    ({ id: checkId } = await client.post<{ id: number }>(`${where}/check-runs`, {
      name: CHECK_NAME,
      head_sha: sha,
      status: "in_progress",
    }));
  } catch (error) {
    // Nothing can be reported to GitHub without these; the log is all there is.
    log(`could not start a check for ${owner}/${repo}@${sha.slice(0, 7)}:`, error);
    return;
  }

  try {
    console.log(`reviewing ${owner}/${repo}@${sha.slice(0, 7)}`);
    const fetched = await fetchRepository(client, owner, repo, sha);
    const result = await deps.review(fetched.snapshot);
    const output = checkOutput(result, fetched.skipped);
    const link = await keep(deps, {
      githubId,
      installationId,
      ...(ranBy === undefined ? {} : { ranBy }),
      owner,
      repo,
      commitSha: sha,
      conclusion: output.conclusion,
      title: output.title,
      result,
      skipped: fetched.skipped,
    });
    const summary = link
      ? `**[Open the full report](${link.review})** · [All reviews of this repository](${link.history})\n\n${output.summary}`
      : output.summary;

    // GitHub takes at most 50 notes per request; later batches add to the first.
    const batches = [];
    for (let i = 0; i < output.annotations.length; i += ANNOTATIONS_PER_REQUEST) {
      batches.push(output.annotations.slice(i, i + ANNOTATIONS_PER_REQUEST));
    }
    for (const batch of batches.length > 0 ? batches : [[]]) {
      await client.patch(`${where}/check-runs/${checkId}`, {
        ...(link ? { details_url: link.review } : {}),
        output: { title: output.title, summary, annotations: batch },
      });
    }
    await client.patch(`${where}/check-runs/${checkId}`, {
      status: "completed",
      conclusion: output.conclusion,
    });
    console.log(`posted ${output.conclusion} for ${owner}/${repo}@${sha.slice(0, 7)}: ${output.title}`);
  } catch (error) {
    log(`review failed for ${owner}/${repo}@${sha.slice(0, 7)}:`, error);
    // Never left spinning, and never a pass: a failed review says so.
    await client
      .patch(`${where}/check-runs/${checkId}`, {
        status: "completed",
        conclusion: "neutral",
        output: {
          title: "The review could not be completed",
          // A stopped review says why in fixed words; anything else stays in the log.
          summary: error instanceof ReviewStoppedError
            ? `${error.userMessage} Push again to retry; if it keeps happening, the server log has the details.`
            : "Nothing was checked for this commit. Push again to retry; if it keeps happening, the server log has the details.",
        },
      })
      .catch((reportError: unknown) => log("could not report the failure:", reportError));
  }
}

/**
 * Saves the finished review and returns the links to it. A failure here is
 * logged and the check is posted without links: the review itself is still
 * right, and withholding it because the history is down would hide a risk.
 */
async function keep(
  deps: ReviewDeps,
  review: Parameters<ReviewHistory["record"]>[0],
): Promise<{ review: string; history: string } | null> {
  if (!deps.history) return null;
  try {
    const { reviewId, historyId } = await deps.history.record(review);
    if (!deps.publicUrl) return null;
    return { review: `${deps.publicUrl}/reviews/${reviewId}`, history: `${deps.publicUrl}/history/${historyId}` };
  } catch (error) {
    (deps.log ?? console.error)(`could not save the review of ${review.owner}/${review.repo}@${review.commitSha.slice(0, 7)}:`, error);
    return null;
  }
}
