import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { AlertTriangle, ArrowLeft, CircleHelp, GitCommitHorizontal, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { formatWhen, loadHistory, loadStoredReview, NoAccess, NotFound, type Conclusion } from "../lib/history.ts";
import { ReviewView } from "./ReviewPage.tsx";
import { Loading } from "./ui.tsx";

/**
 * A review kept from a push, at the address the GitHub check links to.
 *
 * It always says which commit it describes and when, so an old review is never
 * read as the state of the code today.
 */
export function StoredReviewPage({ id }: { id: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["stored-review", id],
    queryFn: () => loadStoredReview(id),
    retry: (count, e) => !(e instanceof NotFound) && !(e instanceof NoAccess) && count < 1,
  });

  if (isPending) return <Loading>Loading the review…</Loading>;
  if (error || !data) {
    return (
      <Problem>
        {error instanceof NoAccess
          ? "This review belongs to a repository your GitHub account can't see. Ask its owner for access on GitHub."
          : error instanceof NotFound
          ? "There is no review at this address. Check that the link was copied in full."
          : "The review could not be loaded. Do not treat this as a pass."}
      </Problem>
    );
  }

  const { owner, name, historyId } = data.repository;
  const { overLimit, tooLarge, treeTruncated } = data.skipped;

  return (
    <ReviewView
      review={data.result}
      context={
        <div className="mb-4 space-y-3">
          <Link
            to="/history/$id"
            params={{ id: historyId }}
            className="inline-flex items-center gap-1.5 text-sm text-ink-soft hover:text-ink"
          >
            <ArrowLeft className="size-4" aria-hidden />
            All reviews of {owner}/{name}
          </Link>
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-ink-soft">
            <GitCommitHorizontal className="size-4" aria-hidden />
            <span>
              {owner}/{name} at commit <code className="font-mono text-ink">{data.commitSha.slice(0, 7)}</code>,
              reviewed {formatWhen(data.createdAt)}. Later changes are not included.
            </span>
          </p>
          {(overLimit > 0 || tooLarge > 0 || treeTruncated) && (
            <p className="rounded-xl bg-warn-bg p-3 text-sm text-ink">
              <strong>Not everything was read.</strong> This repository is larger than one review covers, so some
              files were left out. Problems in them would not appear here.
            </p>
          )}
        </div>
      }
    />
  );
}

/** Every kept review of one repository, newest first. */
export function HistoryPage({ id }: { id: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["history", id],
    queryFn: () => loadHistory(id),
    retry: (count, e) => !(e instanceof NotFound) && !(e instanceof NoAccess) && count < 1,
  });

  if (isPending) return <Loading>Loading the review history…</Loading>;
  if (error || !data) {
    return (
      <Problem>
        {error instanceof NoAccess
          ? "This history belongs to a repository your GitHub account can't see. Ask its owner for access on GitHub."
          : error instanceof NotFound
          ? "There is no review history at this address. Check that the link was copied in full."
          : "The review history could not be loaded."}
      </Problem>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:py-12">
      <h1 className="text-xl font-semibold text-ink sm:text-2xl">
        {data.owner}/{data.name}
      </h1>
      <p className="mt-1.5 text-sm text-ink-soft">
        Every push that was reviewed, newest first. Each one describes the code as it was at that commit.
      </p>

      {data.reviews.length === 0 ? (
        <p className="mt-6 text-sm text-ink-soft">No reviews yet.</p>
      ) : (
        <ol className="mt-6 divide-y divide-line rounded-2xl border border-line bg-surface-raised">
          {data.reviews.map((review) => (
            <li key={review.id}>
              <Link
                to="/reviews/$id"
                params={{ id: review.id }}
                className="flex items-start gap-3 p-4 hover:bg-surface sm:items-center"
              >
                <ConclusionIcon conclusion={review.conclusion} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-ink">{review.title}</span>
                  <span className="mt-0.5 block text-xs text-ink-soft">
                    <code className="font-mono">{review.commitSha.slice(0, 7)}</code> · {formatWhen(review.createdAt)}
                  </span>
                </span>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

/** The same three marks as the GitHub check, in the same words' spirit: none says "secure". */
function ConclusionIcon({ conclusion }: { conclusion: Conclusion }) {
  const { icon, label, className } = {
    failure: { icon: AlertTriangle, label: "High-risk problems", className: "text-danger" },
    neutral: { icon: CircleHelp, label: "Problems, none high-risk", className: "text-warn" },
    success: { icon: ShieldCheck, label: "No proven problems", className: "text-ok" },
  }[conclusion];
  const Icon = icon;
  return <Icon className={`mt-0.5 size-5 shrink-0 sm:mt-0 ${className}`} aria-label={label} role="img" />;
}

function Problem({ children }: { children: ReactNode }) {
  return <p className="p-8 text-sm text-danger">{children}</p>;
}
