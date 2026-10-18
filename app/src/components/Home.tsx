import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { AlertTriangle, CircleHelp, ExternalLink, Loader2, LogIn, LogOut, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  acceptNotice,
  loadInstallations,
  loadMe,
  loadRepos,
  pasteLink,
  rememberLink,
  saveSettings,
  setUpInstallation,
  signInUrl,
  signOut,
  takeRememberedLink,
  type ConnectedRepo,
  type PasteResult,
} from "../lib/account.ts";
import { formatWhen } from "../lib/history.ts";
import { Loading } from "./ui.tsx";

/**
 * The hosted front page: sign in with GitHub, accept the notices once, then
 * paste a repository link. Each step only appears when the one before it is
 * done, so nobody can reach "review" without having read what it involves.
 */
export function Home() {
  const me = useQuery({ queryKey: ["me"], queryFn: loadMe });

  if (me.isPending) return <Loading>Loading…</Loading>;
  if (me.error || !me.data) return <Shell><p className="text-sm text-danger">ShipBrace could not be reached. Please try again in a moment.</p></Shell>;
  if (!me.data.signedIn) return <SignedOut />;
  if (!me.data.noticeAccepted) return <Notice version={me.data.noticeVersion} />;
  return <Paste login={me.data.login} />;
}

function Shell({ children, login }: { children: ReactNode; login?: string }) {
  return (
    <div className="mx-auto max-w-2xl px-4 py-10 sm:py-16">
      <header className="mb-8 flex items-center justify-between gap-4">
        <span className="text-lg font-semibold text-ink">ShipBrace</span>
        {login && (
          <button type="button" onClick={() => void signOut()} className="inline-flex items-center gap-1.5 text-sm text-ink-soft hover:text-ink">
            <LogOut className="size-4" aria-hidden />
            Sign out {login}
          </button>
        )}
      </header>
      {children}
    </div>
  );
}

const button = "inline-flex items-center justify-center gap-2 rounded-lg bg-ink px-4 py-2.5 text-sm font-medium text-surface hover:opacity-90 disabled:opacity-50";

function SignedOut() {
  return (
    <Shell>
      <h1 className="text-2xl font-semibold text-ink sm:text-3xl">A safety check for apps built with AI</h1>
      <p className="mt-3 text-sm leading-relaxed text-ink-soft">
        Paste your GitHub repository's link and ShipBrace reviews its security: what's proven wrong, why it matters, and
        what to do, in plain language. After that, every change you push is checked automatically.
      </p>
      <a href={signInUrl("/")} className={`${button} mt-6`}>
        <LogIn className="size-4" aria-hidden />
        Sign in with GitHub
      </a>
      <p className="mt-3 text-xs text-ink-soft">ShipBrace never sees or stores a password.</p>
      {new URLSearchParams(window.location.search).has("invite-only") && (
        <p className="mt-4 rounded-xl bg-review-bg p-3 text-sm text-ink">
          ShipBrace isn't open to everyone yet. Your GitHub account isn't on the invite list.
        </p>
      )}
    </Shell>
  );
}

/**
 * What happens to someone's code, said before anything happens to it. Keep in
 * step with docs/legal/third-party-services.md, and change NOTICE_VERSION in
 * cloud/src/accounts.ts whenever this changes, so everyone is asked again.
 */
function Notice({ version }: { version: string }) {
  const client = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function accept() {
    setBusy(true);
    const result = await acceptNotice(version);
    setBusy(false);
    if (result.ok) void client.invalidateQueries({ queryKey: ["me"] });
    else setError(result.error ?? "That didn't work. Please reload the page.");
  }

  const point = (title: string, text: ReactNode) => (
    <li>
      <p className="text-sm font-medium text-ink">{title}</p>
      <p className="mt-1 text-sm leading-relaxed text-ink-soft">{text}</p>
    </li>
  );

  return (
    <Shell>
      <h1 className="text-xl font-semibold text-ink sm:text-2xl">Before your first review</h1>
      <p className="mt-2 text-sm text-ink-soft">What ShipBrace does with your code, in full. Nothing below happens until you continue.</p>
      <ul className="mt-6 space-y-5">
        {point("What ShipBrace reads", "The code in repositories you connect, read from GitHub. It is read, never run, in a sealed container with no internet access.")}
        {point(
          "What leaves ShipBrace",
          "The names and versions of the public packages your app uses are sent to OSV.dev, a free database of known flaws run by Google. Never your code, your file names, or private package names. It's on unless you switch it off: there's a switch under Settings once you've connected a repository.",
        )}
        {point(
          "The AI step",
          "Off. If it's ever switched on, short excerpts of your code (with recognised secrets removed) would be sent to Anthropic, the AI provider, to suggest places to check. You'll be asked again before that happens.",
        )}
        {point(
          "What's kept, and for how long",
          "Each review, including short excerpts of the code it's about (secrets removed), for 90 days. Everything is deleted sooner if you remove ShipBrace from a repository or uninstall it on GitHub.",
        )}
        {point("Who can see it", "Only people GitHub lets see the repository. ShipBrace asks GitHub every time a review is opened.")}
        {point("What a review is not", "A review reports what it was able to check. It is not a guarantee that your app is secure.")}
      </ul>
      <p className="mt-6 text-xs text-ink-soft">A full privacy policy is being prepared with legal review.</p>
      <button type="button" onClick={() => void accept()} disabled={busy} className={`${button} mt-4`}>
        {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}I understand, continue
      </button>
      {error && <p className="mt-3 text-sm text-danger">{error}</p>}
    </Shell>
  );
}

function Paste({ login }: { login: string }) {
  const navigate = useNavigate();
  const [link, setLink] = useState(() => takeRememberedLink());
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PasteResult | null>(null);
  const [waitingFor, setWaitingFor] = useState<{ githubId: number; since: number } | null>(null);
  const repos = useQuery({ queryKey: ["repos"], queryFn: loadRepos, refetchInterval: waitingFor ? 4_000 : false });
  const autoSubmitted = useRef(false);

  // Once the queued review is saved, open it.
  useEffect(() => {
    if (!waitingFor) return;
    const repo = repos.data?.find((r) => r.githubId === waitingFor.githubId);
    if (repo?.latest && Date.parse(repo.latest.createdAt) >= waitingFor.since - 5_000) {
      setWaitingFor(null);
      void navigate({ to: "/reviews/$id", params: { id: repo.latest.id } });
    }
  }, [repos.data, waitingFor, navigate]);

  async function submit(event?: FormEvent) {
    event?.preventDefault();
    if (!link.trim() || busy) return;
    setBusy(true);
    setResult(null);
    const outcome = await pasteLink(link);
    setBusy(false);
    setResult(outcome);
    if (outcome.status === "queued") setWaitingFor({ githubId: outcome.repository.githubId, since: Date.now() });
    if (outcome.status === "needs-install") rememberLink(link);
  }

  // Coming back from GitHub with a link pasted before: try it again once.
  useEffect(() => {
    if (link && !autoSubmitted.current) {
      autoSubmitted.current = true;
      void submit();
    }
  }, []);

  return (
    <Shell login={login}>
      <h1 className="text-xl font-semibold text-ink sm:text-2xl">Review a repository</h1>
      <form onSubmit={(e) => void submit(e)} className="mt-4 flex flex-col gap-2 sm:flex-row">
        <label htmlFor="link" className="sr-only">GitHub repository link</label>
        <input
          id="link"
          value={link}
          onChange={(e) => setLink(e.target.value)}
          placeholder="https://github.com/you/your-app"
          autoComplete="off"
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-line bg-surface-raised px-3 py-2.5 text-sm text-ink placeholder:text-ink-soft"
        />
        <button type="submit" disabled={busy || !link.trim()} className={button}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}Review
        </button>
      </form>
      <Outcome result={result} waiting={Boolean(waitingFor)} />

      <Settings />

      <h2 className="mt-10 text-sm font-semibold text-ink">Connected repositories</h2>
      {repos.isPending ? (
        <p className="mt-2 text-sm text-ink-soft">Loading…</p>
      ) : !repos.data || repos.data.length === 0 ? (
        <p className="mt-2 text-sm text-ink-soft">None yet. Paste a link above to connect your first one.</p>
      ) : (
        <ul className="mt-3 divide-y divide-line rounded-2xl border border-line bg-surface-raised">
          {repos.data.map((repo) => (
            <RepoRow key={repo.githubId} repo={repo} />
          ))}
        </ul>
      )}
    </Shell>
  );
}

function Outcome({ result, waiting }: { result: PasteResult | null; waiting: boolean }) {
  if (!result) return null;
  if (result.status === "queued") {
    return (
      <p className="mt-3 flex items-center gap-2 text-sm text-ink-soft">
        {waiting && <Loader2 className="size-4 animate-spin" aria-hidden />}
        Reviewing {result.repository.owner}/{result.repository.name}. This usually takes under a minute; the report opens by itself.
      </p>
    );
  }
  if (result.status === "needs-install") {
    return (
      <div className="mt-3 rounded-xl bg-review-bg p-4 text-sm text-ink">
        <p>{result.message}</p>
        <a href={result.installUrl} className="mt-2 inline-flex items-center gap-1.5 font-medium underline">
          Allow ShipBrace on GitHub <ExternalLink className="size-3.5" aria-hidden />
        </a>
      </div>
    );
  }
  return <p className="mt-3 text-sm text-danger">{result.error}</p>;
}

function RepoRow({ repo }: { repo: ConnectedRepo }) {
  const Icon = !repo.latest ? CircleHelp : repo.latest.conclusion === "failure" ? AlertTriangle : repo.latest.conclusion === "neutral" ? CircleHelp : ShieldCheck;
  const tone = !repo.latest ? "text-ink-soft" : repo.latest.conclusion === "failure" ? "text-danger" : repo.latest.conclusion === "neutral" ? "text-warn" : "text-ok";
  return (
    <li className="flex items-start gap-3 p-4 sm:items-center">
      <Icon className={`mt-0.5 size-5 shrink-0 sm:mt-0 ${tone}`} aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block text-sm text-ink">{repo.owner}/{repo.name}</span>
        <span className="mt-0.5 block text-xs text-ink-soft">
          {repo.latest ? `${repo.latest.title} · ${formatWhen(repo.latest.createdAt)}` : "Not reviewed yet"}
        </span>
      </span>
      {repo.historyId && (
        <Link to="/history/$id" params={{ id: repo.historyId }} className="shrink-0 text-sm text-ink-soft underline hover:text-ink">
          History
        </Link>
      )}
    </li>
  );
}

/**
 * What leaves the platform, per GitHub account or organisation ShipBrace is
 * installed on. A switch only changes reviews started after it is flipped.
 */
function Settings() {
  const client = useQueryClient();
  const data = useQuery({ queryKey: ["installations"], queryFn: loadInstallations });
  const [error, setError] = useState("");
  if (!data.data || data.data.installations.length === 0) return null;

  async function flip(id: number, change: { packageLookup?: boolean; aiReview?: boolean }) {
    setError("");
    const result = await saveSettings(id, change);
    if (!result.ok) setError(result.error ?? "That didn't save. Please try again.");
    void client.invalidateQueries({ queryKey: ["installations"] });
  }

  return (
    <section className="mt-10">
      <h2 className="text-sm font-semibold text-ink">Settings</h2>
      <ul className="mt-3 space-y-3">
        {data.data.installations.map((inst) => (
          <li key={inst.id} className="rounded-2xl border border-line bg-surface-raised p-4">
            <p className="text-sm font-medium text-ink">{inst.account}</p>
            <Switch
              label="Check packages for known flaws"
              detail="Sends the names and versions of your public packages to OSV.dev. Never your code."
              on={inst.packageLookup}
              onChange={(on) => void flip(inst.id, { packageLookup: on })}
            />
            <Switch
              label="AI-assisted review"
              detail={data.data!.aiAvailable ? "Sends short excerpts of your code, secrets removed, to Anthropic." : "Not available yet. Nothing is sent to an AI."}
              on={inst.aiReview}
              disabled={!data.data!.aiAvailable}
              onChange={(on) => void flip(inst.id, { aiReview: on })}
            />
          </li>
        ))}
      </ul>
      {error && <p className="mt-2 text-sm text-danger">{error}</p>}
    </section>
  );
}

function Switch({ label, detail, on, disabled, onChange }: { label: string; detail: string; on: boolean; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <label className={`mt-3 flex items-start justify-between gap-4 ${disabled ? "opacity-60" : "cursor-pointer"}`}>
      <span>
        <span className="block text-sm text-ink">{label}</span>
        <span className="mt-0.5 block text-xs text-ink-soft">{detail}</span>
      </span>
      <input
        type="checkbox"
        role="switch"
        checked={on}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 size-5 shrink-0 accent-[var(--color-ok)]"
      />
    </label>
  );
}

/** Where GitHub sends people after they allow ShipBrace on a repository. */
export function SetupPage() {
  const me = useQuery({ queryKey: ["me"], queryFn: loadMe });
  const [state, setState] = useState<"working" | "done" | "failed">("working");
  const id = Number(new URLSearchParams(window.location.search).get("installation_id"));

  useEffect(() => {
    if (!me.data) return;
    if (!me.data.signedIn) {
      window.location.href = signInUrl(window.location.pathname + window.location.search);
      return;
    }
    if (!me.data.noticeAccepted || !Number.isSafeInteger(id)) return;
    void setUpInstallation(id).then((r) => setState(r.ok ? "done" : "failed"));
  }, [me.data, id]);

  if (me.data?.signedIn && !me.data.noticeAccepted) return <Notice version={me.data.noticeVersion} />;
  if (state === "working") return <Loading>Finishing setup…</Loading>;
  return (
    <Shell>
      <h1 className="text-xl font-semibold text-ink">{state === "done" ? "ShipBrace is set up" : "Setup didn't finish"}</h1>
      <p className="mt-2 text-sm text-ink-soft">
        {state === "done"
          ? "Every change pushed to the repositories you chose will now be reviewed. To review one right now, paste its link."
          : "GitHub didn't confirm that this installation is yours. Please try installing again from your repository's link."}
      </p>
      <Link to="/" className={`${button} mt-6`}>Continue</Link>
    </Shell>
  );
}
