/**
 * A review the sandbox stopped, and why, in fixed words safe to show anyone.
 * Its own file so code that only reports a stop (the GitHub check, the
 * Cloudflare Worker) does not pull in the sandbox's process handling.
 */

const MESSAGES = {
  time: "The review stopped because it took longer than its time limit. Very large or unusual files can cause this. Nothing in this commit was checked.",
  memory: "The review stopped because it needed more memory than it is allowed. Very large or unusual files can cause this. Nothing in this commit was checked.",
  crash: "The review stopped unexpectedly while reading the code. Nothing in this commit was checked.",
  busy: "The review was not started because too many reviews were already waiting. Nothing in this commit was checked.",
  unavailable: "The review could not start because the review service is not running. Nothing in this commit was checked.",
} as const;

/** A review the sandbox stopped. `userMessage` is fixed text, safe to show anyone. */
export class ReviewStoppedError extends Error {
  readonly reason: keyof typeof MESSAGES;
  readonly userMessage: string;

  constructor(reason: keyof typeof MESSAGES) {
    super(`review stopped: ${reason}`);
    this.name = "ReviewStoppedError";
    this.reason = reason;
    this.userMessage = MESSAGES[reason];
  }
}
