import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { fileURLToPath } from "node:url";

// Tries everything a hijacked parser would want, and reports what worked.
const root = fileURLToPath(new URL("../../../", import.meta.url));
const attempt = async (what: () => unknown) => {
  try {
    await what();
    return "allowed";
  } catch (error) {
    // fetch wraps the refusal: the reason is on `cause`.
    const { code, cause } = error as { code?: string; cause?: { code?: string } };
    return code === "ERR_ACCESS_DENIED" || cause?.code === "ERR_ACCESS_DENIED"
      ? "denied"
      : `failed: ${(error as Error).message.slice(0, 80)}`;
  }
};

process.on("message", async () => {
  const report = {
    env: Object.keys(process.env),
    readProjectFile: await attempt(() => readFileSync(`${root}CLAUDE.md`)),
    readEnvFile: await attempt(() => readFileSync(`${root}.env.example`)),
    readHome: await attempt(() => readFileSync(`${process.env.HOME ?? "/etc"}/.ssh/known_hosts`)),
    readSystem: await attempt(() => readFileSync("/etc/hosts")),
    write: await attempt(() => writeFileSync(`${root}server/test/sandbox-fixtures/escaped.txt`, "x")),
    run: await attempt(() => execFileSync("/bin/echo", ["hi"])),
    network: await attempt(() => fetch("https://example.com")),
    socket: await attempt(
      () =>
        new Promise((resolve, reject) => {
          const socket = connect(443, "1.1.1.1", () => resolve(socket.destroy()));
          socket.on("error", reject);
        }),
    ),
    readOwnPackages: await attempt(() => readFileSync(`${root}packages/guardrails/package.json`)),
  };
  process.send!({ type: "done", result: report });
});
