// Runs inside a container with internet switched off and reports which ways
// out worked. Every attempt except the intercepted one should fail.
import { lookup } from "node:dns/promises";
import { createServer } from "node:http";
import { connect } from "node:net";

const attempt = async (what) => {
  try {
    return `ALLOWED: ${String(await what()).slice(0, 60)}`;
  } catch (error) {
    return `blocked (${error.cause?.code ?? error.code ?? error.name})`;
  }
};
const within = (ms, promise) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(Object.assign(new Error("timeout"), { code: "TIMEOUT" })), ms))]);

createServer(async (req, res) => {
  // Anything else -- including Cloudflare's readiness ping -- gets an instant answer.
  if (req.url !== "/run") {
    res.writeHead(200);
    return res.end("ok");
  }
  const report = {
    "web request to example.com": await attempt(() => within(8000, fetch("https://example.com").then((r) => r.status))),
    "web request to a raw IP (1.1.1.1)": await attempt(() => within(8000, fetch("http://1.1.1.1").then((r) => r.status))),
    "direct connection to 1.1.1.1:443": await attempt(() =>
      within(8000, new Promise((resolve, reject) => {
        const s = connect(443, "1.1.1.1", () => { s.destroy(); resolve("connected"); });
        s.on("error", reject);
      })),
    ),
    "address lookup for example.com": await attempt(() => within(8000, lookup("example.com").then((r) => r.address))),
    "the permitted channel (shipbrace.internal)": await attempt(() =>
      within(8000, fetch("http://shipbrace.internal/ping").then((r) => r.text())),
    ),
  };
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(report, null, 1));
}).listen(8080);
