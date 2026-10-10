import { Container } from "@cloudflare/containers";

export { ContainerProxy } from "@cloudflare/containers";

/**
 * Proof, on Cloudflare itself, that a container with `enableInternet = false`
 * has no way out except the host the reviewer uses (see ../src/reviewer.ts).
 * Deploy, open /run, then delete: `npx wrangler deploy` and
 * `npx wrangler delete` from this folder. Not part of the product.
 */
export class Probe extends Container {
  override defaultPort = 8080;
  override sleepAfter = "1m";
  override enableInternet = false;
}

Probe.outboundByHost = { "shipbrace.internal": (() => new Response("intercepted by the Worker")) as never };

interface Env {
  PROBE: DurableObjectNamespace<Probe>;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname !== "/run") return new Response("Not found.", { status: 404 });
    return env.PROBE.get(env.PROBE.idFromName("probe")).fetch("http://probe/run");
  },
};
