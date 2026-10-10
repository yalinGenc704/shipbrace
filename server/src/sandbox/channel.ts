import type { Socket } from "node:net";
import { deserialize, serialize } from "node:v8";

/**
 * The channel between the server and the review container: one Unix socket,
 * messages framed as a 4-byte length followed by the body.
 *
 * The two directions are deliberately encoded differently. Server to reviewer
 * uses V8's format, because a snapshot holds Maps and Sets. Reviewer to server
 * uses plain JSON, because the reviewer is the side that reads hostile code:
 * if it were ever taken over, what it sends back is parsed by the simplest,
 * strictest decoder available, and capped in size.
 */

export const MAX_TO_REVIEWER = 128 * 1024 * 1024;
export const MAX_FROM_REVIEWER = 64 * 1024 * 1024;

export function send(socket: Socket, message: unknown, encoding: "v8" | "json"): void {
  const body = encoding === "v8" ? serialize(message) : Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  socket.write(Buffer.concat([header, body]));
}

/**
 * Calls `onMessage` for each complete message. A message over `maxBytes`, or
 * one that does not decode, ends the connection through `onBad`: the other
 * side is not following the protocol, and nothing it sends after is trusted.
 */
export function receive(
  socket: Socket,
  encoding: "v8" | "json",
  maxBytes: number,
  onMessage: (message: unknown) => void,
  onBad: (why: string) => void,
): void {
  let buffered = Buffer.alloc(0);
  let broken = false;

  socket.on("data", (chunk: Buffer) => {
    if (broken) return;
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 4) {
      const length = buffered.readUInt32BE(0);
      if (length > maxBytes) {
        broken = true;
        return onBad(`message of ${length} bytes is over the ${maxBytes}-byte limit`);
      }
      if (buffered.length < 4 + length) return;
      const body = buffered.subarray(4, 4 + length);
      buffered = buffered.subarray(4 + length);
      let message: unknown;
      try {
        message = encoding === "v8" ? deserialize(body) : JSON.parse(body.toString("utf8"));
      } catch {
        broken = true;
        return onBad("message could not be decoded");
      }
      onMessage(message);
    }
  });
}
