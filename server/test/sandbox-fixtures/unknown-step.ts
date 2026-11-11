// Asks the parent for a step that does not exist.
process.on("message", () => {
  process.send!({ type: "ask", id: 0, step: "fetch", input: "https://example.com" });
});
