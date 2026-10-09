// Asks the parent for the AI step twice, which the real pipeline never does.
process.on("message", () => {
  process.send!({ type: "ask", id: 0, step: "propose", input: {} });
  process.send!({ type: "ask", id: 1, step: "propose", input: {} });
});
