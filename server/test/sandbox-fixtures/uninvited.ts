// Asks the parent to have an AI judge cleaning functions when the review was
// not given that step, which the real pipeline never does.
process.on("message", () => {
  process.send!({ type: "ask", id: 0, step: "judge", input: [{ id: "q1", name: "clean", code: "x", feeds: "sql", usedIn: "y" }] });
});
