// Never finishes: stands in for a parser stuck on a crafted file.
process.on("message", () => {
  for (;;) {}
});
