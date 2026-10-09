// Keeps allocating: stands in for a parser blown up by a crafted file.
process.on("message", () => {
  const hoard: string[][] = [];
  for (;;) hoard.push(new Array(1_000_000).fill("x"));
});
