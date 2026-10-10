// Keeps allocating: stands in for a parser blown up by a crafted file.
process.on("message", () => {
  const hoard: string[][] = [];
  // oxlint-disable-next-line unicorn/no-new-array -- a million-slot array is the point: it has to exhaust memory.
  for (;;) hoard.push(new Array(1_000_000).fill("x"));
});
