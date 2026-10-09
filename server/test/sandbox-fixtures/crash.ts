// Dies outright: stands in for a native crash in the parser.
process.on("message", () => process.abort());
