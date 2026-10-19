#!/bin/sh
# After Claude edits a TypeScript or JavaScript file, lint just that file
# (oxlint takes milliseconds) and hand any problems back to Claude to fix.
path=$(jq -r '.tool_input.file_path // .tool_response.filePath // empty')
case "$path" in
  *.ts|*.tsx|*.js|*.mjs) ;;
  *) exit 0 ;;
esac
[ -f "$path" ] || exit 0
cd "$CLAUDE_PROJECT_DIR" || exit 0
out=$(./node_modules/.bin/oxlint --deny-warnings "$path" 2>&1) && exit 0
# Exit 2 shows the lint output to Claude, which then fixes it.
printf '%s\n' "$out" >&2
exit 2
