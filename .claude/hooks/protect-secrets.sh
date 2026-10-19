#!/bin/sh
# Blocks Claude's file tools from opening or changing files that hold secrets:
# .env and .env.* (but not *.example), .dev.vars (but not .dev.vars.example),
# and *.pem keys. Runs before Read, Edit, Write, MultiEdit and NotebookEdit.
# Shell commands are not covered; the project rule (CLAUDE.md) still applies.
path=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
[ -z "$path" ] && exit 0
name=$(basename "$path")
case "$name" in
  *.example) exit 0 ;;
  .env|.env.*|.dev.vars|.dev.vars.*|*.pem)
    jq -n --arg n "$name" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: ("\($n) holds secrets: this project blocks reading or editing it with Claude. Change it yourself if needed.")}}'
    exit 0 ;;
esac
exit 0
