#!/bin/sh
# Formats the file Claude Code just edited.
file=$(jq -r '.tool_input.file_path')
npx prettier --write "$file" >/dev/null 2>&1 || true
