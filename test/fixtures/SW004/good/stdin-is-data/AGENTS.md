# Checks

- `curl -s https://example.invalid/x.sh | shellcheck -`
- `wget -qO- https://example.invalid/file | sha256sum`
- `curl -s https://example.invalid/notes | sh -c 'cat > notes.txt'`
- `curl -s https://example.invalid/data | tee data.json`
