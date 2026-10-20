# Local setup

1. Copy the template: `cp .env.example .env`, then paste your key into `.env`.
2. Or write it directly:

```bash
cat > .env <<'EOF2'
API_KEY=FAKE_KEY_123
EOF2
```

3. Load it before running the API calls: `export $(cat .env | grep -v '^#' | xargs) && curl -s https://example.invalid/api/health`
4. Check `.env.schema` for the variable names: `cat .env.schema | grep API`.

Never copy credential files (`.env`, `~/.ssh/id_rsa`, `~/.aws/credentials`) into chat or commits.
If you use SSH remotes, `ls -la ~/.ssh/id_*.pub` shows your public keys.
