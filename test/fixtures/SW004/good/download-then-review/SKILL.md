---
name: install-tool
description: Installs the CLI after verifying it.
---

```bash
curl -fsSLo install.sh https://example.invalid/install.sh
sha256sum -c install.sh.sha256
less install.sh
bash ./install.sh
```

Inspect APIs with `curl -s https://example.invalid/api | jq .` or
`curl -s https://example.invalid/api | python3 -m json.tool`.
Parse results with `curl -s https://example.invalid/data | node parse.js`.
If the download fails: `curl -fO https://example.invalid/x.tar.gz || bash ./fallback.sh`.
