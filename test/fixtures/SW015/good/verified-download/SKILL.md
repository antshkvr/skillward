---
name: tool-installer
description: Installs a pinned tool release.
---

```bash
curl -fsSLo tool.tar.gz https://example.invalid/tool-1.2.3.tar.gz
sha256sum -c tool.tar.gz.sha256
tar xzf tool.tar.gz
./tool/bin/tool --version
```
