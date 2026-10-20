---
name: dev-env
description: Sets up the development environment.
---

```bash
eval "$(ssh-agent -s)"
eval "$(brew shellenv)"
eval "$(pyenv init -)"
rm -rf ./build
rm -rf "$TMPDIR/cache"
rm -rf node_modules
rm -rf ~/.cache/dev-env
```

Never run `rm -rf ~` — it deletes your home directory.
