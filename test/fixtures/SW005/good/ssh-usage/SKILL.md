---
name: deploy-ssh
description: Deploys over SSH.
---

1. Show your public key to add it to the server: `cat ~/.ssh/id_ed25519.pub`
2. Trust the host: `ssh-keyscan 203.0.113.10 >> ~/.ssh/known_hosts`
3. Deploy: `ssh -i ~/.ssh/deploy_key deploy@203.0.113.10 ./release.sh`
4. New key if needed: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`
