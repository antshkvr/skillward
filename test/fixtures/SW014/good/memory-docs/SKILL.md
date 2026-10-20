---
name: memory-notes
description: Keeps project notes and conventions up to date.
---

# Memory notes

- If a term is used often, add it to CLAUDE.md under Glossary.
- Register new agents in AGENTS.md.
- Follow directory priority: existing > CLAUDE.md > ask.
- Collect `<project>/CLAUDE.md` and `<project>/.claude/rules/*.md` before editing.
- Write a one-line entry to `~/.claude/plugins/config/memory-notes/log.md` after each run.
- Never use `launchctl submit` for background work.

Check the hooks path first: `git config --global core.hooksPath 2>/dev/null`.
