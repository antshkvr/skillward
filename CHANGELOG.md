# Changelog

## 0.1.1 — 2026-10-20

First public release.

**Scanning**
- `scan`: discovers skills (`SKILL.md` folders), `CLAUDE.md`/`CLAUDE.local.md`/`AGENTS.md`, `.claude/commands` and `agents`, `.mcp.json`, Claude Code settings and hooks, plugin manifests and hooks; `--global` adds `~/.claude` and the `mcpServers` of `~/.claude.json`.
- 16 rules: SW001 hidden-unicode, SW002 html-comment-instructions, SW003 encoded-payload, SW004 pipe-to-shell, SW005 secret-path-access, SW006 env-dump, SW007 suspicious-egress, SW008 permission-bypass, SW009 concealment, SW010 fake-prerequisite, SW011 unpinned-mcp, SW012 remote-mcp, SW013 hook-command, SW014 persistence, SW015 dangerous-script, SW016 secret-in-config.
- Severities calibrated on ~2,900 public repositories with agent configuration: warnings, deny lists, guard hooks, detectors, script comments, CLI option docs and quoted examples are low/info; prose mentions of bypass flags and official vendor installers are medium; executable instructions stay high.
- SW010 catches the ClawHavoc malware shapes: prerequisites that download a password-protected archive, and paste-site pages next to "run it in Terminal".
- No quadratic work on minified one-line files.

**Output**
- `explain`: what each skill, MCP server and config lets the agent do — runs code from the internet, turns approvals off, reads secrets, sends data out, persists, hides things, runs automatically… — with the worst severity and where it shows.
- `text`, `json` (format version 1), `sarif` (2.1.0, GitHub code scanning).
- Everything quoted from scanned files is escaped; snippets are truncated and secrets never printed in full.

**Pinning and config**
- `lock` / `verify`: `skillward.lock` with sha256 per file, snapshots for text diffs, scan of changed files only.
- `skillward.config.json`: `ignore`, `rules`, `failOn`, `inlineIgnore`.
- Inline suppressions `skillward-ignore SWxxx: reason` (always reported separately), `--no-inline-ignore` for audits.

**CI**
- GitHub Action (`action.yml`): scan, SARIF upload to code scanning, job summary; on pull requests only changed files are reported (`scan --files-from`).
- Release workflow: a `vX.Y.Z` tag publishes to npm with provenance via trusted publishing.
- Antivirus-safe build: PowerShell download-and-execute vocabulary lives in `rules/data/vocabulary.json`, not in shipped JavaScript, so Windows Defender's ML heuristic doesn't quarantine the package.

**Research tooling**
- `scripts/corpus/`: collect public agent configs from GitHub (sparse clones, nothing executed), scan them, recheck one rule against real data, profile slow files, scan files straight from git objects.
