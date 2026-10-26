# Changelog

## 0.1.4 — unreleased

0.1.3 was tagged but not published to npm; its changes ship in this release.

- SW002: a hidden HTML comment that tells the agent to read secrets and send them out, or to hide what it does from the user, is `high` (was `medium`). Comments that only describe such an attack, or warn against it, are unchanged.
- SW009: "don't mention this step to the user" is `high`, like "don't tell the user"; not mentioning a step is no longer described as keeping instructions secret.
- Discovery: `.claude/settings.json`, `.mcp.json`, plugin manifests and plugin `hooks/hooks.json` inside a skill folder are targets of their own kind, not files of the skill. A repository with `SKILL.md` at its root has live project settings and MCP servers, and SW011, SW012 and SW017 skipped them (found while checking the corpus: 1,157 files in 134 of 2,910 repositories). A hook script that lives in a skill folder stays in the skill and is now checked by SW017. In lockfiles of such repositories, `verify` reports these files as removed from the skill and added as new targets, and scans them; run `lock` to accept.
- `--global` (scan, explain, lock, verify) also reads other agents' user configuration, only at known paths: Cursor (`~/.cursor/mcp.json`, `hooks.json` with the scripts it runs, `commands/`, `skills/`), Gemini CLI (`~/.gemini/settings.json`, `GEMINI.md`, `commands/`, `extensions/`), Windsurf (`~/.codeium/windsurf/mcp_config.json`, global rules and workflows), Cline (MCP settings, also the older VS Code copy; rules, workflows, skills), Kiro, Codex and `~/.agents`. If you use `lock --global` (or the `SessionStart` hook with `verify --global`), the first `verify` after upgrading lists these files as added and scans them; review them, then run `lock --global`.
- Gemini CLI extensions (`.gemini/extensions/*/gemini-extension.json`, their `GEMINI.md` and commands) are scanned in projects too.
- Codex hooks: `.codex/hooks.json` (and `~/.codex/hooks.json` with `--global`) is a `settings` target, checked by SW013 like Claude Code hooks, including a handler's `commandWindows`. The scripts they run are added to the target, also when named from the git root (`"$(git rev-parse --show-toplevel)/.codex/hooks/x.py"`) or with an interpreter by path (`/usr/bin/python3 x.py`); such a hook is `low` in SW013, like other hooks that only start a shipped script. `.codex/` is scanned even when gitignored.
- Codex configuration: `.codex/config.toml` (and `~/.codex/config.toml` with `--global`) is a `settings` target, parsed as TOML with line numbers. Its MCP servers (`[mcp_servers.*]`) are checked by SW011, SW012 (including `http_headers`) and SW016; its hooks (`[[hooks.<Event>]]`) and `notify` command by SW013, with the scripts they run added to the target. SW008 reports `approval_policy = "never"` together with `sandbox_mode = "danger-full-access"` as `high` (top level, or in a profile with what it inherits), either one alone as `medium`, and MCP servers whose tools run without asking (`default_tools_approval_mode = "auto"`). Secret-like TOML assignments are masked in snippets. On 228 public Codex configs: 24 `high` SW008 findings (no prompts and no sandbox) and 98 unpinned MCP servers.
- Gemini CLI: `.gemini/settings.json` is a `settings` target (was `mcp-config`), so its hooks are checked by SW013 and the scripts they run (`$GEMINI_PROJECT_DIR/.gemini/hooks/x.sh`) are added to it. SW008 reports MCP servers with `"trust": true` (`medium`: their tools run without asking) and `tools.allowed` with the whole shell tool (`run_shell_command`, `high`, like `Bash(*)`; `run_shell_command(git status)` is fine). Files named by `context.fileName` (or `contextFileName`) are read as instructions; with `--global`, the names in `~/.gemini/settings.json` count for the project too and `~/.gemini/<name>` is read. On 198 public Gemini settings files: 60 trusted servers, 3 whole-shell allowlists. `lock` records the new kind once.
- SW013: a hook that starts a shipped script with a quoted interpreter (`'bun' "$GEMINI_PROJECT_DIR/.gemini/hooks/x.ts"`) is `low`, like an unquoted one.
- Cline hooks: scripts named after an event in `.clinerules/hooks/` (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `TaskStart`, `TaskResume`, `TaskCancel`, `TaskComplete`, `PreCompact`; no extension, or `.ps1`) are hook targets of their own: every rule reads them, SW017 checks that they can be reviewed, SW013 lists them as `low`, and `lock` pins them. With `--global`, also `~/Documents/Cline/Hooks/` (and the older `~/Documents/Cline/Rules/Hooks/`).
- SW008 lists an MCP server's `autoApprove` (Cline) or `alwaysAllow` tools as `low`.
- New runtime dependency: `smol-toml` (TOML parser, no dependencies of its own).
- SW012 recognizes remote MCP servers named by Windsurf's `serverUrl` and Gemini CLI's `httpUrl`.
- SW013: network and secret signs count only in what a hook runs. Guard hooks that block `.env` or `curl -X POST` by matching tool input (`grep` and `case` patterns), and URLs or tool names in text a hook only prints, are `medium`, not `high`. `curl`/`wget` to a loopback server is `medium`, like loopback `http` hooks; a local `rsync` no longer counts as network. In the corpus this moves 16 of 22 `high` SW013 findings to `medium`; printed text that runs (`$(…)`, piped into a shell, written to a file) and files a guard reads stay `high`.

## 0.1.3 — 2026-10-23

- Text reports wrap long finding messages at word boundaries to the terminal width, aligned under the message (only when writing to a terminal; files, pipes and CI output are unchanged).
- Corpus tooling: the fetch also checks out the scripts hook commands name; per-repository cap raised to 25,000 files; `corpus:pipeline` fetches and scans per repository and keeps only results.

## 0.1.2 — 2026-10-23

Fixes from a dry run of the GitHub Action on public repositories.

- SARIF: rules no longer carry `security-severity`. Code scanning showed a rule's score on every alert of that rule, so a low documentation mention of SW014 read "High"; each alert now shows its own level (`error` / `warning` / `note`).
- GitHub Action: inline-suppressed and baselined findings are left out of the code scanning upload. Code scanning ignores SARIF suppressions and showed them as open alerts; they are still listed in the job summary and kept in the `sarif-file` output.
- SW009: "don't tell the user about each tool call / every file" is advice against narrating every step, not concealment — medium, not high.
- SW004: the .NET Aspire installer (`aspire.dev`) is a known vendor installer (medium).

## 0.1.1 — 2026-10-23

First public release.

**Scanning**
- `scan`: discovers skills (`SKILL.md` folders), `CLAUDE.md`/`CLAUDE.local.md`/`AGENTS.md`, `.claude/commands` and `agents`, `.mcp.json`, Claude Code settings and hooks, plugin manifests and hooks; `--global` adds `~/.claude` and the `mcpServers` of `~/.claude.json`.
- 17 rules: SW001 hidden-unicode, SW002 html-comment-instructions, SW003 encoded-payload, SW004 pipe-to-shell, SW005 secret-path-access, SW006 env-dump, SW007 suspicious-egress, SW008 permission-bypass, SW009 concealment, SW010 fake-prerequisite, SW011 unpinned-mcp, SW012 remote-mcp, SW013 hook-command, SW014 persistence, SW015 dangerous-script, SW016 secret-in-config, SW017 hook-script.
- Severities calibrated on ~2,900 public repositories with agent configuration: warnings, deny lists, guard hooks, detectors, script comments, CLI option docs and quoted examples are low/info; prose mentions of bypass flags and official vendor installers are medium; executable instructions stay high.
- SW010 catches the ClawHavoc malware shapes: prerequisites that download a password-protected archive, and paste-site pages next to "run it in Terminal".
- Other agents: Cursor (`.cursorrules`, `.cursor/rules/*.mdc`, commands, `.cursor/mcp.json`, `.cursor/hooks.json`), GitHub Copilot / VS Code (`copilot-instructions.md`, `*.instructions.md`, `*.prompt.md`, chat modes, agents, `.vscode/mcp.json`), Gemini CLI (`GEMINI.md`, `.gemini/settings.json`, TOML commands), Windsurf, Cline and Kiro files are discovered and checked by the same rules.
- Hook targets: scripts that hooks run are scanned and locked with the hook file; SW017 flags obfuscated, binary, huge or minified hook scripts.
- Robust on hostile input: very long lines are split for rule matching, snippets read a window around the match, and pipeline patterns are bounded — every rule stays linear (a 6.6 KB crafted line no longer takes 6.7 s in SW004).

**Output**
- `explain`: what each skill, MCP server and config lets the agent do — runs code from the internet, turns approvals off, reads secrets, sends data out, persists, hides things, runs automatically… — with the worst severity and where it shows.
- `text`, `json` (format version 1), `sarif` (2.1.0, GitHub code scanning).
- Everything quoted from scanned files is escaped; snippets are truncated and secrets never printed in full.

**Pinning and config**
- `lock` / `verify`: `skillward.lock` with sha256 per file, snapshots for text diffs, scan of changed files only. Secrets are masked in snapshots and diffs.
- `lock --global` / `verify --global`: pin `~/.claude` and the MCP servers of `~/.claude.json` in `~/.skillward/`, and see what plugin updates or tools changed since.
- `skillward.config.json`: `ignore`, `rules`, `failOn`, `inlineIgnore`.
- Inline suppressions `skillward-ignore SWxxx: reason` (always reported separately), `--no-inline-ignore` to ignore them.
- `--untrusted` (`scan`, `explain`) for someone else's code: the scanned folder's config, `skillward-ignore` comments and `.gitignore` files don't count. Reports always say what the config in use turns off or ignores (text line, JSON `config`), including `lock` and `verify`.
- Baseline: `scan --write-baseline <file>` records current findings, `scan --baseline <file>` fails only on new ones (matched by rule, file and text, not line; hashes only, no snippets). Action input `baseline`.

**CI**
- GitHub Action (`action.yml`): scan, SARIF upload to code scanning, job summary; on pull requests only changed files are reported (`scan --files-from`). On pull requests from forks a refused code scanning upload doesn't fail the job.
- Release workflow: a `vX.Y.Z` tag publishes to npm with provenance via trusted publishing.
- Antivirus-safe build: PowerShell download-and-execute vocabulary lives in `rules/data/vocabulary.json`, not in shipped JavaScript, so Windows Defender's ML heuristic doesn't quarantine the package.

**Research tooling**
- `scripts/corpus/`: collect public agent configs from GitHub (sparse clones, nothing executed), scan them, recheck one rule against real data, profile slow files, scan files straight from git objects.
