# skillward — SPEC

## 1. What it is

A CLI that checks AI-agent instruction files for dangerous content and behavior: `SKILL.md` and skill files,
`CLAUDE.md`, `AGENTS.md`, MCP server configs, Claude Code settings and hooks — and the equivalent files of Cursor, GitHub
Copilot, Gemini CLI, Windsurf, Cline and Kiro.

**Problem.** Skills and instruction files aren't documentation: they are commands an agent executes with the developer's
permissions. Public registries already carry malicious skills, and classic scanners miss attacks written in plain text.

**Model:** open core. A free, open-source CLI and GitHub Action for developers; a team edition later (section 12).

**Positioning, in one sentence.** skillward shows what you agree to when you give an agent a skill, an MCP server or
someone else's repository — and makes sure it doesn't change behind your back.

It is a permissions screen, not an antivirus:
- **It allows or blocks nothing by itself.** A finding is a file, a line and a reason; a human or CI (`--fail-on`) decides.
- **Not only skills:** everything that steers the agent — the `CLAUDE.md`/`AGENTS.md` of a repository you open, MCP
  servers, hooks, `settings.json`, plugins. Opening someone else's repository in an agent means accepting its
  instructions and hooks.
- **Not just once:** `lock`/`verify` pin what was reviewed and catch changes after a skill is already trusted (like an
  app asking for new permissions on update).
- **No malice required:** risky-but-honest patterns (`--yolo`, a vendor's official `curl | sh` installer) are shown
  too, at a lower severity.

Versus antivirus: antivirus looks for known malicious code by signatures and heuristics; skillward looks for dangerous
**instructions and capabilities** (download and run, turn approvals off, read secrets, persist on the machine, hide
actions), so it catches the shape of an attack whatever the payload. The two are neighboring layers: in the corpus
(section 11, October 2026), Windows Defender quarantined 4 ClawHavoc files — the ones carrying the payload inline — and
left 160 copies whose instructions only point at it; skillward flags both kinds. The SW010 checks for these shapes were
written after studying the campaign, so this shows the layers differ, not that skillward generalizes.

**Test for new features:** does it help decide "should I give the agent this?" or "has what I agreed to changed?"
If yes, it belongs here (a rule for secrets in agent configs, checking the script a hook runs). Signature-based
malware detection, quarantine and background protection do not.

## 2. Goals and non-goals

**Goals for v0.1–v0.2**
- Find every agent instruction file in a project or in `~/.claude`.
- Statically catch known dangerous patterns with as few false positives as possible.
- Pin skill versions (lockfile) and show what changed.
- Run in CI and report to GitHub code scanning (SARIF).
- Check a skill's behavior dynamically in an isolated sandbox.

**Non-goals (for now)**
- A web dashboard, accounts, billing.
- Automatically "fixing" skills.
- Every agent at once: Claude Code first, then Cursor / Codex / Gemini CLI where the formats match.

## 3. Stack

- TypeScript, Node LTS, ESM.
- Distributed on npm, run with `npx skillward ...`.
- CLI: `commander`; tests: `vitest`.
- No native dependencies in v0.1, so `npx` works everywhere.
- The scanner **never** executes or loads scanned content and makes no network requests.
- **Antivirus.** Windows Defender's ML heuristic (`Trojan:Script/ObfusScript.A!ml`) quarantined the built
  `dist/rules/SW004-pipe-to-shell.js`, which contained PowerShell download-and-execute cmdlets inside detection regexes.
  That would have broken `npx skillward` for Windows users. Fix:
  - Such tokens (PowerShell download/exec cmdlets, web client, base64 decoding, TCP client, BITS) live in data —
    `src/rules/data/vocabulary.json`. Rules assemble their regexes at load time with `vocab()` / `withVocab()` from
    `src/rules/vocabulary.ts`, the way Semgrep/YARA keep rules; JSON isn't evaluated as a script.
  - Build: `removeComments` (comments with attack examples stay out of `dist`) and `src/rules/data` copied into `dist`.
  - The `source-hygiene` test forbids these tokens in `src/**/*.ts`.
  - Verified on Windows 11 / Defender: 0 detections in `dist`, including an explicit `Start-MpScan`. ML models change —
    before every release, build on Windows with Defender on and run `Start-MpScan` on `dist` (GitHub runners don't
    catch this).

## 4. CLI

```
skillward scan [path]          # current directory by default
  --global                     # also check ~/.claude
  --format text|json|sarif     # text by default
  --output <file>
  --fail-on info|low|medium|high   # exit-code threshold, high by default
  --config <file>
  --baseline <file>            # report only findings not in the baseline
  --write-baseline <file>      # record current findings as the baseline, exit 0
  --untrusted                  # someone else's code: ignore its config, skillward-ignore comments, .gitignore

skillward explain [path]       # what each target lets the agent do (capability summary)
  --global  --all  --untrusted  --format text|json  --output <file>  --config <file>

skillward lock [path]          # create/update skillward.lock
skillward verify [path]        # compare with the lockfile, show a diff
skillward lock --global        # ~/.claude + MCP servers of ~/.claude.json → ~/.skillward/skillward.lock
skillward verify --global
skillward rules                # list rules with descriptions
skillward sandbox <skill-path> # v0.2, see section 7
```

**Exit codes:** `0` — clean or below the threshold, `1` — findings at or above the threshold, `2` — run error.

Also (v0.1): `scan`/`verify` accept `--no-inline-ignore` and `--no-color`; `lock` accepts `--config` and
`--no-snapshots`; `verify` supports `--format text|json`; `scan --files-from <file>` reports findings only in the
listed files (used by the Action on pull requests).

**`explain` (v0.1).** The permissions-screen view of a scan (section 1): the same findings (suppressed ones left out),
grouped per target into capabilities — runs code from the internet (SW004, SW010, SW015 remote-eval/download/LOLBins),
gives a remote host control (reverse shells), turns approvals off (SW008), reads credentials or secrets (SW005, SW006,
SW016, embedded keys/tokens in SW003), sends data out or contacts unusual hosts (SW007, SW012, SW005/SW006 with egress, high
SW013 hooks), persists after the session (SW014), can destroy data (SW015 destructive), hides things from you (SW001,
SW002, SW009, SW017, encoded content in SW003/SW015), runs automatically (SW013, SW011, SW017). Each capability shows its worst
severity and up to three distinct places (relative to the target). Targets are sorted worst first; targets with
nothing notable are counted, and listed with `--all`. It is informational: exit `0` once printed, `2` on errors — CI
gates on `scan --fail-on`. JSON (`--format json`) has its own format version (`1`): `{ version, tool, root, targets:
[{ kind, path, files, scripts, worst, capabilities: [{ id, label, severity, findings, places, locations }] }] }`.

**SARIF (v0.1):** SARIF 2.1.0 for GitHub code scanning. Paths are relative to the current directory (the repository
root in CI) via `uriBaseId: %SRCROOT%`; files outside it (e.g. `~/.claude`) use absolute `file://` URIs. Levels:
high → `error`, medium → `warning`, low/info → `note`. Rules carry no `security-severity`: code scanning takes it from the rule descriptor and shows it
on every alert of that rule, so a low finding of a high rule would read "High" (seen on public repositories); without
it, each alert's severity is its own `level`. Every
result has `partialFingerprints["skillward/v1"]` and `properties.confidence`. Suppressed findings carry `suppressions`.
Rule crashes go to `toolExecutionNotifications`.

## 5. Architecture (v0.1)

```
discovery  →  parsers  →  rule engine  →  reporters
                               ↑
                            config
```

- **discovery** finds targets and classifies them:
  - `skill`: a folder with `SKILL.md` and every file inside (scripts, templates, references); a file belongs to its
    nearest nested skill;
  - `instructions`: `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` (at any depth), `.claude/commands/**/*.md`,
    `.claude/agents/**/*.md`, and `commands/**/*.md`, `agents/**/*.md` at a plugin root (a folder with
    `.claude-plugin/plugin.json`);
  - `mcp-config`: `.mcp.json`, and the `mcpServers` sections of `~/.claude.json` with `--global`;
  - `settings`: `.claude/settings.json`, `.claude/settings.local.json` (hooks, permissions), `hooks/hooks.json` at a
    plugin root;
  - `plugin-manifest`: `.claude-plugin/plugin.json`, `marketplace.json`.

  - **Other agents** (same kinds, same rules):
    - `instructions`: `GEMINI.md`; Cursor `.cursorrules`, `.cursor/rules/**/*.{mdc,md}`, `.cursor/commands/**/*.md`;
      GitHub Copilot `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`,
      `.github/prompts/**/*.prompt.md`, `.github/chatmodes/**/*.chatmode.md`, `.github/agents/**/*.md`; Windsurf
      `.windsurfrules`, `.windsurf/rules/**/*.md`, `.windsurf/workflows/**/*.md`; Cline `.clinerules` (a file, or
      `.clinerules/**/*.md`); Kiro `.kiro/steering/**/*.md`; Gemini CLI custom commands `.gemini/commands/**/*.toml`.
    - `mcp-config`: `.cursor/mcp.json`, `.vscode/mcp.json` (servers under `servers`), `.gemini/settings.json`,
      `.kiro/settings/mcp.json`.
    - `settings`: Cursor hooks `.cursor/hooks.json` (`{"version": 1, "hooks": {event: [{"command": …}]}}`; scripts run
      from the project root).
    - These folders and files are agent configuration, so `.gitignore` doesn't hide them either (`.cursor/`,
      `.windsurf/`, `.gemini/`, `.kiro/`, `.clinerules/`, and the root files above).
  It honors `.gitignore` (including nested ones) and the config's `ignore`, and never enters `node_modules`, `.git`,
  `.hg`, `.svn`, `.skillward`.
  - **`.gitignore` exception:** the contents of `.claude/`, `.claude-plugin/` and the files `CLAUDE.md`,
    `CLAUDE.local.md`, `AGENTS.md`, `.mcp.json` are scanned even when gitignored — local settings are often ignored on
    purpose, but the agent still loads them. The config's `ignore` always applies.
  - Symbolic links are never followed (they can point outside the project, e.g. at `~/.ssh`); a link that looks like
    part of a target is listed in `skipped`.
  - A file passed explicitly to `scan <file>` is always scanned; an unknown name is treated as `instructions`.
    `scan path/SKILL.md` scans the whole skill.
  - `--global` only looks at `CLAUDE.md`, `settings*.json`, `skills/`, `agents/`, `commands/`, `plugins/` in
    `~/.claude` — transcripts, caches and todos are left alone.
  - Files over 2 MB and binary files (a NUL in the first 8 KB) are skipped and listed in `skipped`.
  - **Hook targets.** A command hook in a `settings` target or plugin hooks file that runs a local script
    (`node .github/setup.js`, `"${CLAUDE_PROJECT_DIR}"/.claude/hooks/x.sh`, `${CLAUDE_PLUGIN_ROOT}/hooks/run.sh`, `bash
    scripts/x.sh`) adds that script to the same target: every rule scans its content, `lock` pins it, `explain` counts it.
    The path is resolved against the project (the folder holding `.claude/`) or the plugin root, must stay inside the
    scan root, is never a symlink, and a file already in another target isn't added twice. Hook targets are read even
    when large or binary, to describe them (size, longest line, binary, obfuscation signals) for SW017; their content
    is scanned only if it fits the usual 2 MB text limit. Gitignore doesn't hide a referenced script.
- **parsers** — markdown: frontmatter, body, extracted code blocks and HTML comments; JSON: a tree; scripts: text plus
  a language from the extension or shebang.
- **rule engine** — one module per rule:
  ```ts
  interface Rule {
    id: string;            // "SW004"
    name: string;          // "pipe-to-shell"
    severity: "info" | "low" | "medium" | "high";
    appliesTo: TargetKind[];
    description: string;
    check(target: ParsedTarget): Finding[];
  }
  interface Finding {
    ruleId: string;
    severity: Severity;
    file: string;
    line: number;
    column?: number;
    message: string;
    snippet: string;       // short, truncated
    confidence: "low" | "medium" | "high";
  }
  ```
- **reporters** — `text` (colored, grouped by file), `json`, `sarif` (SARIF 2.1.0).
  - Any text taken from scanned files (snippets, paths, decoded hidden text) is printed with control and invisible
    characters escaped (`<U+202E>`, long runs as `<43 hidden chars U+E0046…U+E007F>`), so the scanner's own output
    can't become a vector (ANSI sequences, bidi).
  - Columns are 1-based UTF-16 code units (the SARIF default).
  - More than 25 findings of one rule in one file collapse into a single summary finding.
  - JSON report (format version `1`):
    ```json
    {
      "version": 1,
      "tool": { "name": "skillward", "version": "0.1.3" },
      "root": "/abs/path",
      "summary": { "targets": 3, "files": 5, "findings": 2,
                   "bySeverity": { "info": 0, "low": 0, "medium": 1, "high": 1 },
                   "failOn": "high", "failed": true },
      "targets": [{ "kind": "skill", "path": ".claude/skills/x", "files": ["..."] }],
      "findings": [ /* Finding */ ],
      "suppressed": [ /* Finding + suppression */ ],
      "baselined": [ /* Finding: known, from --baseline */ ],
      "skipped": [{ "path": "...", "reason": "binary file" }],
      "errors": [{ "ruleId": "SW004", "path": "...", "message": "..." }]
    }
    ```
  - `summary` also has `suppressed` and `baselined` counts, and `baselineStale` when a baseline was applied.
- **Baseline (v0.1).** `scan --write-baseline <file>` records the current active findings; `scan --baseline <file>` moves
  matching ones to `baselined` (no effect on the exit code). Format: `{"version": 1, "findings": [{ruleId, file, line,
  fingerprint}]}`, sorted, no timestamps, no snippets (it must not copy secrets). The fingerprint is the first 16 hex of
  sha256(ruleId, file, snippet with whitespace collapsed — the message when there is no snippet); the line is
  informational. Each entry matches one finding, so a duplicate of a known line is new. Unmatched entries for files in
  this scan are counted as stale. SARIF: `baselineState` `new`/`unchanged` on every unsuppressed result and an
  `external` suppression on known ones. The baseline is only read when passed explicitly — never picked up from the
  scanned folder — because a third-party repository could ship one. `--write-baseline` can't be combined with
  `--files-from` or `--baseline`. The Action takes a `baseline` input.
- **Exit codes:** a crashing rule doesn't stop the scan — it goes to `errors` and the exit code is `2` (incomplete
  result).

## 6. Rule catalog (v0.1)

| ID | Name | Severity | Catches |
|----|------|----------|---------|
| SW001 | hidden-unicode | high | Zero-width characters, bidi overrides, Unicode tag characters (U+E0000–E007F) |
| SW002 | html-comment-instructions | medium | Instructions for the agent inside `<!-- -->` in markdown |
| SW003 | encoded-payload | medium | Long base64/hex blobs; high when they decode to commands/URLs |
| SW004 | pipe-to-shell | high | `curl … \| bash`, `wget … \| sh`, `iwr … \| iex` and variants |
| SW005 | secret-path-access | high | `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.env`, the keychain, browser profiles, `~/.netrc` |
| SW006 | env-dump | medium | `env`, `printenv`, full dumps of `process.env` / `os.environ` |
| SW007 | suspicious-egress | high | URLs to bare IPs, paste sites, shorteners, webhook/tunnel services |
| SW008 | permission-bypass | high | Requests to skip confirmations, approval-bypass flags, auto-approve |
| SW009 | concealment | high | "Don't tell the user", "do it silently", hiding output or actions |
| SW010 | fake-prerequisite | medium | "Before using this skill, install/run" an external binary |
| SW011 | unpinned-mcp | medium | MCP servers via `npx`/`uvx` without a version or with `@latest` |
| SW012 | remote-mcp | low | MCP servers at a remote URL (inventory) |
| SW013 | hook-command | medium | Hooks that run commands; high with network access or secrets |
| SW014 | persistence | high | Writes to `~/.bashrc`, `~/.zshrc`, crontab, launchd, `~/.claude/settings*`, other `CLAUDE.md` files |
| SW015 | dangerous-script | high | In skill scripts: `eval` of downloaded code, `rm -rf ~`, running downloaded files |
| SW016 | secret-in-config | high | Provider tokens and webhook URLs with tokens in agent configs; secret-looking values for secret-named keys |
| SW017 | hook-script | high | A hook runs a script that can't be reviewed: obfuscated, packed, binary, huge or minified |

**Rule principles**
- Phrase rules (SW002, SW008, SW009, SW010) are heuristics with English and Russian vocabularies, extensible.
- Context matters: a pattern in a code block under "Example attack" in security docs is not an instruction. That's what
  the config's `ignore` and inline suppressions `<!-- skillward-ignore SW004: reason -->` are for.
  - The syntax works in any comment (`<!-- -->`, `#`, `//`, `/* */`). A directive on its own line applies to the next
    non-empty line, or to the whole code block if that line opens a fence. A directive at the end of a line applies to
    that line. `skillward-ignore-file SW001: reason` applies to the whole file. Several rules: `SW004, SW005`.
  - Rule IDs are required; "suppress everything" isn't possible.
  - Suppressed findings don't silently disappear: they are listed separately (`suppressed` in text and JSON, SARIF
    `suppressions` of kind `inSource`) and don't affect the exit code — a malicious skill could add such comments
    itself.
  - For auditing third-party skills: `--untrusted` (section 9), or just `--no-inline-ignore`.
- Every rule has fixtures: at least 2 "bad" and 2 similar "good" examples.
- The severity in the table is the default (also shown by `skillward rules` and in SARIF `defaultConfiguration`).
  A finding can be higher or lower depending on the evidence. `rules` in the config replaces the severity of all of a
  rule's findings.

**Severity policy (calibrated on the corpus, section 11).** High is something a user should block: an executable
command or an instruction to the agent (download and run, turn approvals off, read and send a secret, persist,
hide actions). The same pattern in documentation is lowered: warnings ("never …") and deny lists → info; script
comments, CLI option docs (tables, option lists), quoted text (examples, detector patterns), headings → low/info;
a prose mention without a command → medium; official installers of well-known vendors → medium. Threshold phrases
("don't ask for confirmation") are medium; exact bypass flags and settings stay high.

**Per-rule decisions (v0.1)**
- SW001: a single zero-width character → `low`; runs of 2–3 → `medium`; direction marks without RTL text → `medium`;
  invisible characters inside a regex character class in code → `low` (detectors and sanitizers). Not reported:
  ZWJ in emoji sequences, subdivision flags (🏴 + tag chars), ZWJ/ZWNJ inside Persian/Indic words, LRM/RLM in RTL
  text, a single variation selector, a leading BOM. Hidden tag-character text is decoded into the message.
- SW002: only comments outside code blocks and inline code, one finding per comment. `high` confidence for
  prompt-injection phrases ("ignore previous instructions", "you are now", "system prompt", Russian equivalents) or an
  address/imperative together with a command, URL or secret path; `medium` for an address plus an imperative without
  commands. Skipped (unless injection phrases are present): tool directives (markdownlint, prettier, eslint, cspell,
  toc), `skillward-ignore`, TODO/FIXME/NOTE, licenses, provenance notes (`Source: …`), CAPS markers, comments under
  3 words.
- SW003: base64 (≥60 chars, mixed case and digits, entropy ≥4.5), base64url, wrapped lines, hex ≥128, `\xNN` ≥20.
  Decoded without executing: commands/URLs → `high` with a ≤60-char preview; text → `medium`; plain HTML without
  scripts → `low`; binary → `medium`/`low`; MIME bodies of saved e-mails → `info`. Decode-and-exec (`base64 -d | sh`,
  `exec(b64decode)`, `eval(atob)`, `powershell -enc`) is always `high`. PEM private keys → `high`; certificates,
  public keys and placeholder keys are not reported. JWTs → `medium` "embedded token", not decoded; the jwt.io sample
  → `info`. Blobs are truncated in snippets (first 12 chars + length). Context is read from a window around the blob,
  not the whole line (minified one-line files). Exceptions: `data:image|font|audio|video`, SRI `sha*-`, lines about
  checksums/sha256/hash/digest/fingerprint/commit, URL parts.
- SW004: an interpreter counts as executing stdin only when no script, `-c` or `-m` is given (`curl … | python -m
  json.tool` is fine). Official installers of well-known tools → `medium`; warnings, permission rules and deny lists →
  `info`; comments, test files and quotes → `low`; placeholders (`curl <url> | sh`) → `info`.
- SW005: a credential store (`~/.ssh/id_rsa`, `~/.aws/credentials`, …) read or sent → `high`; a bare mention or a
  directory → `low`; a config value pointing a tool at its own credentials → `medium`. `.env` is reported only when
  printed (`medium`) or sent over the network (`high`) — loading, writing and templates are fine. Public/non-secret
  files (`*.pub`, `known_hosts`, `~/.ssh/config`, `~/.aws/config`) aren't reported. A key used as `ssh -i` /
  `ssh-keygen -f` / `IdentityFile` → `info`. Paths in a settings `deny`/`ask` list aren't reported; in `allow` →
  `medium`. Verbs and destinations are read from the sentence around the hit.
- SW006: bare `env`/`printenv` only in a command context (shell scripts, JSON/text, shell blocks, inline code; in
  prose after "run/execute"), not in Python/JS where `env` is a variable. `env | grep` for one variable isn't reported;
  grepping for KEY/TOKEN/SECRET/PASS is. Loops over the environment aren't (that's how child-process environments are
  filtered). Egress on the same line → `high`. Placeholders (`${env}`, `{env}`) and LFI target lists → `info`.
- SW007: paste sites, request catchers, tunnels, bare public IPs in URLs / `/dev/tcp` / next to curl/wget/nc → `high`;
  shorteners and DDNS → `medium`; chat webhooks (Discord, Telegram bot, Slack) → `medium`, `high` with secrets, env or
  `@file` on the line; raw gists → `low`. Loopback, private, link-local, CGNAT, multicast, public DNS resolvers and
  placeholder IPs are excluded; TEST-NET and `2001:db8::` count as public. A known host counts only in a URL, before `/`
  or `:port`, or on a line with a network command. ssh/scp/rsync/ping to an IP aren't reported.
- SW008: flags (`--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `"defaultMode":
  "bypassPermissions"`, Codex `--dangerously-bypass-approvals-and-sandbox`/`--yolo`, `gemini … -y`) → `high` in a
  command (script, JSON, code block, or after an agent CLI name), `medium` when only mentioned in prose, `low` in
  option tables and headings. `--full-auto`, `enableAllProjectMcpServers: true`, `skipDangerousModePermissionPrompt:
  true` → `medium`. `permissions.allow` with `Bash`, `Bash(*)`, `Bash(:*)`, `Bash(*:*)`, `PowerShell(*)` → `high`;
  narrow rules like `Bash(npm run test:*)` aren't reported. Phrases → `medium`; auto-approve-all and "answer yes to all
  prompts" → `high`. A governing warning ("Never run … with", "Don't use") → `info`; quoted examples → `low`.
- SW009: explicit forms ("don't tell the user", "hide … from the user", "the user must not know") → `high`/`high` when
  the object is what the agent does ("about this", "what you did", end of clause); "don't tell the user *that X*"
  (advice on what not to claim) → `medium`. "Don't tell the user **to** …" isn't reported. "Without telling the user"
  → `medium`. "silently/quietly + verb" only as an imperative, `medium`. "Don't show the user raw stack traces/logs"
  → `info`; other "don't show the user" → `medium`. Keeping instructions secret → `medium`. Quoted phrases → `low`.
- SW010: a prerequisite phrase within ±3 logical lines of an external artifact: an executable/script URL, a GitHub
  release download, `curl -o … && chmod +x`, a package installed from a URL. Named packages (`pip install pypdf`,
  `brew install`) are never reported. **High:** a download from a password-protected archive, and a paste-site page
  next to a "run it in your terminal" step (both ClawHavoc shapes). "Ask the user to run/paste" only when the object
  is a command/script or the terminal is named.
- SW011: `npx`/`bunx`/`bun x`/`npm exec`, `pnpm dlx`/`yarn dlx`, `uvx`/`uv tool run`, `pipx run`, `docker`/`podman
  run`, including via `cmd /c` and as a single string without `args`. No version / `@latest` / dist-tag / git URL
  without SHA → `medium`; a version range → `low`; a docker tag other than `latest` → `info` (pin a digest).
- SW012: every remote server → `low` (host and auth header names, no values); `http://` to a non-local host or
  credentials in the URL → `medium`. Loopback isn't reported; empty placeholders are skipped; `${VAR}` URLs are reported
  with their default host.
- SW013: a hook that starts a script shipped with the project/plugin → `low`; inline shell, absolute or out-of-project
  paths → `medium`; network or secret paths → `high`; `statusLine` → `info` unless it shows the same signs. `type:
  "http"` hooks: remote → `high`, loopback → `medium`. Secrets in messages and snippets are masked.
- SW014: needs a write to the path (redirect, `tee`, `cp`/`mv`/`ln`, `sed -i`, `writeFile`, `open(…, 'a'|'w')`, prose
  "append/add/write … to"). Persistence by itself: `crontab -`, `launchctl load|bootstrap`, `schtasks /create`,
  `Register-ScheduledTask`, `reg add …\Run`, `authorized_keys`, global `~/.claude` settings/hooks → `high`; shell rc
  writes with a plain export/alias, systemd units, `crontab -e`, installing global skills → `medium`; project-level
  config and prose → `low`/`info`. Reading is never reported.
- SW015: scripts, JSON and code blocks with a code language or none (`text`/`md`/`log` and prose aren't). Eval/exec
  of downloaded or decoded code (including through variables), destructive commands, download-then-run (same line or
  ≤20 lines), LOLBins, encoded PowerShell, reverse shells. A checksum/signature check between download and run clears
  a multi-line finding. Guard-hook block lists, deny lists, comments and test files are lowered; cheat-sheet
  placeholders (`ATTACKER_IP`) → `medium`/`low`. Quiet on `eval "$(ssh-agent -s)"`, `eval "$(brew shellenv)"`,
  `rm -rf ./build`.
- SW016: provider tokens by exact format (AWS access key IDs, GitHub, GitLab, Slack tokens and webhook URLs, Discord
  webhooks, OpenAI, Anthropic, Stripe live, Google API, npm, PyPI, Hugging Face, SendGrid, Telegram bot, DigitalOcean,
  Shopify) → `high`/`high`; a value assigned to a secret-named key (`api_key`, `*_TOKEN`, `--token`, `Authorization:
  Bearer`) → `medium`/`medium` only when it looks generated (letters and digits, entropy ≥3.5, not a word, path or
  identifier) **in real configuration** (JSON configs, `.env` files, scripts); the same in markdown docs → `low` (usually an
  example). Tokens in the scanned repository's own test files (`tests/`, `*.test.*`, `test_*.py`, `fixtures/`) → `low`.
  Ignored: placeholders (`your-…`, `FAKE`, `example`, `xxxx`, `<…>`, sequences like `1234`/`abcd`, example words like
  `secure`/`password`), variables (`$X`, `${X}`), AWS documentation keys, URL query parameters (`?…&token=`), names that
  hold something else (`tokenAddress`, `max_tokens`, `hashed_secret`, `tokenizer`), chain addresses and JWTs (SW003).
  Corpus: 82 high / 97 medium across 2,917 repositories — live Slack webhooks, Anthropic/Perplexity keys in `.mcp.json`,
  `ANTHROPIC_AUTH_TOKEN` in `settings.local.json`. The snippet shows only the first 4 characters and the length. Private keys and JWTs stay in SW003.
  Test fixtures use generic forms only; provider-format tokens are generated at test run time, never committed.
- SW017: for every hook target (section 5). Obfuscation signals (javascript-obfuscator `_0x…` identifiers, packers
  such as `eval(function(p,a,c,k,e,…`, dense `\xNN` escapes, a long string array) or a binary → `high`/`high`; over
  1 MB or a line over 20,000 characters (minified/bundled) → `medium`/`medium`. A readable script gets no SW017 finding —
  its content is checked by the other rules. The finding is on the script, line 1, and names the hook event.
- Known limitation of phrase rules: a phrase matches within one logical line.
- `~/.claude.json` (`--global`): every line outside `mcpServers` (top-level and per project) is blanked, keeping line
  numbers; the JSON value is reduced to those sections and findings are limited to them. History is never scanned.
  Size limit 50 MB for this file (2 MB for others).
- Performance: don't use `String.prototype.matchAll` in per-line loops — it recompiles the regex on every call; use
  `execAll` from `src/text.ts` (46 s → 8 s on a real `~/.claude`). Bound `[^\n]*` quantifiers and read context from a
  window: minified one-line files made some rules quadratic.

## 7. v0.2 — sandbox (`skillward sandbox`)

**Idea:** run an agent with the skill in a disposable isolated environment on typical tasks and record what it tries
to do.

**Environment**
- A Docker container: non-root user, no host mounts, all capabilities dropped, read-only where possible, CPU/memory
  limits, a hard timeout.
- Runs **only on a separate machine/VM**, never on a main laptop.
- **No real secrets in the container.** The model API key stays outside: the container talks to the model through a
  proxy that adds the key. A dedicated key with a spending limit.

**Honeytokens**
- Fake `~/.ssh/id_rsa`, `~/.aws/credentials`, a project `.env` — every value carries a unique per-run marker.
- Any read of a honeytoken, or the marker showing up in outbound traffic, means `malicious`.

**Observation**
- All egress goes through a logging proxy; only the model endpoint is allowed, everything else is blocked and logged.
- Agent tool-use hooks log every tool call: shell commands, reads, writes.
- Optionally: filesystem monitoring.

**Scenarios**
- 3–5 tasks per skill: some generated from the skill's description (so the skill actually triggers), some neutral.
- The cheapest suitable model, a token budget per run.

**Verdicts**
- `malicious` — touched a honeytoken, leaked the marker, wrote to a persistence location.
- `suspicious` — egress outside the allow list, package installs, approval bypass, asking the user to run something.
- `clean` — none of the above.
- Report: a timeline of actions plus the reason for the verdict.

## 8. Lockfile

`skillward.lock` (JSON, committed to the repository):

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

`verify` shows added, removed and changed files (with a text diff) and runs `scan` only on what changed.

**Implementation details (v0.1)**
- The lock covers every target (not only skills) and all of their files, binaries included. The file key is the path
  relative to the skill folder; for single-file targets, the file name. The hash is `sha256` of the bytes.
- `lockedAt` changes only for entries whose files changed; `source` is maintained by hand and preserved on rewrite.
- A hash can't show a diff, so `lock` stores copies of locked text files (≤ 2 MB) in `.skillward/snapshots/<sha256>`
  (content-addressed, unused ones removed). Commit `.skillward/` with the lock and `verify` in CI shows diffs; without
  snapshots changes are still detected, just without text. `--no-snapshots` turns this off.
- The lockfile is untrusted input (it comes with the repository): it is validated, and hashes are checked against
  `sha256:<64 hex>` before being used in paths.
- `skillward.lock` and `.skillward/` are never part of what gets locked.
- `verify` exit codes: `0` — matches the lock; `1` — any change (review it and lock again); `2` — no lockfile / error.
  Findings in the changed files are shown in the report; `--fail-on` only affects the report's verdict.
- Diffs are capped at 200 lines per file; invisible characters are escaped.
- **Secrets are masked in snapshots and diffs** with SW016's detectors plus JWTs and private key blocks (first 4
  characters and the length). Snapshots are committed with the lock, so they must not copy secrets; both sides of a
  diff are masked, and a change only inside a masked value is reported as "only masked secret values changed".
- **`lock`/`verify --global`** pin the user's own configuration: what `scan --global` reads in `~/.claude` (with
  hook scripts) and `~/.claude.json`, without walking a project. State lives in `~/.skillward/skillward.lock` and
  `~/.skillward/snapshots/` — outside `~/.claude`, which is what is locked. `~/.claude.json` is rewritten constantly
  (history, counters, per-project state), so only its MCP servers are locked: the `mcpServers` sections as canonical
  JSON (keys sorted, projects without servers left out); that text is what is hashed, snapshotted and diffed.
  `--global` refuses a path and reads no project config (an explicit `--config` applies to the scan of changes). Known
  limit: the lock is on the same machine as what it pins, so it detects changes by updates and tools, not by an attacker
  who can also rewrite `~/.skillward`.
## 9. Config

`skillward.config.json`:

```json
{
  "ignore": ["docs/security-examples/**"],
  "rules": { "SW012": "off", "SW006": "high" },
  "failOn": "high",
  "inlineIgnore": true
}
```

- `ignore` — gitignore patterns relative to the scan root. `rules` — `"off"` or a severity that replaces the rule's.
  `failOn` — the default for `--fail-on` (the flag wins). `inlineIgnore` — honor `skillward-ignore` (default `true`).
- Unknown keys and wrong types are errors (exit `2`); an unknown rule ID in `rules` is allowed (the config may be
  written for a newer version).
- The config is looked up in the scan root, or given with `--config <file>`. It is plain JSON and never executed.
- **The scanned folder's config is untrusted when the folder is someone else's.** It could turn off exactly the rules
  its skills trip, or `ignore` their paths; `skillward-ignore` comments and `.gitignore` (which decides what is walked
  outside agent directories) are the same kind of lever. So:
  - Reports always say what the applied config hides: a text line `Config <path>: turns off …; sets severity …;
    ignores …` (with a hint to use `--untrusted` when the config came from the scanned folder), and a `config`
    section in the JSON of `scan`, `explain` and `verify`. `lock` and `verify` print the line too: a config's `ignore`
    decides what is locked at all, so a skill left out of the lock must not look like a verified one. In the Action, this line lands in the job summary, so a pull request
    that edits the config to hide its own finding is visible.
  - `scan`/`explain --untrusted`: the scanned folder's `skillward.config.json` isn't read (the report says it was
    skipped), inline suppressions are off, `.gitignore` files are not respected. An explicit `--config` is the user's
    own and still applies. A baseline is only ever read from `--baseline`.

## 10. GitHub Action

**Implementation (v0.1)**
- A composite action at the repository root (`action.yml`); the logic lives in `action/scan.sh` and
  `action/changed-files.sh` (both tested).
- All inputs reach the shell only through `env`; `${{ }}` is never interpolated into `run:` (injection protection,
  enforced by a test).
- Third-party actions are pinned to full commit SHAs (tested). `version` is an exact skillward version from npm or
  `local` (build from the action's checkout); ranges and `latest` are refused. The default equals the `package.json`
  version (tested).
- Pull-request mode (`only-changed: auto` on `pull_request`): `git diff --name-only --diff-filter=ACMT <base-sha> HEAD`
  (a two-dot tree diff — works with shallow checkouts; the base commit is fetched with `--depth=1`); the list goes to
  `scan --files-from <file>`: findings only in those files, but targets (skills) are parsed whole for context. Deleted
  files aren't scanned. If the list can't be built, a warning and a full scan. `pull_request_target` is deliberately
  not supported.
- Order: scan → SARIF → upload to code scanning (`if: always()`) → fail the job if the exit code ≠ 0 and `fail-on` ≠
  `never`. On a pull request from a fork (read-only token) the upload step has `continue-on-error`: GitHub may refuse
  the upload, and that must not fail the job — the gate and the job summary don't depend on it (tested). Code scanning
  ignores SARIF `suppressions` (an inline-suppressed result became an open alert in a test repository), so the upload is
  a copy without suppressed and baselined results; `sarif-file` keeps them, and the job summary lists them (tested). A run error (exit 2) fails the job right away. The text report goes to the job summary (HTML-escaped: it
  quotes scanned content).
- Outputs: `sarif-file`, `exit-code`, `findings` (active, excluding suppressed and baselined).
- No separate repository for the Action: `uses: owner/skillward@<sha>`. This repository's CI runs its own Action with
  `version: local`.

**Releases.** `.github/workflows/release.yml`: a `vX.Y.Z` tag → `scripts/check-release.mjs` checks that the tag,
`package.json`, the `action.yml` default and a CHANGELOG section agree → `npm publish --provenance` via npm trusted
publishing (OIDC, no token in the repository). A version already on npm is skipped.

## 11. Research: public skills corpus

- Collect public skills from open registries and GitHub, respecting their terms and rate limits.
- Run `scan` on all of them, and `sandbox` on the top ones and everything `scan` flagged.
- Malicious findings: report to the platform and the author first (responsible disclosure), wait, then publish. Never
  publish working payloads in full.

**Static part (`scripts/corpus/`)** — the corpus lives outside the repository (`--dir`, `SKILLWARD_CORPUS`, default
`../skillward-corpus`):
1. `npm run corpus:discover` — candidates in `repos.json` from `sources.json`: seed repositories (official and popular),
   links from awesome lists, GitHub code search (`SKILL.md`, `.mcp.json`, `.claude-plugin/marketplace.json`,
   `hooks/hooks.json`, `.claude/settings.json` with hooks, `CLAUDE.md`, `AGENTS.md`), forks dropped. Code search returns
   ≤1000 results per query, so queries are split by `size:`; requests go through `gh api` with a 6.5 s pause (10/min
   limit). Seeds and awesome lists are always included; search hits are a deterministic sample by sha256 of the name up
   to `maxRepos`.
2. `npm run corpus:fetch` — per repository: `git clone --depth 1 --filter=blob:none --no-checkout`, then exactly the
   files discovery reads are selected from the tree (`classifyFile` plus everything in skill folders, no binary
   extensions, files in hook folders) and only those are checked out (sparse). A second pass reads the checked-out hook
   files the way discovery does and also checks out the scripts their commands name (`scripts/guard.sh`,
   `.github/setup.js`), so hook targets and SW017 are measured. At most `--max-files` (default 25,000) per repository,
   agent files first. Third-party code never lands on disk in bulk. Hardening: no hooks, submodules or LFS filters,
   `core.symlinks=false`, no password prompts; paths that can't be created on Windows (and `.git` aliases) are
   dropped. Metadata (commit SHA, file count, hook scripts, files over the cap, status) goes to `meta/`.
3. `npm run corpus:scan` — an in-process scan with audit settings: the repository's config and inline
   `skillward-ignore` are ignored, so a repository can't hide its own findings. Results: `results/<owner>__<repo>.json`
   (JSON report v1 + `repo`, `sha`), summary `summary.json`/`summary.md`, a review list `review-<severity>.md`.

`npm run corpus:pipeline` does steps 2 and 3 per repository for a full run on a separate machine: fetch, scan, write
the result, then delete the checkout unless it has a finding to review (`--keep`, default `high`), so the disk holds a
few repositories at a time. Resumable; `corpus:scan` on the same directory then writes the summary from the stored
results, including how many hook scripts were fetched and how many repositories hit the file cap.

Nothing from the corpus is executed. False positives found in the corpus become `good` fixtures.

Tuning tools: `npm run corpus:recheck -- --rule SWxxx [--severity high] [--grep re] [--on SWyyy]` re-runs one rule on
the files a rule flagged (before/after by severity, grouped samples); `npx tsx scripts/corpus/profile.ts --repo
owner/name [--rule SWxxx]` shows per-rule time and the slowest files; `scripts/corpus/scan-blob.ts` scans files
straight from git objects in memory (for files antivirus removed from the working tree).

**First run (2026-10-20):** 3,000 candidates → 2,917 repositories with agent files, 573k files. Before tuning: 55,539
findings, 25,250 high, a high finding in 40% of repositories. After: 46,777 findings, 6,604 high, 17.8%. A hand-labelled
random sample of 60 high findings: ~85% point at a genuinely dangerous pattern (about a quarter of those in offensive-
security skills). Copies of the ClawHavoc malware campaign (fake "prerequisite" with a password-protected archive or a
paste-site command) are still redistributed in GitHub mirrors months after the registry removed them.

**Known gaps, to fix before publishing numbers** (the fetch now covers the first two: a 25,000-file cap and the scripts
hook commands name; the rerun is pending):
- A cap of 1,500 files per repository truncated 193 large collections (~1.8M files not fetched).
- The fetch selects agent files only, so scripts that hooks run (`.claude/hooks/*`, plugin `hooks/*`, `.github/*.js`) are
  missing: hook targets and SW017 can't be measured on this corpus. The rerun must add hook directories and the files
  hook commands name.
- Antivirus on the scanning machine removed the most malicious files on checkout, so the scan never saw them. Run the
  corpus on a machine without real-time antivirus interference (a VM), and report antivirus detections separately.

## 12. Later: team edition (not before there are users)

- A team dashboard: which skills/MCP servers are installed by whom and in which repositories.
- Organization allow lists and policies.
- Alerts when skills change.
- Reports for security audits.

## 13. Roadmap

- [x] **v0.1 core:** discovery, rule engine, text/JSON reporters, rules SW001–SW015 with fixtures (≥2 bad / ≥2 good),
  SARIF 2.1.0, `lock`/`verify` with snapshots, config (`ignore`, `rules`, `failOn`, `inlineIgnore`), inline
  suppressions, `~/.claude.json` MCP sections in `--global`.
- [x] **GitHub Action** with pull-request mode (`scan --files-from`).
- [x] **Precision pass** over all rules against the public corpus; hand-labelled precision estimate.
- [x] **Release workflow** with npm trusted publishing.
- [x] **`explain`:** capability summary per target (the permissions-screen view).
- [x] **Baseline:** `scan --write-baseline` / `--baseline`, Action input `baseline`.
- [x] **`--untrusted`** for someone else's code; reports say what the config hides.
- [x] **`lock`/`verify --global`** for `~/.claude` and the MCP servers in `~/.claude.json`; secrets masked in diffs and snapshots.
- [x] **First npm release** (0.1.1, 2026-10-23).
- [ ] **Responsible disclosure** of corpus findings; publish the report and launch.
- [ ] **Corpus rerun** without the gaps above.
- [x] **SW016 secret-in-config.**
- [x] **Hook targets** scanned and locked with their hook file; **SW017 hook-script**.
- [x] **Other agents:** Cursor, GitHub Copilot / VS Code, Gemini CLI, Windsurf, Cline, Kiro (project-level files).
- [ ] **Other agents, global:** `~/.cursor`, `~/.gemini`, Windsurf/Cline user MCP configs in `--global`.
- [ ] **v0.2 sandbox:** container, proxy, honeytokens, agent run, tool-call logging, verdicts, report.
