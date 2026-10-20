import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { isWarningContext } from "./phrases.js";
import { vocab } from "./vocabulary.js";

const SEP = String.raw`(?:/|\\{1,2})`;
const HOME = String.raw`(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:(?:USERPROFILE|HOME)|/home/[\w.-]+|/Users/[\w.-]+|/root|[A-Za-z]:${SEP}Users${SEP}[\w. -]+?)${SEP}`;
const END = String.raw`(?![\w-]|\.\w)`;

/** A place where written code runs again later: on shell start, on a schedule, at login, every agent session. */
interface Location {
  re: RegExp;
  label: string;
  /** Severity for a command that writes there. */
  severity: Severity;
  /** Severity for prose ("add this to your ~/.zshrc"): setup advice to humans looks the same. Defaults to `severity`. */
  proseSeverity?: Severity;
  /**
   * Severity for a command write whose line looks like ordinary setup (`export PATH=…`,
   * `eval "$(tool completions zsh)"`) rather than a download, decoder or reverse shell. Defaults to `severity`.
   */
  plainSeverity?: Severity;
}

const re = (source: string) => new RegExp(source, "gi");

export const LOCATIONS: Location[] = [
  {
    re: re(String.raw`(?<![\w$.-])\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|kshrc|cshrc|tcshrc)${END}|\.config${SEP}fish${SEP}config\.fish\b|(?<![\w])\$PROFILE\b`),
    label: "a shell startup file (runs on every new shell)",
    severity: "high",
    // "echo 'export PATH=…' >> ~/.bashrc" is in every install guide; a download or decoder there is not.
    plainSeverity: "medium",
    proseSeverity: "low",
  },
  {
    re: re(String.raw`/etc/cron(?:tab|\.d|\.daily|\.hourly|\.weekly|\.monthly)\b|/var/spool/cron\b`),
    label: "cron (runs on a schedule)",
    severity: "high",
  },
  {
    re: re(String.raw`Library${SEP}Launch(?:Agents|Daemons)\b`),
    label: "launchd (runs at login/boot)",
    severity: "high",
  },
  {
    re: re(String.raw`\.config${SEP}systemd${SEP}user\b|/etc/systemd/system\b|/(?:usr/)?lib/systemd/system\b`),
    label: "a systemd unit (runs at boot/login)",
    // Installing a service unit is ordinary deployment documentation; the unit's content is what matters.
    severity: "medium",
    proseSeverity: "low",
  },
  {
    re: re(String.raw`Start Menu${SEP}Programs${SEP}Startup\b|\bshell:startup\b`),
    label: "the Windows Startup folder (runs at login)",
    severity: "high",
  },
  {
    re: re(String.raw`\.ssh${SEP}authorized_keys2?${END}`),
    label: "SSH authorized_keys (grants remote login — a backdoor)",
    severity: "high",
  },
  {
    re: re(String.raw`(?<![\w-])\.git${SEP}hooks${SEP}`),
    label: "a git hook (runs on every commit/checkout)",
    severity: "medium",
    proseSeverity: "low",
  },
  {
    // `hooks${END}`: not `~/.claude/hooks.log`.
    re: re(String.raw`${HOME}\.claude${SEP}(?:settings(?:\.local)?\.json|hooks${END})|${HOME}\.claude\.json${END}`),
    label: "global Claude Code settings or hooks (affect every future session)",
    severity: "high",
    proseSeverity: "medium",
  },
  {
    // `cp -r my-skill ~/.claude/skills/` is how skills are installed; it still changes every future session.
    // Plugin config/data directories hold plugin state, not code.
    re: re(String.raw`${HOME}\.claude${SEP}(?:skills|agents|commands|plugins(?!${SEP}(?:config|data)\b))\b`),
    label: "global Claude Code skills/agents/commands/plugins (affect every future session)",
    severity: "medium",
    proseSeverity: "low",
  },
  {
    re: re(String.raw`${HOME}\.claude${SEP}CLAUDE\.md\b`),
    label: "global agent instructions (affect every future session)",
    severity: "high",
    proseSeverity: "medium",
  },
  {
    re: re(String.raw`(?<![\w-])\.claude${SEP}(?:settings(?:\.local)?\.json|hooks)\b`),
    label: "Claude Code project settings (hooks and permissions)",
    // Project settings live in the repo and show up in review; global ones (above) do not.
    severity: "medium",
    proseSeverity: "low",
  },
  {
    // Creating project commands/agents/skills is what plugin-dev docs teach; it still changes future sessions.
    re: re(String.raw`(?<![\w-])\.claude${SEP}(?:skills|agents|commands)\b`),
    label: "Claude Code project commands/agents/skills",
    severity: "low",
    proseSeverity: "info",
  },
  {
    // Memory skills and "add this convention to CLAUDE.md" are everywhere; the file lives in the repo.
    re: re(String.raw`(?<![\w.-])(?:CLAUDE|AGENTS|CLAUDE\.local)\.md\b`),
    label: "an agent instruction file (changes what agents do next time)",
    severity: "low",
    proseSeverity: "info",
  },
];

/** Commands that install persistence by themselves, whatever the path. */
interface PersistenceCommand {
  re: RegExp;
  label: string;
  severity: Severity;
}

export const COMMANDS: PersistenceCommand[] = [
  { re: /\bcrontab\s+-(?=\s|$|["'`;)|&])|\|\s*crontab\b(?!\s+-l\b)|\bcrontab\s+(?!-[lr]\b)(?!-e\b)[\w./~$-]+\.(?:txt|cron|tab)\b/gi, label: "installs a crontab (runs on a schedule)", severity: "high" },
  { re: /\bcrontab\s+-e\b/gi, label: "edits the crontab (runs on a schedule)", severity: "medium" },
  { re: /\blaunchctl\s+(?:load|bootstrap|submit|enable)\b/gi, label: "loads a launchd job (runs at login/boot)", severity: "high" },
  { re: /\bschtasks(?:\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b/gi, label: "creates a scheduled task", severity: "high" },
  {
    re: /\b(?:reg(?:\.exe)?\s+add|New-ItemProperty|Set-ItemProperty)\b[^\n]{0,400}?\\(?:Software|SOFTWARE)\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b/gi,
    label: "adds a Windows Run key (runs at login)",
    severity: "high",
  },
  { re: /\bsystemctl\s+(?:--user\s+)?enable\b/gi, label: "enables a systemd service (runs at boot/login)", severity: "low" },
  // Needs a value: `git config --global core.hooksPath` alone only reads it.
  { re: /\bgit\s+config\s+(?:--global|--system)\s+core\.hooksPath\s+(?![|;&<>`)]|\d?>)\S/gi, label: "sets a global git hooks path (runs on every commit)", severity: "medium" },
];

/**
 * Write indicators that must sit right before the path: `>> ~/.bashrc`, `tee -a ~/.zshrc`.
 * A `>` at the start of a line is a markdown blockquote, not a redirect.
 */
const WRITE_BEFORE = /(?:(?<=\S[^\S\n]*)(?<![-=<>])>{1,2}|\btee(?:\s+-a|\s+--append)?|\bOut-File(?:\s+-Append)?(?:\s+-FilePath)?|\b(?:Add|Set)-Content(?:\s+-Path)?)\s*["']?$/i;
/** Copy-like commands write to their LAST argument: `cp hook.json ~/.claude/settings.json`. */
const COPY_BEFORE = /\b(?:cp|mv|install|ln(?:\s+-\w+)*|copy|move|Copy-Item|Move-Item|rsync)\b[^\n|;&`,]*\s["']?$/i;
const COMMAND_END = /^["']?\s*(?:$|[;&|)`]|#)/;
/** Writes anywhere on the line: `sed -i`, `writeFile(...)`, `open(path, "a")`. */
const WRITE_ON_LINE =
  /\bsed\s+(?:-\w+\s+)*-i\b|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|write_text|write_bytes|WriteAllText|AppendAllText)\b|\bopen\s*\([^\n]{0,400}?,\s*["'](?:a|w|a\+|w\+|ab|wb)["']\s*[,)]/i;
/** Prose: "append this line to ~/.zshrc", "добавь в ~/.bashrc". */
const PROSE_BEFORE =
  /(?<![\p{L}])(?:append|add|write|insert|put|paste|place|save|register|inject|copy)(?![\p{L}])[^.!?\n]{0,80}?(?<![\p{L}])(?:to|into|in|at|inside)\s+(?:your\s+|the\s+|their\s+|a\s+)?["'`*_]*$|(?<![\p{L}])(?:добав|запиш|допиш|встав|сохран|пропиш|внес)\p{L}*[^.!?\n]{0,80}?(?<![\p{L}])(?:в|во)\s+["'`*_]*$/iu;

/** A payload that is more than setup: downloads, decoders, reverse shells, background jobs. */
const SUSPICIOUS_PAYLOAD = new RegExp(
  String.raw`(?<![\w.-])(?:curl|wget|nc|ncat|netcat|socat|base64|xxd|nohup|osascript|${vocab("psFetch", "psEval", "psDecode")})(?![\w-])|/dev/(?:tcp|udp)/|\b(?:bash|sh)\s+-i\b|\bpython3?\s+-c\b|\bhttps?://`,
  "i",
);
/** `<repo>/CLAUDE.md`, `<li>AGENTS.md`: the `>` closes a placeholder or tag, it is not a redirect. */
const PLACEHOLDER_BEFORE = /<[^<>\s]*>\s*["']?$/;
/** "existing > CLAUDE.md > ask": arrows in prose, not a redirect. */
const ARROW_AFTER = /^["'`]?\s+(?:>|->|→)\s/;
const PROSE_PREPOSITION = /(?<![\p{L}])(?:into|to|in|inside)\s+(?:your\s+|the\s+|their\s+|a\s+)?["'`*_]*$/iu;
/** Permission rules in settings (`"Bash(*>> ~/.zshrc)"`) are SW008's business, not a write. */
const PERMISSION_RULE = /"(?:Bash|PowerShell|Read|Edit|Write|MultiEdit|NotebookEdit)\(/;

const DELIMITER = /[\s"'`()<>=,;|]/;

/** Expands a match to the surrounding path token (`~/.config/systemd/user/x.service`). */
function pathToken(text: string, start: number, end: number): [number, number] {
  while (start > 0 && !DELIMITER.test(text[start - 1]!)) start--;
  while (end < text.length && !DELIMITER.test(text[end]!)) end++;
  return [start, end];
}

const rule: Rule = {
  id: "SW014",
  name: "persistence",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Writes that survive the session: shell rc files, crontab, launchd, systemd, Windows Run keys and scheduled tasks, ~/.ssh/authorized_keys, git hooks, ~/.claude settings and other CLAUDE.md/AGENTS.md files.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of logicalLines(file.text)) {
    if (file.type === "json" && PERMISSION_RULE.test(line.text)) continue;
    // A markdown table row: `| crontab | Scheduled tasks |` is not a pipe into crontab.
    const tableRow = file.type === "markdown" && /^\s*\|/.test(line.text);
    const taken: Array<[number, number]> = [];
    const add = (start: number, end: number, severity: Severity, confidence: Confidence, message: string) => {
      if (taken.some(([s, e]) => start < e && end > s)) return;
      taken.push([start, end]);
      // "Never use `launchctl submit`", "Do not add a second set in .claude/settings.json".
      if (isWarningContext(line.text, start)) {
        severity = "info";
        confidence = "low";
        message = "Mentions persistence in what looks like a warning. Listed for inventory.";
      }
      findings.push(
        findingAt(rule, file, { offset: line.offsets[start]!, length: end - start, message, confidence, severity }),
      );
    };

    for (const { re, label, severity } of COMMANDS) {
      re.lastIndex = 0;
      for (const m of execAll(re, line.text)) {
        if (tableRow && line.text[m.index] === "|") continue;
        // `| crontab -e | Edit cron jobs |`: a command reference table documents commands, it doesn't run them.
        if (tableRow) add(m.index, m.index + m[0].length, "low", "medium", `Mentions a persistence command in a table: ${label}. Listed for inventory.`);
        else add(m.index, m.index + m[0].length, severity, "high", persistMessage(label));
      }
    }

    const lineWrites = WRITE_ON_LINE.test(line.text);
    for (const { re, label, severity, proseSeverity, plainSeverity } of LOCATIONS) {
      re.lastIndex = 0;
      for (const m of execAll(re, line.text)) {
        const [start, end] = pathToken(line.text, m.index, m.index + m[0].length);
        const before = line.text.slice(0, start);
        const after = line.text.slice(end);
        const redirect = WRITE_BEFORE.test(before) && !PLACEHOLDER_BEFORE.test(before) && !ARROW_AFTER.test(after);
        // "Copy the folder into ~/.claude/skills/" is prose; `cp -r x ~/.claude/skills/` is a command.
        const copy = COPY_BEFORE.test(before) && COMMAND_END.test(after) && !PROSE_PREPOSITION.test(before);
        const commandWrite = redirect || copy || lineWrites;
        if (commandWrite) {
          const level = plainSeverity && !SUSPICIOUS_PAYLOAD.test(line.text) ? plainSeverity : severity;
          add(start, end, level, "high", persistMessage(`writes to ${label}`));
        } else if (PROSE_BEFORE.test(before)) {
          add(start, end, proseSeverity ?? severity, "medium", persistMessage(`asks to write to ${label}`));
        }
      }
    }
  }
  return findings;
}

function persistMessage(what: string): string {
  return `Persistence: ${what}. Whatever lands there keeps running after the session ends. Skills should not install it — remove it or leave it to the user.`;
}
