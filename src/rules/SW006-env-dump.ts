import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { isWarningContext } from "./phrases.js";
import { withVocab } from "./vocabulary.js";

/** Sending data out on the same line turns a dump into exfiltration. Exported for reuse by other rules. */
export const EGRESS = withVocab(
  /\b(?:curl|wget|nc|ncat|netcat|socat|scp|telnet|ftp|__psFetch__|webhook)\b|\b(?:requests|httpx|axios|http|https|urllib\.request|aiohttp)\.(?:post|put|get|request|urlopen)\b|\bfetch\s*\(|\/dev\/(?:tcp|udp)\//i,
);

/** Secret-looking variable names, for `env | grep -i token`-style hunting. */
const SECRET_NAMES = /key|token|secret|pass|cred|auth|aws|gcp|azure|api/i;

interface Pattern {
  re: RegExp;
  label: string;
  /** Base severity/confidence before the egress check. */
  severity: Severity;
  confidence: Confidence;
}

const re = (source: string, flags = "gi") => new RegExp(source, flags);

const PROC_LABEL = "process environment from /proc";

/** Code-level dumps, matched everywhere. */
const CODE_PATTERNS: Pattern[] = [
  { re: re(String.raw`/proc/(?:self|\d+|\*|\$\{?\w+\}?)/environ\b`), label: PROC_LABEL, severity: "high", confidence: "high" },
  // A command of its own, not `npx expo export -p web`.
  { re: re(String.raw`(?:^|(?<=[;&|(\x60]|\$\()\s*)export\s+-p(?=\s*(?:$|[|;&)>\x60]))`), label: "export -p", severity: "medium", confidence: "medium" },
  {
    re: re(String.raw`\b(?:Get-ChildItem|gci|dir|ls|Get-Item)\s+(?:-Path\s+)?["']?env:(?:[\\/]?\*)?["']?(?=\s|$|[|;)\x60])`),
    label: "PowerShell Env: drive listing",
    severity: "medium",
    confidence: "high",
  },
  {
    re: re(String.raw`\[(?:System\.)?Environment\]::GetEnvironmentVariables\s*\(\s*\)`),
    label: "GetEnvironmentVariables()",
    severity: "medium",
    confidence: "high",
  },
  {
    re: re(String.raw`\b(?:JSON\.stringify|console\.(?:log|dir|info|error|warn|table)|util\.inspect)\s*\(\s*process\.env\s*[,)]`),
    label: "process.env serialized",
    severity: "medium",
    confidence: "high",
  },
  // Loops and Object.entries over the environment are left out on purpose: they are how child
  // environments get filtered (`{k: v for k, v in os.environ.items() if …}`). Sending them out is
  // still caught by the egress check below.
  {
    re: re(String.raw`\b(?:print|pprint|json\.dumps|str|repr|yaml\.dump|logging\.\w+|logger\.\w+)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b(?![\w.\[])`),
    label: "os.environ serialized",
    severity: "medium",
    confidence: "high",
  },
  {
    re: re(String.raw`\b(?:p|pp|puts|print)\s*\(?\s*ENV(?:\.(?:to_h|to_a|inspect))?\b(?!\s*[\[.])|\bENV\.inspect\b`, "g"),
    label: "Ruby ENV dumped",
    severity: "medium",
    confidence: "medium",
  },
  { re: re(String.raw`\bfmt\.\w*Print\w*\s*\([^)\n]*\bos\.Environ\s*\(\s*\)`), label: "os.Environ() printed", severity: "medium", confidence: "high" },
];

/** Whole-environment references that are only a dump when sent out on the same line. */
// `$ENV` is a shell variable (often "prod"/"staging"), not Ruby's ENV.
const WHOLESALE = re(String.raw`(?<![\w.$])(?:process\.env|os\.environ|ENV)(?![\w.\[$])|\bos\.Environ\s*\(\s*\)`, "g");
/** Passing the environment to a child process is normal. */
const CHILD_ENV =
  /\benv\s*[:=]\s*(?:\{\s*\.\.\.)?(?:process\.env|os\.environ|dict\(\s*os\.environ\s*\))|\bEnv\s*=\s*(?:append\()?os\.Environ\(\)|\.\.\.process\.env\b/;

/** Bare `env` / `printenv` as a command: preceded by a command boundary, followed by end/pipe/redirect. */
// A quote or brace before `env` is usually a string or a placeholder (`"env"`, `${env}`, `{env}`, `\begin{env}`),
// so a quote only counts as a boundary where a JSON value starts (`"command": "env > /tmp/x"`).
const BARE_COMMAND =
  /(?:^|[;&|(`]|(?<=:\s*)"|\$\(|\b(?:sudo|then|do|exec|time)\s)\s*(env|printenv)(?:\s+(?:-0|--null))?\s*(?=$|[|;&)>`"]|\s+(?:\||>|;|&&|\)))/gi;
/** `/proc/self/environ` is only a dump when something reads it; pentest guides list it as an LFI target. */
const PROC_READ =
  /(?<![\w-])(?:cat|strings|tr|xargs|less|more|head|tail|grep(?!\s+-\w*q)|sed|awk|od|xxd|base64|Get-Content|readFile\w*|read_text|open)(?![\w-])|<\s*\/proc/;
/** `?file=/proc/self/environ`, `file:///proc/…`: a path requested from a remote target, not read here. */
const REMOTE_PATH_BEFORE = /(?:=|:\/\/)[^\s"'`]*$/;
const GREP_AFTER = /^\s*(?:-0\s+|--null\s+)?\|\s*(?:sort\s*\|\s*)?(?:grep|rg|findstr|Select-String)\b(.*)$/i;
/** "run `env`" — an inline `env` that is a command, not a name. */
const RUN_BEFORE = /(?:\b(?:run|execute|type|call|enter|paste)|(?<!\p{L})(?:выполни|запусти|введи))\s+`(?:env|printenv)`/iu;

const PROSE = [
  re(
    String.raw`\b(print|dump|list|show|send|upload|output|display|collect|post|share|paste|exfiltrate|report|log)\s+(?:out\s+)?(?:all|every|each|the\s+(?:full|entire|complete|whole)|your|all\s+(?:of\s+)?(?:the|your))\s+(?:of\s+(?:the|your)\s+)?(?:environment(?:al)?\s+variables|env(?:ironment)?\s+vars?|environment)\b`,
  ),
  re(
    String.raw`(?<!\p{L})(выведи|покажи|отправь|пришли|собери|скопируй|перешли|вставь|выгрузи|загрузи)\s+(?:мне\s+)?(?:все|всё|полный\s+список|список\s+всех)\s+переменн\p{L}*\s+(?:окружени|сред)\p{L}*`,
    "giu",
  ),
];
const PROSE_SEND = /^(?:send|upload|post|share|paste|exfiltrate|report|отправь|пришли|перешли|выгрузи|загрузи)$/i;

const SHELL_LANGS = new Set(["", "sh", "bash", "zsh", "shell", "console", "terminal", "shellsession", "fish", "ksh"]);

const rule: Rule = {
  id: "SW006",
  name: "env-dump",
  severity: "medium",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Dumps of the whole environment (`env`, `printenv`, `process.env`, `os.environ`, `/proc/self/environ`, `Get-ChildItem Env:`). Environment variables hold API keys and tokens; high when the same line sends data out.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

interface Hit {
  start: number;
  end: number;
  severity: Severity;
  confidence: Confidence;
  label: string;
  /** `sent`: the line also sends data out; `mention`: named but not read (an LFI target list, a URL, a warning). */
  kind: "dump" | "sent" | "mention";
}

interface CommandRange {
  start: number;
  end: number;
  inline: boolean;
  content: string;
}

function checkFile(file: ParsedFile): Finding[] {
  const hits: Hit[] = [];
  const contexts = commandContext(file);
  const contextAt = (offset: number) => contexts.find((r) => offset >= r.start && offset < r.end);

  for (const line of logicalLines(file.text)) {
    if (/^\s*#!/.test(line.text)) continue;
    const egress = EGRESS.test(line.text);
    const lineHits: Hit[] = [];
    const add = (index: number, length: number, label: string, severity: Severity, confidence: Confidence, mention = false) => {
      const start = line.offsets[index]!;
      const end = line.offsets[Math.min(index + length, line.offsets.length) - 1]! + 1;
      if (lineHits.some((h) => start < h.end && end > h.start)) return;
      if (mention) lineHits.push({ start, end, label, severity: "info", confidence: "low", kind: "mention" });
      else if (egress) lineHits.push({ start, end, label, severity: "high", confidence: "high", kind: "sent" });
      else lineHits.push({ start, end, label, severity, confidence, kind: "dump" });
    };

    for (const { re: pattern, label, severity, confidence } of CODE_PATTERNS) {
      for (const m of execAll(pattern, line.text)) {
        const mention =
          label === PROC_LABEL &&
          (REMOTE_PATH_BEFORE.test(line.text.slice(0, m.index)) || !PROC_READ.test(line.text) || isWarningContext(line.text, m.index));
        add(m.index, m[0].length, label, severity, confidence, mention);
      }
    }

    for (const m of execAll(BARE_COMMAND, line.text)) {
      const name = m[1]!;
      const nameIndex = m.index + m[0].lastIndexOf(name);
      const context = contextAt(line.offsets[nameIndex]!);
      if (!context) continue;
      // Inline `env` in prose is usually a name ("the `env` section"); only "run `env`" is a command.
      if (context.inline && /^\s*(?:env|printenv)\s*$/i.test(context.content) && !RUN_BEFORE.test(line.text)) continue;
      const rest = line.text.slice(nameIndex + name.length);
      const before = line.text.slice(0, nameIndex);
      // `"env": {` is a JSON key, not a command.
      if (/^\s*["']\s*:/.test(rest)) continue;
      // `\.(env|secret)$` is a regex alternation, not a pipe; `$(env)` is still a command.
      if (/[(|]$/.test(before) && !/\$\($/.test(before) && /^[|)]/.test(rest)) continue;
      const grep = GREP_AFTER.exec(rest);
      if (grep) {
        // Filtering for one variable is a check; hunting for secret names is not.
        // Only the grep's own arguments: `env | grep -i bitbucket || echo "no token found"`.
        if (!SECRET_NAMES.test(grep[1]!.split(/\|\||;|&&/)[0]!)) continue;
        add(nameIndex, name.length, `${name} filtered for secret names`, "medium", "high");
        continue;
      }
      add(nameIndex, name.length, name.toLowerCase(), "medium", "high");
    }

    if (egress && !CHILD_ENV.test(line.text)) {
      for (const m of execAll(WHOLESALE, line.text)) add(m.index, m[0].length, "the whole environment", "high", "high");
    }

    for (const pattern of PROSE) {
      for (const m of execAll(pattern, line.text)) {
        // "Do not dump the full environment; it may contain credentials."
        if (isWarningContext(line.text, m.index)) continue;
        add(m.index, m[0].length, "all environment variables", PROSE_SEND.test(m[1]!) ? "high" : "medium", "medium");
      }
    }
    hits.push(...lineHits);
  }

  return hits.map((h) =>
    findingAt(rule, file, {
      offset: h.start,
      length: h.end - h.start,
      message:
        h.kind === "sent"
          ? `Dumps environment variables (${h.label}) and sends them out. Env vars hold API keys and tokens. Remove it.`
          : h.kind === "mention"
            ? `Mentions the ${h.label} without reading it here (a target list, a URL or a warning). Listed for inventory.`
            : `Dumps environment variables (${h.label}). Env vars hold API keys and tokens that end up in logs or the agent's context. Read only the specific variable you need.`,
      confidence: h.confidence,
      severity: h.severity,
    }),
  );
}

/**
 * Where a bare `env` is a shell command rather than a word: shell scripts, JSON/text files,
 * shell code blocks and inline code spans in markdown. Not in Python/JS code, where `env` is a variable.
 */
function commandContext(file: ParsedFile): CommandRange[] {
  const whole: CommandRange[] = [{ start: 0, end: file.text.length, inline: false, content: "" }];
  if (file.type === "script") return file.script!.language === "shell" || file.script!.language === "unknown" ? whole : [];
  if (file.type !== "markdown") return whole;
  const ranges: CommandRange[] = [];
  for (const block of file.markdown!.codeBlocks) {
    if (SHELL_LANGS.has(block.lang)) ranges.push({ start: block.offset, end: block.offset + block.content.length, inline: false, content: "" });
  }
  for (const m of file.text.matchAll(/`([^`\n]+)`/g)) {
    ranges.push({ start: m.index + 1, end: m.index + 1 + m[1]!.length, inline: true, content: m[1]! });
  }
  return ranges;
}
