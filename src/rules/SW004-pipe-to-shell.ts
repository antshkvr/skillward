import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt, isScriptCommentLine } from "./helpers.js";
import { isWarningContext } from "./phrases.js";
import { vocab } from "./vocabulary.js";

/** Commands that fetch remote content to stdout. */
const FETCH = String.raw`(?:curl|wget|fetch)`;
/** Shells and interpreters that can execute code given to them. */
const SHELL = String.raw`(?:(?:ba|da|z|k|c|tc|fi|a)?sh|python[\d.]*|perl|ruby|node|php|pwsh|powershell(?:\.exe)?|source)`;
/** End of a command name: `sh` but not `shellcheck`, `sh-foo` or `sh.exe`; a trailing full stop is fine. */
const END = String.raw`(?![\w-]|\.\w)`;
/** Optional privilege escalation / env prefix between the pipe and the shell. */
const PREFIX = String.raw`(?:(?:sudo|doas)(?:\s+-{1,2}[\w-]+)*\s+)?(?:env\s+(?:\w+=\S*\s+)*)?`;
/** One pipeline stage's text: no newline, `|`, `;` or `&&`. */
const STAGE = String.raw`(?:(?!&&)[^|\n;])`;
/** What follows the command name when it reads code from stdin, not data for a script. */
const STDIN_CODE = String.raw`(?=\s*(?:$|-(?:\s|$)|[;&|)]|["'\x60](?=\s|$|[;&|)])))`;
/**
 * The command a download is piped into, when it executes stdin:
 * a shell, unless given `-c` or a script file; an interpreter with no script, `-m`, `-c` or `-e`.
 */
const PIPE_TARGET =
  String.raw`(?:(?:ba|da|z|k|c|tc|fi|a)?sh${END}(?!\s+-c\b)(?!\s+[^-\s|;&)"'\x60<>])(?!\s+["'\x60][^\s"'\x60;&|)])` +
  String.raw`|(?:python[\d.]*|perl|ruby|node|php)${END}${STDIN_CODE}` +
  String.raw`|(?:pwsh|powershell(?:\.exe)?)${END}(?=\s*(?:$|-(?:\s|$)|-c(?:ommand)?\s+-(?:\s|$)|[;&|)"'\x60])))`;

interface Pattern {
  re: RegExp;
  label: string;
}

const PATTERNS: Pattern[] = [
  {
    // curl -fsSL https://… | sudo bash -s --   (intermediate stages like `| tee log |` allowed)
    re: new RegExp(
      String.raw`(?<![\w.-])${FETCH}\s+${STAGE}*?[^|\s;&]${STAGE}*(?:\|(?!\|)${STAGE}*)*?(?<!\|)\|(?!\|)\s*${PREFIX}${PIPE_TARGET}`,
      "gi",
    ),
    label: "remote download piped into a shell",
  },
  {
    // bash <(curl …), source <(wget -qO- …)
    re: new RegExp(String.raw`(?<![\w.-])(?:${SHELL}|\.)\s+<\(\s*${FETCH}${END}`, "gi"),
    label: "remote download executed via process substitution",
  },
  {
    // bash -c "$(curl …)", eval "$(wget -O- …)", sh -c `curl …`
    re: new RegExp(
      String.raw`(?<![\w.-])(?:${SHELL}(?:\s+-\w+)*|eval)\s+["']?(?:\$\(|\x60)\s*${FETCH}${END}`,
      "gi",
    ),
    label: "remote download executed via command substitution",
  },
  // PowerShell download-and-execute. The cmdlet names come from data/vocabulary.json (see vocabulary.ts).
  {
    // <download cmdlet> https://… | <expression cmdlet>
    re: new RegExp(
      String.raw`(?<![\w.-])(?:${vocab("psFetch")}|curl|wget)\b[^|\n]*(?:\|(?!\|)[^|\n]*)*?\|\s*${vocab("psEval")}\b`,
      "gi",
    ),
    label: "PowerShell download piped into execution",
  },
  {
    // <expression cmdlet> (<download cmdlet> …), or on a web client's downloaded string
    re: new RegExp(
      String.raw`(?<![\w.-])${vocab("psEval")}\b\s*(?:-Command\s+)?[("'\s]*(?:&\s*)?(?:${vocab("psFetch")}|${vocab("psHttpClient")})`,
      "gi",
    ),
    label: "PowerShell execution of downloaded content",
  },
  {
    // a web client's downloaded string piped into execution
    re: new RegExp(String.raw`${vocab("psClientRead")}\s*\([^)\n]*\)[^|\n]*\|\s*${vocab("psEval")}\b`, "gi"),
    label: "PowerShell downloaded string piped into execution",
  },
];

// ---- Where a command appears ------------------------------------------------------------------------------
// A dangerous command in a deny list, a comment, a warning or a detector's test string is documentation, not
// something that runs. Shared with SW015.

/**
 * `code`: would run (a script line, a code block, prose telling the agent to run it, a hook `command`).
 * `string`: a quoted string in code that is not handed to a shell — test data, a block list, a message.
 * `quote`: quoted in prose or a JSON value that is not a command — an example being discussed.
 */
export type CommandContext = "code" | "comment" | "warning" | "permission" | "string" | "quote" | "test";

/** Language of the text around `offset`: the script language, a code block's info string, `json` or `prose`. */
export function languageAt(file: ParsedFile, offset: number): string {
  if (file.type === "json") return "json";
  if (file.script) return file.script.language;
  if (file.type === "markdown") {
    const block = file.markdown?.codeBlocks.find((b) => offset >= b.offset && offset <= b.offset + b.content.length);
    return block ? block.lang || "code" : "prose";
  }
  return /\.(?:ya?ml|toml|dockerfile|mk)$|(?:^|\/)(?:Dockerfile|Makefile)$/i.test(file.path) ? "yaml" : "prose";
}

const HASH_COMMENT_LANGS = new Set([
  "shell", "sh", "bash", "zsh", "fish", "console", "terminal", "python", "py", "python3", "ruby", "rb", "perl", "powershell",
  "ps1", "pwsh", "yaml", "yml", "toml", "dockerfile", "makefile", "r", "code", "unknown", "php",
]);
const SLASH_COMMENT_LANGS = new Set([
  "javascript", "js", "mjs", "cjs", "typescript", "ts", "tsx", "jsx", "go", "rust", "rs", "java", "c", "cpp", "cs", "csharp",
  "kotlin", "swift", "jsonc", "php", "code", "unknown", "groovy", "scala", "dart",
]);

interface PrefixScan {
  /** Index of the opening quote of the string the match is in, or -1. */
  stringStart: number;
  quote: string;
  comment: boolean;
}

/** Walks the line up to `index`, tracking quotes and comment markers outside them. */
function scanPrefix(prefix: string, lang: string): PrefixScan {
  const prose = lang === "prose";
  const quotes = prose ? ['"', "“"] : lang === "json" ? ['"'] : SLASH_COMMENT_LANGS.has(lang) && !HASH_COMMENT_LANGS.has(lang) ? ['"', "'", "`"] : ['"', "'"];
  let quote = "";
  let start = -1;
  for (let i = 0; i < prefix.length; i++) {
    const c = prefix[i]!;
    if (quote) {
      if (c === "\\" && quote !== "'") i++;
      else if (c === quote || (quote === "“" && c === "”")) quote = "";
      continue;
    }
    if (quotes.includes(c)) {
      // An apostrophe inside a word ("don't") does not open a string.
      if (c === "'" && /\w/.test(prefix[i - 1] ?? "") && /\w/.test(prefix[i + 1] ?? "")) continue;
      quote = c;
      start = i;
      continue;
    }
    const atWordStart = i === 0 || /\s/.test(prefix[i - 1]!);
    if (atWordStart && c === "#" && HASH_COMMENT_LANGS.has(lang) && prefix[i + 1] !== "!") return { stringStart: -1, quote: "", comment: true };
    if (atWordStart && c === "/" && prefix[i + 1] === "/" && SLASH_COMMENT_LANGS.has(lang)) return { stringStart: -1, quote: "", comment: true };
  }
  return { stringStart: quote ? start : -1, quote, comment: false };
}

/** The string is an argument of something that runs it: `bash -c "…"`, `os.system("…")`, `ssh host "…"`. */
const EXEC_WRAPPER = new RegExp(
  String.raw`(?:\b(?:ba|z|da|k)?sh\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*c[a-zA-Z]*\s*|\b(?:pwsh|powershell)(?:\.exe)?\s+(?:-\w+(?:\s+(?!-)[\w"']+)?\s+)*?-c(?:ommand)?\s*|\beval\s+|\bssh\s+[^"'\n]*\s|\b(?:system|exec\w*|spawn\w*|popen\w*|run|call|check_call|check_output|getoutput|getstatusoutput|Popen|shell_exec|passthru|execa|Start-Process|Process\.Start|\$)\s*\(\s*(?:\[\s*)?(?:[frbu]{1,2})?|\bRUN\s+(?:\[\s*)?|\bdocker\s+(?:exec|run)\b[^"'\n]*\s)$`,
  "i",
);
/** JSON keys whose string values are commands: hooks, MCP servers, package scripts. */
const COMMAND_KEY = /"(?:[\w-]*(?:command|cmd|script)s?|run|exec|shell|args|entrypoint|install|postinstall|preinstall|prepare|setup|start|bash)"\s*:\s*(?:\[[^\]]*)?$/i;
/** A string element on its own line inside a JSON array: the key is on an earlier line. */
const OPEN_ARRAY_KEY = /"([\w-]+)"\s*:\s*\[[^\]]*$/;
/** A command line inside a string: `"-c", "…"` argument lists, `/TR "powershell -c '…'"`. */
const SHELL_C_ARG = /["']-c["']\s*,\s*$/;
const COMMAND_STRING = /\b(?:ba|z|da)?sh\s+-c\b|\b(?:pwsh|powershell)(?:\.exe)?\b[^"\n]*\s-c(?:ommand)?\b/i;
const PERMISSION_RULE = /"(?:Bash|PowerShell|Shell)\([^"]*$/;
/** Paths of tests and fixtures: attack strings there are inputs for a detector. */
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|__fixtures__|testdata|test-data)\/|\.(?:test|spec)\.\w+$|(?:^|\/)test_[^/]*\.(?:py|js|ts|rb|go|sh|ps1)$|_test\.(?:py|go|rb|sh)$/i;

const denyCache = new WeakMap<ParsedFile, string[]>();
/** `permissions.deny` / `ask` entries of a settings file: listing a command there blocks it. */
function deniedEntries(file: ParsedFile): string[] {
  let cached = denyCache.get(file);
  if (!cached) {
    const perms = (file.json?.value as { permissions?: { deny?: unknown; ask?: unknown } } | undefined)?.permissions;
    cached = [perms?.deny, perms?.ask].flatMap((list) => (Array.isArray(list) ? list.filter((e): e is string => typeof e === "string" && e.length > 3) : []));
    denyCache.set(file, cached);
  }
  return cached;
}

/**
 * Where the match at `index` of `lineText` sits. `lang` comes from `languageAt`; `lineStart` is the line's offset
 * in `textBefore`'s coordinates (for JSON arrays whose key is on an earlier line).
 */
export function commandContext(
  file: ParsedFile,
  lang: string,
  lineText: string,
  index: number,
  textBefore = "",
): CommandContext {
  if (isWarningContext(lineText, index)) return "warning";
  const prefix = lineText.slice(0, index);
  if (lang === "json") {
    if (PERMISSION_RULE.test(prefix)) return "permission";
    const denied = deniedEntries(file);
    if (denied.length && denied.some((e) => lineText.includes(JSON.stringify(e).slice(1, -1)))) return "permission";
  }
  // Attack strings in tests are inputs for a detector, whatever their syntax.
  if (TEST_PATH.test(file.path)) return "test";
  if (lang !== "prose" && lang !== "json" && isCommentLine(file, lang, lineText)) return "comment";
  const scan = scanPrefix(prefix, lang);
  if (scan.comment) return "comment";
  if (scan.stringStart >= 0) {
    const before = prefix.slice(0, scan.stringStart);
    const inside = prefix.slice(scan.stringStart + 1);
    const arrayKey = lang === "json" && /^\s*$/.test(before) ? OPEN_ARRAY_KEY.exec(textBefore.slice(-2000))?.[1] : undefined;
    const runs =
      lang === "json"
        ? COMMAND_KEY.test(before) || (arrayKey !== undefined && COMMAND_KEY.test(`"${arrayKey}": [`))
        : EXEC_WRAPPER.test(before) ||
          SHELL_C_ARG.test(before) ||
          COMMAND_STRING.test(inside) ||
          (scan.quote === '"' && HASH_COMMENT_LANGS.has(lang) && /\$\(|`/.test(inside));
    if (!runs) return lang === "prose" || lang === "json" ? "quote" : "string";
  } else if (lang === "json") {
    return "quote";
  }
  return "code";
}

function isCommentLine(file: ParsedFile, lang: string, line: string): boolean {
  if (file.script) return isScriptCommentLine(file, line);
  if (HASH_COMMENT_LANGS.has(lang) && /^\s*#(?!!)/.test(line)) return true;
  return SLASH_COMMENT_LANGS.has(lang) && /^\s*(?:\/\/|\/\*|\*\s)/.test(line);
}

/** Severity and a message suffix for a match outside plain code; undefined for code. */
export function contextSeverity(context: CommandContext): { severity: Severity; confidence: Confidence; note: string } | undefined {
  switch (context) {
    case "code":
      return undefined;
    case "warning":
      return { severity: "info", confidence: "low", note: "Mentioned in what looks like a warning; listed for inventory." };
    case "permission":
      return { severity: "info", confidence: "low", note: "Appears in a permission rule (usually a deny list); listed for inventory." };
    case "comment":
      return { severity: "low", confidence: "medium", note: "It is in a comment, so it does not run here." };
    case "quote":
      return { severity: "low", confidence: "medium", note: "It is quoted as an example, not given as a command." };
    case "test":
      return { severity: "low", confidence: "medium", note: "It is in a test or fixture file — likely input for a detector." };
    case "string":
      return { severity: "medium", confidence: "low", note: "It is in a string; check whether that string is ever run." };
  }
}

// ---- Well-known installers --------------------------------------------------------------------------------

/**
 * Official install scripts of widely used tools. Still unpinned remote code, so still reported, but as medium:
 * the host is the vendor's own, not a lookalike or a random repository.
 */
const KNOWN_INSTALLERS: RegExp[] = [
  /^(?:sh\.rustup\.rs|static\.rust-lang\.org|astral\.sh|bun\.sh|bun\.com|deno\.land|deno\.com|get\.docker\.com|ollama\.com|ollama\.ai|get\.pnpm\.io|sdk\.cloud\.google\.com|install\.python-poetry\.org|fnm\.vercel\.app|mise\.run|mise\.jdx\.dev|starship\.rs|get\.k3s\.io|tailscale\.com|dot\.net|cursor\.com|opencode\.ai|foundry\.paradigm\.xyz|nixos\.org|install\.determinate\.systems|pyenv\.run|get\.sdkman\.io|rclone\.org|fly\.io|pixi\.sh|wasmtime\.dev|get\.volta\.sh|volta\.sh|deb\.nodesource\.com|rpm\.nodesource\.com|install\.ohmyz\.sh|get\.pulumi\.com|cli\.doppler\.com|get\.rvm\.io|sh\.vector\.dev|get\.helm\.sh|ziglang\.org|get\.jetify\.com|install\.terraform\.io|get\.opentofu\.org|code-server\.dev|claude\.ai|aka\.ms|(?:community\.)?chocolatey\.org|hf\.co|huggingface\.co|x\.ai|run\.linkerd\.io|rover\.apollo\.dev|railway\.com|railway\.app|cli\.github\.com|get\.nextflow\.io|vercel\.com|supabase\.com|cloudflare\.com|sentry\.io|get\.chezmoi\.io|tea\.xyz)$/i,
];
/** Install scripts in vendors' own GitHub repositories (`raw.githubusercontent.com/<owner>/<repo>/…`). */
const KNOWN_GITHUB_INSTALLERS = /^\/(?:Homebrew\/install|nvm-sh\/nvm|ohmyzsh\/ohmyzsh|helm\/helm|anchore\/(?:grype|syft)|aquasecurity\/trivy|golangci\/golangci-lint|rbenv\/rbenv-installer|pyenv\/pyenv-installer|creationix\/nvm|tj\/n|Schniz\/fnm|jdx\/mise|starship\/starship|sigstore\/cosign|goreleaser\/goreleaser|cli\/cli|(?:microsoft|Azure|aws|awslabs|google|GoogleCloudPlatform|docker|anthropics|openai|vercel|cloudflare|hashicorp|huggingface|astral-sh|oven-sh|denoland|nodejs|rust-lang|golang|kubernetes|kubernetes-sigs|grafana|elastic|getsentry|supabase|stripe|github)\/[^/]+)\//i;

const URL_RE = /\bhttps?:\/\/([a-z0-9.-]+)(?::\d+)?(\/[^\s"'|)`;<>]*)?/i;
const BARE_HOST_RE = /(?<![\w./-])((?:[a-z0-9-]+\.)+(?:sh|io|com|org|dev|ai|run|net|rs|land|app|xyz|systems)(?![\w-]))(\/[^\s"'|)`;<>]*)?/i;

/** Host and path of the first URL at or after `index` on the line (PowerShell installers often omit the scheme: `bun.sh/install.ps1`). */
export function urlAfter(lineText: string, index: number): { host: string; path: string } | undefined {
  const rest = lineText.slice(index, index + 400);
  const m = URL_RE.exec(rest) ?? BARE_HOST_RE.exec(rest);
  return m ? { host: m[1]!.toLowerCase(), path: m[2] ?? "/" } : undefined;
}

export function isKnownInstaller(url: { host: string; path: string } | undefined): boolean {
  if (!url) return false;
  if (url.host === "raw.githubusercontent.com" || url.host === "github.com") return KNOWN_GITHUB_INSTALLERS.test(url.path);
  return KNOWN_INSTALLERS.some((re) => re.test(url.host));
}

/** `curl … | sh` with a placeholder instead of a URL: `curl * | sh`, `curl <url> | bash`, `curl ... | sh`. */
const PLACEHOLDER = /(?:^|\s)(?:\*|\.\.\.|…|<[^>\s]*>|\[[^\]\s]*\]|URL|url|\{[^}\s]*\})(?=\s|\||$)/;

const rule: Rule = {
  id: "SW004",
  name: "pipe-to-shell",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Remote code piped straight into a shell or interpreter: `curl … | bash`, `wget -O- … | sh`, `bash <(curl …)`, PowerShell download-and-execute, and variants.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of logicalLines(file.text)) {
    const seen: Array<[number, number]> = [];
    for (const { re, label } of PATTERNS) {
      re.lastIndex = 0;
      for (const m of execAll(re, line.text)) {
        const start = m.index;
        const end = start + m[0].length;
        // Several patterns can describe the same command; report it once.
        if (seen.some(([s, e]) => start < e && end > s)) continue;
        seen.push([start, end]);
        const lang = languageAt(file, line.offsets[start]!);
        const lineStart = line.offsets[0]!;
        const where = contextSeverity(commandContext(file, lang, line.text, start, lang === "json" ? file.text.slice(Math.max(0, lineStart - 2000), lineStart) : ""));
        const url = urlAfter(line.text, start);
        let severity: Severity = "high";
        let confidence: Confidence = "high";
        let message = `Executes code fetched from the network (${label}). It runs unreviewed, with your permissions, and can change at any time. Download, review and pin the script by checksum instead.`;
        if (where) {
          ({ severity, confidence } = where);
          message = `Mentions running code fetched from the network (${label}). ${where.note}`;
        } else if (!url && PLACEHOLDER.test(m[0])) {
          [severity, confidence] = ["info", "low"];
          message = `Shows the pattern of running code fetched from the network (${label}) with a placeholder instead of a URL. Listed for inventory.`;
        } else if (isKnownInstaller(url)) {
          severity = "medium";
          message = `Runs the official installer of a well-known tool from ${url!.host} (${label}). The vendor's own host, but the script is unpinned and runs unreviewed; prefer a package manager or a pinned, checksummed download.`;
        }
        findings.push(
          findingAt(rule, file, {
            offset: line.offsets[start]!,
            length: Math.min(m[0].length, line.offsets.length - start),
            message,
            confidence,
            severity,
          }),
        );
      }
    }
  }
  return findings;
}
