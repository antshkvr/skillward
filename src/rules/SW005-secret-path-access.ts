import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt, isScriptCommentLine } from "./helpers.js";
import { APOS, isWarningContext } from "./phrases.js";
import { vocab } from "./vocabulary.js";

/** Path separator, including JSON-escaped backslashes. */
const SEP = String.raw`(?:/|\\{1,2})`;
/** Home directory in shell, PowerShell, cmd and absolute forms. */
const HOME =
  String.raw`(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\$env:(?:USERPROFILE|HOME)|/home/[\w.-]+|/Users/[\w.-]+|/root|[A-Za-z]:${SEP}Users${SEP}[\w. -]+?)${SEP}`;
const END = String.raw`(?![\w-]|\.\w)`;
/** A space, possibly shell-escaped: `Application\ Support`. */
const SP = String.raw`\\? `;
/** Excludes non-secret files inside a credentials directory, e.g. `~/.ssh/id_ed25519.pub`. */
const notFollowedBy = (names: string) => String.raw`(?!${SEP}(?:${names})${END})`;

interface SecretPattern {
  re: RegExp;
  label: string;
  /** `file`: a credential store itself. `dir`: a location holding credentials. */
  strength: "file" | "dir";
}

const re = (source: string) => new RegExp(source, "gi");

const PATTERNS: SecretPattern[] = [
  // Credential files.
  { re: re(String.raw`\.ssh${SEP}id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?!\.pub)${END}`), label: "an SSH private key", strength: "file" },
  { re: re(String.raw`\.aws${SEP}credentials${END}`), label: "AWS credentials", strength: "file" },
  {
    re: re(String.raw`\.config${SEP}gcloud${SEP}(?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials)`),
    label: "Google Cloud credentials",
    strength: "file",
  },
  { re: re(String.raw`\.azure${SEP}(?:accessTokens\.json|msal_token_cache\.\w+)`), label: "Azure tokens", strength: "file" },
  { re: re(String.raw`\.kube${SEP}config${END}`), label: "Kubernetes credentials", strength: "file" },
  { re: re(String.raw`\.docker${SEP}config\.json`), label: "Docker registry credentials", strength: "file" },
  { re: re(String.raw`(?<![\w.-])\.git-credentials${END}`), label: "stored Git credentials", strength: "file" },
  { re: re(String.raw`(?<![\w.-])[._]netrc${END}`), label: "a .netrc password file", strength: "file" },
  { re: re(String.raw`${HOME}\.(?:npmrc|pypirc)${END}`), label: "package registry tokens", strength: "file" },
  {
    re: re(String.raw`\.(?:gem|cargo)${SEP}credentials(?:\.toml)?${END}|\.config${SEP}gh${SEP}hosts\.yml|\.terraform\.d${SEP}credentials\.tfrc\.json|(?<![\w.-])\.vault-token${END}`),
    label: "CLI access tokens",
    strength: "file",
  },
  { re: re(String.raw`\.claude${SEP}\.credentials\.json`), label: "Claude credentials", strength: "file" },
  { re: re(String.raw`\.gnupg${SEP}(?:private-keys-v1\.d|secring\.gpg)`), label: "GPG private keys", strength: "file" },
  { re: re(String.raw`(?<![\w-])/etc/(?:shadow|gshadow)${END}`), label: "system password hashes", strength: "file" },
  {
    re: re(String.raw`\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b|(?<![\w-])login\.keychain(?:-db)?${END}|Library${SEP}Keychains\b`),
    label: "the macOS Keychain",
    strength: "file",
  },
  { re: re(String.raw`\b(?:vaultcmd|cmdkey\s+/list)\b`), label: "Windows Credential Manager", strength: "file" },
  { re: re(String.raw`(?<![\w-])(?:Login${SP}Data|key[34]\.db)${END}`), label: "browser saved passwords", strength: "file" },
  {
    re: re(String.raw`(?<![\w-])wallet\.dat${END}|nkbihfbeogaeaoehlefnkodbefgpgknn|\.ethereum${SEP}keystore|\.config${SEP}solana${SEP}id\.json|exodus\.wallet`),
    label: "crypto wallet keys",
    strength: "file",
  },
  // Locations that hold credentials.
  { re: re(String.raw`${HOME}\.ssh${END}${notFollowedBy(String.raw`[\w.*-]+\.pub|known_hosts|config|authorized_keys`)}`), label: "the SSH directory", strength: "dir" },
  { re: re(String.raw`${HOME}\.aws${END}${notFollowedBy("config")}`), label: "the AWS config directory", strength: "dir" },
  { re: re(String.raw`${HOME}\.config${SEP}gcloud${END}`), label: "the Google Cloud config directory", strength: "dir" },
  {
    re: re(String.raw`${HOME}\.(?:azure|kube|docker|gnupg|password-store|bitcoin|electrum)${END}`),
    label: "a credentials directory",
    strength: "dir",
  },
  {
    re: re(
      String.raw`(?:Google|Microsoft|BraveSoftware)${SEP}(?:Chrome|Edge|Brave-Browser)${SEP}User${SP}Data|Library${SEP}Application${SP}Support${SEP}(?:Google${SEP}Chrome|BraveSoftware|Microsoft${SP}Edge|Firefox|Chromium)|\.config${SEP}(?:google-chrome|chromium|BraveSoftware|microsoft-edge)|\.mozilla${SEP}firefox|Mozilla${SEP}Firefox${SEP}Profiles`,
    ),
    label: "a browser profile (cookies, sessions, saved passwords)",
    strength: "dir",
  },
];

/** `path.join(os.homedir(), ".ssh", …)`, `Path.home() / ".aws"` and similar. */
const HOME_CALL = /\b(?:homedir\s*\(|expanduser\s*\(|Path\.home\s*\(|getenv\s*\(\s*["'](?:HOME|USERPROFILE)|environ\s*\[\s*["'](?:HOME|USERPROFILE)|GetFolderPath\s*\()/i;
const QUOTED_SECRET_DIR = /["'`]\.(ssh|aws|gnupg|kube|docker|azure)["'`/\\]/gi;
const PRIVATE_KEY_NAME = /\bid_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?\b(?!\.pub)|["'`]credentials["'`]/i;

/** `.env`, `.env.local` — but not `process.env`, `$env:`, or `.env.example` templates. */
const DOTENV = /(?<![\w.$-])\.env(?:\.(?!(?:example|sample|template|dist|defaults?|schema)\b)[\w-]+)?(?![\w-]|\.\w)/gi;
/** Templates and schemas hold variable names, not values: `.env.example`, `.env.dev.example`, `.env.schema`. */
const DOTENV_TEMPLATE = /(?<![\w.$-])\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist|defaults?|schema)\b/i;
/** Loading `.env` into the environment (`source .env`, `export $(cat .env | xargs)`, dotenv) is normal dev practice. */
const DOTENV_LOAD =
  /\b(?:source\s+\S*\.env|source\s+<\(|set\s+-a|export\s+\$\(\s*(?:cat|grep)\b[^)]*\.env|load_dotenv|dotenv|env_file|EnvironmentFile)\b|--env-file\b|--exclude[= ]["']?\S*\.env|(?:^|[\s;&`])\.\s+\S*\.env\b/i;

const word = (alternatives: string) => new RegExp(String.raw`(?<![\p{L}\p{N}_-])(?:${alternatives})(?![\p{L}\p{N}_-])`, "iu");
const stem = (alternatives: string) => new RegExp(String.raw`(?<!\p{L})(?:${alternatives})\p{L}*`, "iu");

/** Commands that actually send data over the network. */
const NETWORK_COMMANDS = [
  word(String.raw`curl|wget|nc|ncat|netcat|scp|rsync|ftp|sftp|${vocab("psFetch")}|requests\.post|axios\.post|fetch`),
];
/** Prose verbs about sending data. Weaker than a command: often appear in warnings and docs. */
const PROSE_SEND = [
  // Not "paste": that is the user's hand ("paste the token from the VPS .env into the dashboard").
  word(String.raw`upload|uploads|send|sends|post|exfiltrate|attach|transmit|forward|webhook`),
  stem(String.raw`отправ|загруз|передай|переда[тв]|перешл|выгруз`),
];
/** A destination on the line: URL, IP, or a host name ("send it to example.invalid"). */
const URL =
  /\bhttps?:\/\/|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|xyz|ru|cn|site|online|top|me|co|ai|sh|cc|tk|pw|info|biz|invalid)\b/i;
/** `type %USERPROFILE%\.ssh\id_rsa` — cmd's `type` prints a file; the English word is too common to match alone. */
const CMD_TYPE = /\btype\s+["']?(?:%\w+%|[A-Za-z]:[\\/])/i;
/** A config value naming the file: `"keyPath": "~/.ssh/id_rsa"` — the tool it configures will read it. */
const CONFIG_VALUE = /^\s*"[\w.-]+"\s*:\s*"$/;
/** `curl -d @.env`, `nc host < .env`, `curl -T .env`: the file itself is the payload. */
const DOTENV_PAYLOAD = /(?:@|<\s*|--upload-file\s+|-T\s+|--data(?:-binary|-raw)?\s+)["']?[^\s"']*\.env\b/;
const READ_COMMANDS = [
  word(String.raw`cat|less|more|head|tail|cp|copy|tar|zip|grep|base64|Get-Content|gc|readFile|readFileSync|read_text|open|strings|xxd|hexdump|find-generic-password|find-internet-password|dump-keychain`),
];
const PROSE_READ_VERBS = [
  // Imperatives only: "the server reads .env at boot" describes a program, not an instruction.
  word(String.raw`read|print|show|display|dump|include|collect|gather|extract|grab|list|look at`),
  stem(String.raw`прочит|прочт|выведи|вывест|покаж|открой|откры|скопир|собер|собра|вставь|извлек|достань`),
];
const DISPLAY_COMMAND = /(?<![\w-])(?:cat|less|more|head|tail|bat|Get-Content|gc|strings|xxd|hexdump)(?![\w-])|\btype\s+["']?(?:%\w+%|[A-Za-z]:|\S*\.env)/i;
const SINGLE_KEY_GREP = /\bgrep\b[^|]*["']\^?[A-Z][A-Z0-9_]*=?["']/;
/** `print("--- .env ---")`, `echo "create .env first"` — code printing a message that names the file. */
const CODE_PRINT = /\b(?:print|printf|echo|console\.\w+)\s*\(?\s*f?["'`]/;
/** Verbs that put the secret in front of someone, not just into the agent's context. */
const REVEAL_VERBS = [word(String.raw`print|show|display|dump|include|echo`), stem(String.raw`выведи|вывест|покаж|вставь`)];
/** `ssh -i ~/.ssh/id_rsa`: the key is used as an identity, not read. */
const IDENTITY_ARG = /(?:\s-[iIf]|--identity-file|IdentityFile|ssh-add)\s*=?\s*["']?[^\s"']*$/;
/** `[ -f ~/.git-credentials ]`, `grep -q host ~/.netrc`, `Test-Path`: checks that a file exists, doesn't read it out. */
const EXISTENCE_CHECK = /(?:\[\[?|\btest)\s+-[efsr]\s+["']?$|\bTest-Path\s+["']?$|\b(?:exists|isfile|is_file|existsSync|access)\s*\(\s*["'`]?$|\bgrep\s+-[a-zA-Z]*q[a-zA-Z]*\s+(?:"[^"]*"|'[^']*'|\S+)\s+["']?$/i;
/** `cat > .env <<EOF`, `echo KEY=… >> .env`, `open(".env", "w")`: writes the file, doesn't read it. */
const WRITE_BEFORE = />>?\s*["']?$|\btee\s+(?:-a\s+)?["']?$|(?:\s-o|--output)\s*=?\s*["']?$/;
/** `Read(~/.ssh/**)` — a Claude Code permission rule quoted in docs, not an access. */
const PERMISSION_RULE_BEFORE = /\b(?:Read|Edit|Write|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|Bash)\($/;
/** "(e.g., curl posting .env files, cat ~/.ssh/id_rsa)" — examples of what to look for. */
const EXAMPLE_BEFORE = /\((?:e\.g\.|eg\.|for example|such as|like)[^)]*$|\b(?:e\.g\.,?|for example|such as)\s[^.]*$/i;
/** Non-secret files inside credential directories: `~/.aws/atx/…`, Chrome's `NativeMessagingHosts`. */
const HARMLESS_SUBPATH = /^(?:\/|\\{1,2})(?:NativeMessagingHosts|Extensions|policies|atx|cli|sso\/cache\/[\w-]+\.lock|plugins)\b/i;
const WRITE_MODE_AFTER = /^["'`]?\s*,\s*["'](?:w|a|wb|ab|x)["']/;
/**
 * A negation or warning earlier in the same sentence: "Never copy credential files (`.env`, keys)",
 * "Don't attach secrets by default (`.env`, key files)", "never read contents".
 */
const NEGATION = new RegExp(
  String.raw`(?<![\p{L}\p{N}_])(?:never|don${APOS}?t|do not|does not|must not|should not|shouldn${APOS}t|cannot|can${APOS}t|not|avoid|instead of|rather than|никогда|не|нельзя|без)(?![\p{L}\p{N}_])`,
  "iu",
);
/** Source code that defines patterns rather than accessing files: detectors, blocklists, scanners. */
const PATTERN_DEFINITION = /\bre\.compile\s*\(|\bnew RegExp\s*\(|\bRegExp\s*\(|\b[Pp]atterns?\s*[:=]|\b_?add\s*\(\s*r["']|\br["'][^"']*\\|\/[^/\s]*\\\.[^/]*\/[gimsuy]*/;

/** Regex syntax on the line: escaped parens or pipes, `\s+`, `.{0,30}`, `[^…]` — a grep pattern or a detector. */
const REGEX_SYNTAX = /\\[()|]|\\s[*+]|\.\{\d|\[\^/;
const TARGETED_KEYCHAIN = /\bfind-(?:generic|internet)-password\b(?=[^|;&]*\s-[sl]\s)/;
const CREDENTIAL_LIST = /\bcmdkey\s+\/list\b/i;

const matchesAny = (patterns: RegExp[], text: string) => patterns.some((p) => p.test(text));

const rule: Rule = {
  id: "SW005",
  name: "secret-path-access",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "References to credential stores: ~/.ssh, ~/.aws, ~/.config/gcloud, .env, ~/.netrc, the keychain, browser profiles, wallets. Severity rises when the same line reads or sends them.",
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
  message: string;
  label: string;
  exfil: boolean;
}

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  const permissions = permissionRules(file);
  for (const line of logicalLines(file.text)) {
    const hits = checkLine(line.text);
    // A comment in a script documents the code ("a planted ~/.ssh/id_rsa symlink must not be read"); it doesn't run.
    // Kept visible when it also talks about sending, since an agent reads comments too.
    const comment = hits.length > 0 && isScriptCommentLine(file, line.text);
    for (const hit of hits) {
      let { message, confidence, severity } = hit;
      const perm = permissions && permissionRuleAt(line.text, hit, permissions);
      if (perm === "deny") continue; // `"deny": ["Read(./.env)"]` protects the file.
      if (perm === "allow") {
        message = `A permission rule lets the agent use ${hit.label} without asking. Move it to "deny" unless the agent truly needs it.`;
        [severity, confidence] = ["medium", "medium"];
      } else if (comment) {
        message = `Mentions ${hit.label} in a code comment${hit.exfil ? " that also talks about sending data. Check what the code around it does." : ". Listed for inventory."}`;
        [severity, confidence] = [hit.exfil ? "medium" : "info", "low"];
      }
      findings.push(findingAt(rule, file, { offset: line.offsets[hit.start]!, length: hit.end - hit.start, message, confidence, severity }));
    }
  }
  return findings;
}

type PermissionKind = "allow" | "deny";

/** Claude Code `permissions` entries of a settings file, by kind (`ask` counts as protective, like `deny`). */
function permissionRules(file: ParsedFile): Map<string, PermissionKind> | undefined {
  const value = file.json?.value as { permissions?: Record<string, unknown> } | undefined;
  const perms = value?.permissions;
  if (!perms || typeof perms !== "object") return undefined;
  const rules = new Map<string, PermissionKind>();
  for (const [key, kind] of [["allow", "allow"], ["deny", "deny"], ["ask", "deny"]] as const) {
    const list = perms[key];
    if (Array.isArray(list)) for (const entry of list) if (typeof entry === "string") rules.set(entry, kind);
  }
  return rules;
}

/** The permission rule whose JSON string literal on this line contains the hit, if any. */
function permissionRuleAt(text: string, hit: Hit, rules: Map<string, PermissionKind>): PermissionKind | undefined {
  for (const m of execAll(/"((?:[^"\\]|\\.)*)"/g, text)) {
    if (hit.start < m.index || hit.end > m.index + m[0].length) continue;
    let entry: string;
    try {
      entry = JSON.parse(m[0]) as string;
    } catch {
      continue;
    }
    return rules.get(entry);
  }
  return undefined;
}

/**
 * A substring of every pattern above. Lines without any of these can't match, so the ~25 path
 * regexes and the verb lists are skipped for them. Keep in sync when adding patterns.
 */
const MAYBE_SECRET =
  /\.ssh|\.aws|gcloud|\.azure|\.kube|\.docker|netrc|npmrc|pypirc|credential|hosts\.yml|vault-token|gnupg|shadow|password|keychain|vaultcmd|cmdkey|login|key[34]\.db|wallet|nkbih|ethereum|solana|exodus|bitcoin|electrum|chrom|edge|brave|firefox|mozilla|\.env/i;

const SENTENCE_END = /[.;!?]\s|\s[—–]\s/g;

/** Verbs and markers in the sentence around a hit. Prose lines hold several sentences; code lines are one. */
interface Context {
  network: boolean;
  proseSend: boolean;
  readCommand: boolean;
  proseRead: boolean;
  destination: boolean;
  /** A negation or warning earlier in the same sentence. */
  negated: boolean;
}

function contextAt(text: string, start: number, end: number): Context {
  let from = 0;
  let to = text.length;
  for (const m of execAll(SENTENCE_END, text)) {
    if (m.index + m[0].length <= start) from = m.index + m[0].length;
    else if (m.index >= end) {
      to = m.index;
      break;
    }
  }
  // Shell variables are not verbs: `${NC}` (a color) is not netcat.
  const sentence = text.slice(from, to).replace(/\$\{?\w+\}?/g, "$V");
  const negated = NEGATION.test(text.slice(from, start));
  const shell = /[|&;]|\$\(/.test(sentence);
  return {
    // "Never tar or rsync over it, exclude .env" is prose about a command; `x; curl -d @~/.ssh/id_rsa …` is not.
    network: matchesAny(NETWORK_COMMANDS, sentence) && !(negated && !shell) && !isWarningContext(text, start),
    proseSend: matchesAny(PROSE_SEND, sentence),
    readCommand: matchesAny(READ_COMMANDS, sentence) || CMD_TYPE.test(sentence),
    proseRead: matchesAny(PROSE_READ_VERBS, sentence),
    destination: URL.test(sentence),
    negated,
  };
}

export function checkLine(text: string): Hit[] {
  if (!MAYBE_SECRET.test(text)) return [];
  const hits: Hit[] = [];
  const overlaps = (start: number, end: number) => hits.some((h) => start < h.end && end > h.start);
  const patternDefinition = PATTERN_DEFINITION.test(text) || REGEX_SYNTAX.test(text);

  const add = (matchStart: number, matchEnd: number, label: string, strength: "file" | "dir") => {
    // Report the whole path once: `~/.ssh/id_rsa` matches both the key file and the directory pattern.
    const [start, end] = pathToken(text, matchStart, matchEnd);
    if (overlaps(start, end)) return;
    const before = text.slice(0, start);
    const { network, proseSend, readCommand, proseRead, destination, negated } = contextAt(text, start, end);
    const exfil = network || (proseSend && destination && !negated);
    let severity: Severity;
    let confidence: Confidence;
    let kind: MessageKind;
    if (IDENTITY_ARG.test(before)) [severity, confidence, kind] = ["info", "medium", "identity"];
    else if (patternDefinition) [severity, confidence, kind] = ["info", "low", "pattern"];
    // `curl http://target.example/.ssh/id_rsa` probes a remote server (pentest docs); it isn't this machine's key.
    else if (text.slice(start, end).includes("://")) [severity, confidence, kind] = ["low", "low", "remote"];
    else if (PERMISSION_RULE_BEFORE.test(before)) [severity, confidence, kind] = ["low", "low", "permission"];
    else if (strength === "dir" && HARMLESS_SUBPATH.test(text.slice(matchEnd))) [severity, confidence, kind] = ["low", "low", "mention"];
    else if (EXAMPLE_BEFORE.test(before)) [severity, confidence, kind] = ["info", "low", "example"];
    else if (exfil) [severity, confidence, kind] = ["high", "high", "exfil"];
    else if (negated) [severity, confidence, kind] = ["low", "low", "warning"];
    else if (EXISTENCE_CHECK.test(before)) [severity, confidence, kind] = ["low", "medium", "exists"];
    else if (proseSend) [severity, confidence, kind] = ["high", "medium", "send"];
    else if (readCommand || proseRead) [severity, confidence, kind] = ["high", strength === "file" ? "high" : "medium", "access"];
    // `"GOOGLE_APPLICATION_CREDENTIALS": "~/.config/gcloud/…"`: points a tool at its own credentials, like `ssh -i`.
    else if (strength === "file" && CONFIG_VALUE.test(before)) [severity, confidence, kind] = ["medium", "medium", "access"];
    // A bare mention ("credentials live in ~/.aws/credentials", a path table in a pentest guide) accesses nothing.
    else if (strength === "file") [severity, confidence, kind] = ["low", "low", "mention"];
    else [severity, confidence, kind] = ["low", "low", "mention"];
    if (severity === "high" && !exfil && (TARGETED_KEYCHAIN.test(text) || CREDENTIAL_LIST.test(text))) {
      // `security find-generic-password -s my-tool -w` fetches the tool's own secret; `cmdkey /list` enumerates targets.
      [severity, confidence, kind] = ["medium", "medium", "access"];
    }
    hits.push({ start, end, severity, confidence, message: messageFor(label, kind), label, exfil });
  };

  for (const { re, label, strength } of PATTERNS) {
    re.lastIndex = 0;
    for (const m of execAll(re, text)) add(m.index, m.index + m[0].length, label, strength);
  }

  if (HOME_CALL.test(text)) {
    QUOTED_SECRET_DIR.lastIndex = 0;
    for (const m of execAll(QUOTED_SECRET_DIR, text)) {
      const strong = PRIVATE_KEY_NAME.test(text.slice(m.index));
      add(m.index, m.index + m[0].length, strong ? "credentials in the home directory" : `the ~/.${m[1]!.toLowerCase()} directory`, strong ? "file" : "dir");
    }
  }

  // `.env` is everywhere in docs ("create a .env file"), so it is only reported next to an access verb.
  // Project `.env` files are the user's own config: reading one is common dev practice, sending one is not.
  DOTENV.lastIndex = 0;
  for (const m of execAll(DOTENV, text)) {
    const [start, end] = pathToken(text, m.index, m.index + m[0].length);
    if (overlaps(start, end)) continue;
    const { network, proseSend, readCommand, proseRead, destination, negated } = contextAt(text, start, end);
    const payload = network && DOTENV_PAYLOAD.test(text);
    if (!payload && (DOTENV_TEMPLATE.test(text) || DOTENV_LOAD.test(text) || patternDefinition)) continue;
    if (WRITE_BEFORE.test(text.slice(0, m.index)) || WRITE_MODE_AFTER.test(text.slice(m.index + m[0].length))) continue;
    // `.env*`, `**/.env*` in a glob list (gitignore, copy-include, a CSV of paths) names files, it doesn't read them.
    if (text[m.index + m[0].length] === "*") continue;
    const before = text.slice(0, start);
    if (text.slice(start, end).includes("://") || PERMISSION_RULE_BEFORE.test(before) || EXAMPLE_BEFORE.test(before)) continue;
    const exfil = network || (proseSend && destination && !negated);
    if (negated && !exfil) continue;
    let severity: Severity;
    let confidence: Confidence;
    let kind: MessageKind;
    if (exfil) [severity, confidence, kind] = ["high", "high", "exfil"];
    // "Paste the keys into your .env", "add the secret to the webhook and .env" — about writing it, not sending it.
    else if (proseSend) continue;
    else if (EXISTENCE_CHECK.test(text.slice(0, m.index))) continue;
    // Printing the whole file puts every value in the agent's context; `cp .env …`, `grep '^ONE_KEY=' .env` don't.
    else if (DISPLAY_COMMAND.test(text) && !SINGLE_KEY_GREP.test(text)) [severity, confidence, kind] = ["medium", "medium", "dotenv"];
    else if (readCommand) [severity, confidence, kind] = ["low", "low", "dotenv"];
    else if (proseRead && matchesAny(REVEAL_VERBS, text) && !CODE_PRINT.test(text)) [severity, confidence, kind] = ["medium", "low", "dotenv"];
    else if (proseRead) [severity, confidence, kind] = ["low", "low", "dotenv"];
    else continue;
    const label = "a .env file with secrets";
    hits.push({ start, end, severity, confidence, message: messageFor(label, kind), label, exfil });
    // One `.env` finding per line is enough.
    break;
  }

  // A line that names several credential stores is a list — a blocklist, a detector, an audit checklist or an
  // attack-surface table — not an instruction to open each of them. Exfiltration still counts.
  const quoted = (h: Hit) => /["'`]/.test(text[h.start - 1] ?? "") && text[h.end] === text[h.start - 1];
  if (hits.length >= 3 || (hits.length === 2 && hits.every(quoted) && /[,[{|]/.test(text))) {
    for (const h of hits) {
      if (h.exfil || h.severity === "info") continue;
      h.severity = "info";
      h.confidence = "low";
      h.message = `Lists ${h.label} among other credential stores (a blocklist, detector or checklist). Listed for inventory.`;
    }
  }

  return hits.sort((a, b) => a.start - b.start);
}

const DELIMITER = /[\s"'`()<>=,;|@]/;

/** Expands a match to the surrounding path token; shell-escaped spaces (`Application\ Support`) stay inside. */
function pathToken(text: string, start: number, end: number): [number, number] {
  const isDelimiter = (i: number) => DELIMITER.test(text[i]!) && !(text[i] === " " && text[i - 1] === "\\");
  while (start > 0 && !isDelimiter(start - 1)) start--;
  while (end < text.length && !isDelimiter(end)) end++;
  return [start, end];
}

type MessageKind =
  | "identity"
  | "pattern"
  | "remote"
  | "permission"
  | "example"
  | "exfil"
  | "warning"
  | "exists"
  | "send"
  | "access"
  | "dotenv"
  | "mention";

function messageFor(label: string, kind: MessageKind): string {
  switch (kind) {
    case "identity":
      return `Uses ${label} as an SSH identity. Normal for ssh/git; listed for inventory — make sure the key itself is never read or sent.`;
    case "pattern":
      return `Mentions ${label} in a pattern definition (a detector or blocklist). Listed for inventory.`;
    case "remote":
      return `Mentions ${label} as a path on a remote server (a URL), not on this machine. Listed for inventory.`;
    case "permission":
      return `Mentions ${label} in a permission rule. Make sure it is in "deny", not "allow".`;
    case "example":
      return `Mentions ${label} as an example. Listed for inventory.`;
    case "exfil":
      return `Accesses ${label} on a line that also sends data out. This is how credentials get stolen. Remove it.`;
    case "warning":
      return `Mentions ${label} in what looks like a warning. Listed for inventory.`;
    case "exists":
      return `Checks whether ${label} exists. Make sure its contents are never printed or sent.`;
    case "send":
      return `Mentions ${label} next to sending or uploading data. Check that its contents never leave the machine.`;
    case "dotenv":
      return `Reads ${label}. Its values land in the agent's context and in anything it calls or logs. Read only the variable you need.`;
    case "mention":
      return `Mentions ${label}. Skills and instructions rarely need it; check that nothing reads or uploads it.`;
    case "access":
      return `Accesses ${label}. Reading it exposes credentials to the agent and anything it calls. Remove it unless truly required.`;
  }
}
