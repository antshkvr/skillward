import type { Confidence, Finding, ParsedFile, ParsedTarget, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { vocab, withVocab } from "./vocabulary.js";
import sw004, { commandContext, contextSeverity, isKnownInstaller, languageAt, urlAfter } from "./SW004-pipe-to-shell.js";

type Category = "remote-eval" | "destructive" | "download-exec" | "lolbin" | "encoded" | "reverse-shell";

interface Pattern {
  re: RegExp;
  category: Category;
  label: string;
}

/** Fetching or decoding code at run time. */
const FETCH_OR_DECODE = String.raw`(?:requests\.(?:get|post)|urlopen|urllib|httpx\.|fetch\s*\(|axios|https?\.get|XMLHttpRequest|responseText|atob\s*\(|b64decode|base64|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|Buffer\.from\s*\([^)]*,\s*["'](?:base64|hex)["'])`;
const EVAL_CALL = String.raw`(?<![\w$.])(?:exec|eval|execfile|new\s+Function|vm\.runIn\w*Context|runInNewContext)\s*\(`;
/** Shell or interpreter reading code from stdin (not given a script or `-c`). */
const STDIN_SHELL = String.raw`(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[\d.]*|perl|node)(?![\w.-])(?!\s+[^-\s|;&)"'\x60])`;
const HOME_OR_ROOT = String.raw`(?:"?(?:~|\$HOME|\$\{HOME\})"?\/?\*?|"?\/"?\*?|--no-preserve-root\s+\/)`;
const END = String.raw`(?=$|[\s;&|)\x60'"])`;

const PATTERNS: Pattern[] = [
  // Running fetched or decoded code.
  { re: new RegExp(`${EVAL_CALL}[^\\n]*?${FETCH_OR_DECODE}`, "g"), category: "remote-eval", label: "eval/exec of downloaded or decoded code" },
  { re: /\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\([^\n]{0,400}?(?:requests|urlopen|httpx|urllib|\.recv\s*\()/g, category: "remote-eval", label: "unpickling network data" },
  { re: new RegExp(String.raw`\b(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r)\b[^\n|]*\|\s*${STDIN_SHELL}`, "g"), category: "remote-eval", label: "decoded payload piped into a shell" },
  { re: /(?<![\w-])(?:eval|(?:ba|z|da)?sh\s+-c)\s+["']?\$\(\s*[^)\n]*\bbase64\s+(?:-d|--decode|-D)\b/g, category: "remote-eval", label: "eval of a decoded payload" },
  { re: new RegExp(String.raw`\b${vocab("psEval")}\b[^\n]{0,400}${vocab("psDecode")}|${vocab("psDecode")}[^\n]{0,400}\|\s*${vocab("psEval")}\b`, "gi"), category: "remote-eval", label: "PowerShell execution of a decoded payload" },
  // Destroying data.
  {
    re: new RegExp(String.raw`(?<![\w-])rm\s+(?:-[a-zA-Z]+\s+|--[a-z-]+\s+)*?(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\s+(?:-[a-zA-Z]+\s+|--[a-z-]+\s+)*${HOME_OR_ROOT}${END}`, "g"),
    category: "destructive",
    label: "recursive delete of the home or root directory",
  },
  {
    re: /\bRemove-Item\b(?=[^\n]{0,400}-Recurse)[^\n]{0,400}?\s(?:-(?:Literal)?Path\s+)?["']?(?:~|\$HOME|\$env:USERPROFILE|\$env:HOMEDRIVE\\?|[A-Za-z]:\\?)["']?\\?\*?(?=$|[\s;|)])/gi,
    category: "destructive",
    label: "recursive delete of the home directory or a drive",
  },
  { re: /\b(?:rd|rmdir)\s+\/s\b(?:\s+\/q)?\s+["']?(?:[A-Za-z]:\\?|%USERPROFILE%|%HOMEPATH%)["']?(?=$|\s)/gi, category: "destructive", label: "recursive delete of a drive or profile" },
  { re: /\bmkfs(?:\.\w+)?\s+(?:-\S+\s+)*\/dev\//g, category: "destructive", label: "formatting a disk" },
  { re: /\bdd\b[^\n]{0,400}\bof=\/dev\/(?:sd[a-z]|nvme\d|disk\d|hd[a-z]|xvd[a-z]|vd[a-z]|mmcblk\d)/g, category: "destructive", label: "overwriting a disk with dd" },
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/g, category: "destructive", label: "fork bomb" },
  // Windows living-off-the-land binaries that fetch and run remote code.
  { re: /\bcertutil(?:\.exe)?\s+[^\n]{0,400}-urlcache\b/gi, category: "lolbin", label: "certutil -urlcache download" },
  { re: /\bbitsadmin(?:\.exe)?\s+[^\n]{0,400}\/transfer\b/gi, category: "lolbin", label: "bitsadmin /transfer download" },
  { re: /\bmshta(?:\.exe)?\s+["']?(?:https?:|vbscript:|javascript:)/gi, category: "lolbin", label: "mshta running remote script" },
  { re: /\bregsvr32(?:\.exe)?\b[^\n]{0,400}\/i:\s*["']?https?:/gi, category: "lolbin", label: "regsvr32 loading a remote scriptlet" },
  { re: /\brundll32(?:\.exe)?\b[^\n]{0,400}javascript:/gi, category: "lolbin", label: "rundll32 running JavaScript" },
  { re: /\bmsiexec(?:\.exe)?\b[^\n]{0,400}\s\/[iq]\w*\s+["']?https?:/gi, category: "lolbin", label: "msiexec installing from a URL" },
  // Hidden PowerShell.
  {
    re: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,400}?\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+["']?[A-Za-z0-9+/]{16,}={0,2}/gi,
    category: "encoded",
    label: "Base64-encoded PowerShell command",
  },
  // Reverse shells.
  {
    re: /(?:\b(?:ba|z|da)?sh\s+-i\b[^\n]{0,400}|\bexec\s+\d+)[<>]&?\s*\/dev\/(?:tcp|udp)\/|\/dev\/(?:tcp|udp)\/(?!(?:localhost|127\.0\.0\.1)\/)[\w.-]+\/\d+[^\n]{0,400}(?:0>&1|>&\s*\d|<&\s*\d)/g,
    category: "reverse-shell",
    label: "shell over /dev/tcp",
  },
  { re: /\b(?:nc|ncat|netcat)\b[^\n]{0,400}\s-(?:[a-z]*e|c)\s+["']?(?:\/bin\/)?(?:(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell)\b/gi, category: "reverse-shell", label: "netcat executing a shell" },
  { re: /\bmkfifo\b[^\n]{0,400}\b(?:nc|ncat|netcat|openssl\s+s_client)\b/g, category: "reverse-shell", label: "named pipe into netcat" },
  { re: /\bsocat\b[^\n]{0,400}\b(?:exec|system):[^\n]{0,400}(?:sh|bash|cmd)\b/gi, category: "reverse-shell", label: "socat executing a shell" },
  { re: /\bsocket\b(?=[^\n]{0,400}\bdup2\s*\()(?=[^\n]{0,400}(?:subprocess|pty\.spawn|\/bin\/(?:ba)?sh))/g, category: "reverse-shell", label: "Python socket + dup2 shell" },
  { re: new RegExp(String.raw`${vocab("psSocket")}\b(?=[^\n]{0,400}\b${vocab("psEval")}\b)`, "gi"), category: "reverse-shell", label: "PowerShell TCP client running commands" },
];

const DOWNLOAD_TOOL = new RegExp(String.raw`\b(?:curl|wget|fetch|${vocab("psFetch", "psBits")})\b`, "i");
const VERIFY = /\b(?:sha(?:1|224|256|384|512)sum|shasum|md5sum|Get-FileHash|gpg\s+--verify|cosign\s+verify|minisign|sigstore)\b/i;
/** Same line: download from a URL, then make it executable or run it. */
const DOWNLOAD_THEN_RUN = withVocab(
  /\b(?:curl|wget|fetch|__psFetch__|__psBits__)\b[^\n]{0,400}?\bhttps?:\/\/[^\n]{0,400}?(?:&&|;|\|\|)\s*[^\n]{0,400}?(?:chmod\s+(?:[ugoa]*\+x|[0-7]{3,4})\b|(?:^|[\s;&(])\.\/[\w.-]+|(?:sudo\s+)?(?:ba|z|da)?sh\s+(?!-c\b)[\w./~$-]+|\bStart-Process\b|&\s*["']?\.?[\\/]?[\w.-]+\.exe|\b[\w./\\-]+\.(?:exe|msi|AppImage|run|pkg|dmg)\b)/i,
);
const OUTPUT_FILE = /(?:\s-o\s*|\s--output[=\s]|\s-O\s+|\s-OutFile\s+|\s-Destination\s+)["']?([^\s"';&|]+)/i;
const SHELLISH = new Set(["", "sh", "bash", "zsh", "shell", "console", "terminal", "ps1", "powershell", "pwsh", "cmd", "bat", "batch", "python", "py", "python3", "js", "javascript", "mjs", "ts", "typescript", "node", "ruby", "rb", "perl", "php", "json", "jsonc", "yaml", "yml", "dockerfile", "makefile"]);

const rule: Rule = {
  id: "SW015",
  name: "dangerous-script",
  severity: "high",
  appliesTo: ["skill", "instructions", "settings", "plugin-manifest"],
  description:
    "Dangerous code in skill scripts and code blocks: eval/exec of downloaded or decoded code, `rm -rf ~` and disk wiping, download-then-execute, Windows LOLBins (certutil, mshta, regsvr32), encoded PowerShell, reverse shells.",
  check(target) {
    return target.files.flatMap((file) => checkFile(target, file));
  },
};

export default rule;

interface Segment {
  text: string;
  offset: number;
}

function segments(file: ParsedFile): Segment[] {
  if (file.type === "script" || file.type === "json") return [{ text: file.text, offset: 0 }];
  if (file.type === "markdown") {
    return (file.markdown?.codeBlocks ?? []).filter((b) => SHELLISH.has(b.lang)).map((b) => ({ text: b.content, offset: b.offset }));
  }
  return [];
}

function checkFile(target: ParsedTarget, file: ParsedFile): Finding[] {
  const segs = segments(file);
  if (segs.length === 0) return [];
  // `curl … | sh` is SW004's job; don't report the same line twice as remote code execution.
  const sw004Lines = new Set(sw004.check({ ...target, files: [file] }).map((f) => f.line));
  const findings: Finding[] = [];
  const pushAt = (offset: number, length: number, category: Category, text: string, severity: Severity, confidence: Confidence) => {
    const finding = findingAt(rule, file, { offset, length, severity, confidence, message: text });
    if ((category === "remote-eval" || category === "download-exec") && sw004Lines.has(finding.line)) return;
    if (findings.some((f) => f.line === finding.line && f.message === finding.message)) return;
    findings.push(finding);
  };

  for (const seg of segs) {
    const lines = logicalLines(seg.text);
    const at = (line: Line, index: number) => seg.offset + line.offsets[Math.min(index, line.offsets.length - 1)]!;
    /** Reports a match, judged by where it sits: a deny list, comment, warning or test string is not a command. */
    const push: Push = (line, index, length, category, label, severity, confidence) => {
      const lineStart = at(line, 0);
      const lang = languageAt(file, at(line, index));
      const before = lang === "json" ? file.text.slice(Math.max(0, lineStart - 2000), lineStart) : "";
      const where = contextSeverity(commandContext(file, lang, line.text, index, before));
      let text = message(category, label);
      if (where) {
        ({ severity, confidence } = where);
        text = `Mentions a dangerous command (${label}). ${where.note}`;
      } else if ((category === "reverse-shell" || category === "download-exec") && PLACEHOLDER_HOST.test(line.text)) {
        [severity, confidence] = ["medium", "low"];
        text += " The target is a placeholder, as in a pentest cheat sheet; it still tells the agent how to do it.";
      } else if (category === "download-exec" && isKnownInstaller(urlAfter(line.text, index))) {
        severity = "medium";
        text = `Downloads and runs the official installer of a well-known tool (${label}). The vendor's own host, but unpinned; prefer a package manager or verify a checksum.`;
      } else if (category === "download-exec" && GITHUB_RELEASE.test(line.text.slice(index))) {
        // A published release asset over HTTPS: how most CLIs are installed. Unverified, but not a dropper URL.
        severity = "medium";
        text = `Downloads a GitHub release binary and runs it (${label}) without verifying it. Pin the version and check its checksum or signature.`;
      }
      pushAt(at(line, index), length, category, text, severity, confidence);
    };

    for (const line of lines) {
      for (const { re, category, label } of PATTERNS) {
        re.lastIndex = 0;
        for (const m of execAll(re, line.text)) push(line, m.index, m[0].length, category, label, "high", "high");
      }
      const dl = DOWNLOAD_THEN_RUN.exec(line.text);
      if (dl) {
        const verified = VERIFY.test(line.text);
        push(line, dl.index, dl[0].length, "download-exec", "download then execute", verified ? "medium" : "high", verified ? "low" : "high");
      }
    }

    checkTaintedEval(lines, push);
    checkDownloadThenRunLater(lines, push);
    checkPythonReverseShell(seg, (offset, length, category, label) =>
      pushAt(offset, length, category, message(category, label), PLACEHOLDER_HOST.test(seg.text) ? "medium" : "high", PLACEHOLDER_HOST.test(seg.text) ? "low" : "high"),
    );
  }
  return findings;
}

type Line = ReturnType<typeof logicalLines>[number];
type Push = (line: Line, index: number, length: number, category: Category, label: string, severity: Severity, confidence: Confidence) => void;

const GITHUB_RELEASE = /https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/(?:latest\/)?download\//i;

/** Pentest cheat-sheet placeholders instead of a real attacker host. TEST-NET (203.0.113.x) is not one: fixtures use it. */
const PLACEHOLDER_HOST = /\b(?:ATTACKER[\w-]*|LHOST|LPORT|YOUR[_-]?(?:IP|HOST|SERVER|DOMAIN)|ATTACK(?:ER)?_?IP|KALI[_-]?IP)\b|<(?:ip|host|attacker|lhost|your[^>]*)>|\b(?:attacker|evil|malicious)(?:[._-]\w+)*\.(?:com|net|org|example|io)\b|\bx\.x\.x\.x\b|\b10\.10\.(?:10|14|16)\.\d{1,3}\b/i;

const ASSIGNMENT = /(?:^|[\s;(])(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^=\n][^\n]{0,400})/;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `code = requests.get(url).text` … `exec(code)` */
/** Cheap prefilter for the eval-of-tainted-variable check. */
const EVAL_LIKE = /\b(?:exec|eval|Function|runIn\w*Context)\s*\(/;

function checkTaintedEval(lines: Line[], push: Push): void {
  const tainted = new Set<string>();
  const assign = new RegExp(String.raw`(?:^|[\s;(])(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[^=\n][^\n]{0,400}?${FETCH_OR_DECODE}`);
  // Regexes over all tainted names, rebuilt only when the set grows: big bundled scripts taint hundreds of
  // names, and compiling one regex per name per line made this quadratic.
  let use: RegExp | undefined;
  let mention: RegExp | undefined;
  const taint = (name: string) => {
    if (tainted.has(name)) return;
    tainted.add(name);
    const names = [...tainted].map(escapeRe).join("|");
    use = new RegExp(String.raw`(?<![\w$.])(?:exec|eval|new\s+Function|vm\.runIn\w*Context)\s*\(\s*(?:compile\s*\(\s*)?(?:${names})(?![\w$])`, "g");
    mention = new RegExp(String.raw`(?<![\w$])(?:${names})(?![\w$])`);
  };
  for (const line of lines) {
    if (use && EVAL_LIKE.test(line.text)) {
      use.lastIndex = 0;
      for (const u of execAll(use, line.text)) push(line, u.index, u[0].length, "remote-eval", "eval/exec of downloaded or decoded code", "high", "high");
    }
    const m = assign.exec(line.text);
    if (m) taint(m[1]!);
    // Propagate: `text = await res.text()` where `res` came from fetch.
    const derived = mention && ASSIGNMENT.exec(line.text);
    if (derived && mention!.test(derived[2]!)) taint(derived[1]!);
  }
}

/** Download to a file on one line, run that file a few lines later (without verifying it). */
function checkDownloadThenRunLater(lines: Line[], push: Push): void {
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k]!;
    if (!DOWNLOAD_TOOL.test(line.text) || !/\bhttps?:\/\//i.test(line.text)) continue;
    const file = downloadedFile(line.text);
    if (!file) continue;
    const base = file.split(/[\\/]/).pop()!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (!base) continue;
    const run = new RegExp(
      String.raw`(?:^|&&|;|\|\|?)\s*(?:sudo\s+)?(?:chmod\s+(?:[ugoa]*\+x|[0-7]{3,4})\s+|(?:ba|z|da)?sh\s+|Start-Process\s+(?:-FilePath\s+)?|&\s*|\.\s+)?["']?(?:[\w./\\~$-]*[\\/])?${base}["']?(?=$|[\s;&|)])`,
      "i",
    );
    for (let j = k + 1; j < Math.min(lines.length, k + 20); j++) {
      const later = lines[j]!.text;
      if (VERIFY.test(later)) break;
      if (run.test(later)) {
        push(line, 0, line.text.length, "download-exec", "download then execute", "high", "medium");
        break;
      }
    }
  }
}

function downloadedFile(text: string): string | undefined {
  const explicit = OUTPUT_FILE.exec(text);
  if (explicit && explicit[1] !== "-") return explicit[1];
  // curl -O / wget without -O keep the remote file name.
  if (/\bcurl\b[^\n]{0,400}\s-[a-zA-Z]*O\b/.test(text) || (/\bwget\b/.test(text) && !/\s-O\b/.test(text))) {
    const url = /\bhttps?:\/\/[^\s"'?#]+/i.exec(text)?.[0];
    const name = url?.split("/").pop();
    return name || undefined;
  }
  return undefined;
}

/** Multi-line Python reverse shell: socket + connect + dup2 + a shell. */
function checkPythonReverseShell(seg: Segment, push: (offset: number, length: number, category: Category, label: string) => void): void {
  const t = seg.text;
  if (!/\bsocket\.socket\s*\(/.test(t) || !/\.connect\s*\(/.test(t)) return;
  const dup2 = /\bdup2\s*\(/.exec(t);
  if (!dup2 || !/subprocess|pty\.spawn|\/bin\/(?:ba)?sh/.test(t)) return;
  push(seg.offset + dup2.index, dup2[0].length, "reverse-shell", "Python socket + dup2 shell");
}

function message(category: Category, label: string): string {
  switch (category) {
    case "remote-eval":
      return `Runs code that is downloaded or decoded at run time (${label}). It can't be reviewed and can change at any time. Ship the code in the skill instead.`;
    case "destructive":
      return `Destructive command (${label}) can wipe the home directory or the disk. Remove it.`;
    case "download-exec":
      return `Downloads a program and runs it (${label}). The binary is unreviewed and can change. Vendor it, or pin and verify a checksum.`;
    case "lolbin":
      return `Uses a Windows system tool to fetch or run remote code (${label}) — a common malware technique. Remove it.`;
    case "encoded":
      return `Runs ${label}, which hides what it does from review. Use the plain script.`;
    case "reverse-shell":
      return `Opens a reverse shell (${label}), giving a remote host control of this machine. Remove it.`;
  }
}
