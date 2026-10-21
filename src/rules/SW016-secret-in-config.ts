import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { execAll, lineText, locate, makeSnippet } from "../text.js";
import { findingAt } from "./helpers.js";

/**
 * Credentials written into agent configuration: provider tokens (exact formats, high) and secret-looking values
 * assigned to secret-named keys (heuristic, medium). Claude Code's `settings.local.json` is a common source: allowed
 * commands are saved verbatim, tokens included. SW003 covers private keys and JWTs; SW005 covers paths to secret files.
 */
interface TokenPattern {
  re: RegExp;
  label: string;
}

const token = (source: string) => new RegExp(String.raw`(?<![A-Za-z0-9_-])(?:${source})(?![A-Za-z0-9_-])`, "g");

const PROVIDER_TOKENS: TokenPattern[] = [
  { re: token(String.raw`(?:AKIA|ASIA)[0-9A-Z]{16}`), label: "an AWS access key ID" },
  { re: token(String.raw`gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}`), label: "a GitHub token" },
  { re: token(String.raw`glpat-[A-Za-z0-9_-]{20,}`), label: "a GitLab token" },
  { re: token(String.raw`xox[abposr]-[A-Za-z0-9-]{10,}`), label: "a Slack token" },
  { re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Z0-9]{8,}\/[A-Za-z0-9]{8,}\/[A-Za-z0-9]{16,}/g, label: "a Slack webhook URL" },
  { re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{40,}/g, label: "a Discord webhook URL" },
  { re: token(String.raw`sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}`), label: "an Anthropic API key" },
  { re: token(String.raw`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), label: "an OpenAI API key" },
  { re: token(String.raw`(?:sk|rk)_live_[0-9A-Za-z]{24,}`), label: "a Stripe live key" },
  { re: token(String.raw`AIza[0-9A-Za-z_-]{35}`), label: "a Google API key" },
  { re: token(String.raw`npm_[A-Za-z0-9]{36}`), label: "an npm token" },
  { re: token(String.raw`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`), label: "a PyPI token" },
  { re: token(String.raw`hf_[A-Za-z0-9]{34,}`), label: "a Hugging Face token" },
  { re: token(String.raw`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), label: "a SendGrid API key" },
  { re: token(String.raw`\d{8,10}:AA[A-Za-z0-9_-]{33}`), label: "a Telegram bot token" },
  { re: token(String.raw`dop_v1_[a-f0-9]{64}`), label: "a DigitalOcean token" },
  { re: token(String.raw`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`), label: "a Shopify token" },
];

/** `api_key = "…"`, `"OPENAI_API_KEY": "…"`, `--token …`, `Authorization: Bearer …`. */
// Anchored at the start of an identifier and bounded: an unbounded `[\w-]*` before the keyword made matching
// quadratic on minified one-line bundles (a 1 MB identifier-like run).
const SECRET_WORD = String.raw`[A-Za-z0-9_-]{0,40}?(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|access[_-]?key|auth[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_-]{0,40}`;
const SECRET_NAME = String.raw`(?<![A-Za-z0-9_-])${SECRET_WORD}`;
const ASSIGNMENTS = [
  new RegExp(String.raw`["']?(${SECRET_NAME})["']?\s*[:=]\s*["']([^"'\s$\{\}<>]{16,})["']`, "gi"),
  // Unquoted (`KEY=value` in shell and .env): token characters only, so minified code (`a.token=0,b…`) doesn't match.
  new RegExp(String.raw`(?<![\w.-])(${SECRET_NAME})=([A-Za-z0-9_.~+/=:-]{16,})(?![^\s"'&;|)])`, "gi"),
  new RegExp(String.raw`(?<![A-Za-z0-9_-])--(${SECRET_WORD})(?:=|\s+)["']?([^\s"'$\{\}<>]{16,})`, "gi"),
  /\b(Authorization:\s*(?:Bearer|token|Basic))\s+([A-Za-z0-9._~+/=-]{20,})/gi,
];

/** Values that are obviously not real: placeholders, variables, repeated characters, docs examples. */
const PLACEHOLDER =
  /fake|example|sample|dummy|placeholder|redacted|changeme|change[_-]?me|your[_-]?|my[_-]?(?:api|secret|token)|xxxx|\*{3}|\.{3}|<|>|test[_-]?(?:key|token|secret)|insert|replace|todo|null|undefined|none|^(?:true|false)$/i;
/** Typed-by-hand filler: sequences and repeats ("sk-1234567890abcdef", "xoxb-0000…"). */
const SEQUENTIAL = /0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|wxyz|qwer|asdf|(.)\1{3,}/i;
/** Words people put in example secrets. */
const EXAMPLE_WORDS = /secret|secure|passw|admin|demo|hardcod|default|local|mysecret|letmein|super|strong|abc12|pass12/i;
/** \`tokenAddress\`, \`max_tokens\`, \`tokenizer\`, \`api_key_env\`: names that hold something else than a secret. */
const NOT_A_SECRET_NAME = /(?:token|key|secret)s?[_-]?(?:address|addr|id|ids|symbol|name|type|count|limit|url|uri|endpoint|path|file|usage|izer|ize|length|budget|expir\w*|env|var|header|field|prefix|format|hash|mint|program|decimals)$|^max[_-]?tokens?$|^tokens$|^hashed|tokeniz/i;
/** Test code and fixtures of the scanned repository hold fake tokens on purpose. */
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|test-fixtures)\/|\.(?:test|spec)\.[a-z]+$|(?:^|\/)test_[^/]+\.py$|_test\.(?:go|py)$/i;

/** AWS documentation keys. */
const DOC_KEYS = new Set(["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"]);

/** Bits per character; real secrets are random. */
function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Looks like a generated secret rather than a word, a path, a hostname or an identifier. */
function looksRandom(value: string): boolean {
  if (PLACEHOLDER.test(value) || SEQUENTIAL.test(value) || EXAMPLE_WORDS.test(value)) return false;
  if (/^0x[0-9a-f]{40,64}$/i.test(value) || value.startsWith("eyJ")) return false; // chain addresses; JWTs are SW003's
  if (/^[a-z]+(?:[_-][a-z]+)*$/i.test(value)) return false; // words, snake/kebab identifiers
  if (/[/\\]/.test(value) && !/^[A-Za-z0-9+/=]+$/.test(value)) return false; // paths
  if (/^(?:\d+|[a-f0-9]{7,40})$/.test(value) && !/[a-f]/.test(value)) return false; // plain numbers
  if (!/\d/.test(value) || !/[A-Za-z]/.test(value)) return false;
  return entropy(value) >= 3.5;
}

const rule: Rule = {
  id: "SW016",
  name: "secret-in-config",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Credentials written into agent configuration: provider tokens (AWS, GitHub, Slack, OpenAI, Anthropic, Stripe, …), webhook URLs with tokens, and secret-looking values assigned to secret-named keys. Common in settings.local.json, where allowed commands are saved verbatim.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

interface Hit {
  start: number;
  end: number;
  label: string;
  severity: Severity;
  confidence: Confidence;
  test?: boolean;
}

function checkFile(file: ParsedFile): Finding[] {
  const text = file.text;
  const inTest = TEST_PATH.test(file.path);
  const hits: Hit[] = [];
  const overlaps = (s: number, e: number) => hits.some((h) => s < h.end && e > h.start);

  for (const { re, label } of PROVIDER_TOKENS) {
    re.lastIndex = 0;
    for (const m of execAll(re, text)) {
      const value = m[0];
      if (DOC_KEYS.has(value) || PLACEHOLDER.test(value) || SEQUENTIAL.test(value) || entropy(value) < 3) continue;
      if (overlaps(m.index, m.index + value.length)) continue;
      // Secret scanners' own tests are full of fake tokens.
      if (inTest) hits.push({ start: m.index, end: m.index + value.length, label, severity: "low", confidence: "low", test: true });
      else hits.push({ start: m.index, end: m.index + value.length, label, severity: "high", confidence: "high" });
    }
  }

  for (const re of ASSIGNMENTS) {
    re.lastIndex = 0;
    for (const m of execAll(re, text)) {
      const name = m[1]!;
      const value = m[2]!;
      const start = m.index + m[0].lastIndexOf(value);
      const end = start + value.length;
      if (inTest || overlaps(start, end) || !looksRandom(value) || NOT_A_SECRET_NAME.test(name)) continue;
      // `?alt=media&token=…` in a link: a download token in a URL, not a configured credential.
      if (/(?:[?&]|&amp;|&#x26;|&#38;)$/i.test(text.slice(Math.max(0, m.index - 6), m.index + (m[0].startsWith('"') || m[0].startsWith("'") ? 1 : 0)))) continue;
      // Real configuration (JSON configs, .env-style files, scripts) vs. examples in documentation.
      const config = file.type === "json" || file.type === "script" || /(?:^|\/)\.env[\w.-]*$/.test(file.path);
      hits.push({ start, end, label: `a secret-looking value for "${name}"`, severity: config ? "medium" : "low", confidence: config ? "medium" : "low" });
    }
  }

  return hits
    .sort((a, b) => a.start - b.start)
    .map((h) => {
      const finding = findingAt(rule, file, {
        offset: h.start,
        length: h.end - h.start,
        severity: h.severity,
        confidence: h.confidence,
        message: h.test
          ? `Contains what looks like ${h.label} in a test file. Usually a fake token for tests; make sure it isn't a real one.`
          : h.severity === "high"
            ? `Contains ${h.label}. Anyone who can read this file — and every tool the agent calls — can use it. Revoke it at the provider, then remove it from the file and its history.`
            : `Contains ${h.label}. If it is a real credential, revoke it and load it from the environment instead.`,
      });
      return { ...finding, snippet: redactedSnippet(file, h.start, h.end) };
    });
}

/** The line with the secret replaced by its first 4 characters and its length — never the full value. */
function redactedSnippet(file: ParsedFile, start: number, end: number): string {
  const { line, column } = locate(file.lineStarts, start);
  const text = lineText(file.text, file.lineStarts, line);
  const from = column - 1;
  const to = Math.min(text.length, from + (end - start));
  const short = `${text.slice(from, from + 4)}…[${end - start} chars]`;
  const redacted = text.slice(0, from) + short + text.slice(to);
  return makeSnippet(redacted, from, from + short.length);
}

const JWT = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const KEY_BEGIN = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/g;
const KEY_END = /-----END [A-Z ]{0,40}PRIVATE KEY-----/g;

/** Private key blocks, BEGIN to END (or to the end of the text). One forward pass: linear even with many headers. */
function privateKeySpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let from = 0;
  for (const begin of execAll(KEY_BEGIN, text)) {
    if (begin.index < from) continue; // inside the previous block
    KEY_END.lastIndex = begin.index + begin[0].length;
    const end = KEY_END.exec(text);
    KEY_END.lastIndex = 0;
    from = end ? end.index + end[0].length : text.length;
    spans.push([begin.index, from]);
    if (!end) break;
  }
  return spans;
}

/**
 * Masks credentials in arbitrary text, keeping the first 4 characters and the length (`ghp_…[40 chars]`). Used where
 * skillward shows file content that isn't a finding: `verify` diffs and the snapshots they are made from. Errs on the
 * side of masking: no placeholder or test-path exceptions for provider tokens.
 */
export function redactSecrets(text: string): string {
  const spans: Array<[number, number]> = [];
  for (const { re } of PROVIDER_TOKENS) {
    for (const m of execAll(re, text)) spans.push([m.index, m.index + m[0].length]);
  }
  for (const re of ASSIGNMENTS) {
    for (const m of execAll(re, text)) {
      const value = m[2]!;
      if (!looksRandom(value) || NOT_A_SECRET_NAME.test(m[1]!)) continue;
      const start = m.index + m[0].lastIndexOf(value);
      spans.push([start, start + value.length]);
    }
  }
  for (const m of execAll(JWT, text)) spans.push([m.index, m.index + m[0].length]);
  spans.push(...privateKeySpans(text));
  if (!spans.length) return text;

  // Overlapping matches (a token inside an assignment, a key inside a block) are masked as one.
  spans.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const [start, end] of spans) {
    const last = merged.at(-1);
    if (last && start < last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  let out = "";
  let pos = 0;
  for (const [start, end] of merged) {
    const value = text.slice(start, end);
    const mask = value.startsWith("-----BEGIN") ? `-----BEGIN PRIVATE KEY-----…[${value.length} chars]` : `${value.slice(0, 4)}…[${value.length} chars]`;
    out += text.slice(pos, start) + mask;
    pos = end;
  }
  return out + text.slice(pos);
}
