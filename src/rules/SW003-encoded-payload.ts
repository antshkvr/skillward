import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { escapeInvisible, lineText, locate, logicalLines, makeSnippet, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { vocab } from "./vocabulary.js";

/** Decoded text that looks like something to execute or contact. */
const INDICATORS =
  new RegExp(
    String.raw`\b(?:curl|wget|bash|zsh|sh\s+-c|powershell|pwsh|${vocab("psEval", "psFetch")}|eval|exec|nc\s+-e|ncat|netcat|rm\s+-rf|base64\s+-d|chmod\s+\+x|subprocess|os\.system|child_process)\b|https?:\/\/|\/dev\/tcp|\|\s*(?:ba)?sh\b`,
    "i",
  );

/** Contexts where long encoded strings are expected and harmless. */
const CHECKSUM_CONTEXT = /\b(?:checksum|sha1|sha224|sha256|sha384|sha512|md5|hash|digest|fingerprint|integrity|etag|commit|revision|nonce|salt)\b/i;
const DATA_URI_BEFORE = /data:(?:image|font|audio|video)\/[\w.+-]+(?:;[\w=-]+)*;base64,$/i;
const SRI_BEFORE = /(?:sha(?:256|384|512)-)$/i;

const BASE64 = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=_-])/g;
const BASE64URL = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_-]{60,}(?![A-Za-z0-9+/=_-])/g;
const HEX = /(?<![0-9A-Za-z])[0-9a-fA-F]{128,}(?![0-9A-Za-z])/g;
const HEX_ESCAPES = /(?:\\x[0-9a-fA-F]{2}){20,}/g;
const JWT = /(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w-])/g;
const PEM = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?(?:-----END \1-----|$)/g;
/** Placeholder bodies in docs: `...`, `…`, `<your key here>`, `YOUR_PRIVATE_KEY`, `REDACTED`. */
const PEM_PLACEHOLDER = /\.\.\.|…|<[^>\n]*>|\b(?:your|redacted|placeholder|example|replace|contents?|insert|paste)\b|x{4,}/i;
/** jwt.io's sample token (`"sub":"1234567890","name":"John Doe"`) is in every JWT tutorial. */
const SAMPLE_JWT_PAYLOAD = /"sub"\s*:\s*"1234567890"|"name"\s*:\s*"John Doe"/;
/** Signatures, lockfiles and transcripts carry binary base64 by design. */
/** How far around a blob its line is read for context (data URI prefix, checksum words, URL). */
const CONTEXT_CHARS = 300;
const BINARY_DATA_FILE = /\.(?:jsonl|ndjson|sig|asc|lock|har|ipynb)$/i;
/** Saved e-mails: MIME bodies and attachments are base64 by design. */
const MAIL_FILE = /\.(?:eml|mbox|msg)$/i;
/** Decoded HTML (an e-mail body, a page) without script: links in it are not commands. */
const PLAIN_MARKUP = /^\s*<(?:!doctype|html|head|meta|body|div|p|table|span|style|title)\b/i;
const ACTIVE_MARKUP = /<script\b|javascript:|\bon[a-z]+\s*=/i;
/** A base64 line inside a wrapped block (76-column MIME style). */
const WRAPPED_LINE = /^\s*["']?([A-Za-z0-9+/]{40,}={0,2})["',]?\s*$/;

/** Decode-and-execute pipelines; reported regardless of blob length. */
const DECODE_TO_SHELL =
  /\bbase64\s+(?:-d|-D|--decode)\b[^|\n]*\|\s*(?:sudo\s+)?(?:(?:ba|da|z|k)?sh|python[\d.]*|perl|node)\b/gi;
const DECODE_EXEC =
  /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|atob|Buffer\.from)\s*\(|\bpython[\d.]*\s+-c\s+["'][^"'\n]*\bb64decode\b[^"'\n]*\bexec\b/gi;
const POWERSHELL_ENC =
  /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,400}?\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["']?([A-Za-z0-9+/]{8,}={0,2})/gi;

const rule: Rule = {
  id: "SW003",
  name: "encoded-payload",
  // Raised to high per finding when the blob decodes to commands/URLs (see SPEC).
  severity: "medium",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Long base64/hex blobs, decode-and-execute pipelines and embedded private keys. Encoded content hides what the agent will run from reviewers; it is high severity when it decodes to commands or URLs.",
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
  /** Replace the blob in the snippet so secrets are never printed in full. */
  redact?: boolean;
}

function checkFile(file: ParsedFile): Finding[] {
  const text = file.text;
  const hits: Hit[] = [];
  const taken = (start: number, end: number) => hits.some((h) => start < h.end && end > h.start);
  const add = (hit: Hit) => {
    if (!taken(hit.start, hit.end)) hits.push(hit);
  };

  // PEM blocks: private keys are reported, certificates and public keys are expected content.
  const masked: Array<[number, number]> = [];
  for (const m of execAll(PEM, text)) {
    masked.push([m.index, m.index + m[0].length]);
    if (/PRIVATE KEY/.test(m[1]!)) {
      const header = `-----BEGIN ${m[1]}-----`;
      const closed = m[0].endsWith(`-----END ${m[1]}-----`);
      const body = closed ? m[0].slice(header.length, -`-----END ${m[1]}-----`.length) : "";
      // Detector patterns and docs quote the header alone (`"-----BEGIN RSA PRIVATE KEY-----"` in a rule table) or
      // show a placeholder body (`...`, `<your key>`): no key material.
      const material = closed && !PEM_PLACEHOLDER.test(body) && body.replace(/\\n|[\s"'`,+]/g, "").length >= 8;
      add({
        start: m.index,
        end: m.index + header.length,
        severity: material ? "high" : "info",
        confidence: material ? "high" : "low",
        message: material
          ? "Embedded private key. Anyone who gets this file gets the key, and the agent may use or leak it. Remove it and rotate the key."
          : "Private key header without key material (a placeholder or a detection pattern). Listed for inventory.",
      });
    }
  }
  const isMasked = (i: number) => masked.some(([s, e]) => i >= s && i < e);

  // Decode-and-execute pipelines.
  for (const line of logicalLines(text)) {
    for (const m of execAll(POWERSHELL_ENC, line.text)) {
      const decoded = decodeUtf16(m[1]!);
      const start = line.offsets[m.index]!;
      const end = line.offsets[m.index + m[0].length - 1]! + 1;
      add({
        start,
        end,
        severity: "high",
        confidence: "high",
        message:
          "PowerShell -EncodedCommand runs a base64-hidden script" +
          (decoded ? `: "${preview(decoded)}"` : "") +
          ". Reviewers can't see what it does. Replace it with the plain command.",
        redact: true,
      });
    }
    for (const re of [DECODE_TO_SHELL, DECODE_EXEC]) {
      for (const m of execAll(re, line.text)) {
        add({
          start: line.offsets[m.index]!,
          end: line.offsets[m.index + m[0].length - 1]! + 1,
          severity: "high",
          confidence: "high",
          message:
            "Decodes hidden content and executes it. Reviewers can't see what runs. Replace it with the plain command or code.",
        });
      }
    }
  }

  // JWTs: credentials, not code — report without decoding into the message.
  for (const m of execAll(JWT, text)) {
    if (isMasked(m.index)) continue;
    const payload = asText(Buffer.from(m[0].split(".")[1]!, "base64url"));
    const sample = payload !== undefined && SAMPLE_JWT_PAYLOAD.test(payload);
    add({
      start: m.index,
      end: m.index + m[0].length,
      severity: sample ? "info" : "medium",
      confidence: sample ? "low" : "medium",
      message: sample
        ? "The jwt.io sample token (a tutorial example, not a credential). Listed for inventory."
        : "Embedded JWT token. Tokens in instructions leak to anyone with the file and to every tool the agent calls. Remove it.",
      redact: true,
    });
  }

  const candidates: Array<{ start: number; end: number; blob: string; encoding: "base64" | "hex" | "hexEscapes" }> = [];
  for (const m of execAll(BASE64, text)) candidates.push({ start: m.index, end: m.index + m[0].length, blob: m[0], encoding: "base64" });
  for (const m of execAll(BASE64URL, text)) {
    if (!/[_-]/.test(m[0])) continue; // plain base64 already covered
    candidates.push({ start: m.index, end: m.index + m[0].length, blob: m[0].replace(/-/g, "+").replace(/_/g, "/"), encoding: "base64" });
  }
  candidates.push(...wrappedBlocks(file));
  for (const m of execAll(HEX, text)) candidates.push({ start: m.index, end: m.index + m[0].length, blob: m[0], encoding: "hex" });
  for (const m of execAll(HEX_ESCAPES, text)) {
    candidates.push({ start: m.index, end: m.index + m[0].length, blob: m[0].replace(/\\x/g, ""), encoding: "hexEscapes" });
  }
  candidates.sort((a, b) => a.start - b.start || b.end - a.end);

  for (const c of candidates) {
    if (isMasked(c.start) || taken(c.start, c.end)) continue;
    const { line } = locate(file.lineStarts, c.start);
    // Context is a window around the blob, not the whole line: minified JSON can be one 1 MB line with
    // thousands of candidates, and re-testing the full line for each one is quadratic.
    const lineStart = Math.max(file.lineStarts[line - 1]!, c.start - CONTEXT_CHARS);
    const lineEnd = file.lineStarts[line] ?? text.length;
    const lineStr = text.slice(lineStart, Math.min(lineEnd, c.end + CONTEXT_CHARS));
    const before = text.slice(lineStart, c.start);
    if (DATA_URI_BEFORE.test(before) || SRI_BEFORE.test(before)) continue;
    if (CHECKSUM_CONTEXT.test(lineStr) && c.encoding !== "hexEscapes") continue;
    // Part of a URL path or query (long tokens in links): SW007 looks at destinations.
    if (/(?:https?|ftp):\/\/\S*$/i.test(before)) continue;
    if (c.encoding === "base64" && !looksLikeBase64(c.blob)) continue;
    if (c.encoding === "hex" && (!/[0-9]/.test(c.blob) || !/[a-f]/i.test(c.blob))) continue;

    const bytes = c.encoding === "base64" ? Buffer.from(c.blob, "base64") : Buffer.from(c.blob, "hex");
    const kind = c.encoding === "base64" ? "Base64" : "Hex";
    const decoded = asText(bytes);
    let hit: Omit<Hit, "start" | "end">;
    if (MAIL_FILE.test(file.path)) {
      hit = { severity: "info", confidence: "low", message: `${kind} content in a saved e-mail (MIME encoding). Listed for inventory.` };
    } else if (decoded !== undefined && PLAIN_MARKUP.test(decoded) && !ACTIVE_MARKUP.test(decoded)) {
      hit = {
        severity: "low",
        confidence: "low",
        message: `${kind}-encoded HTML (${bytes.length} bytes) without scripts. Prefer plain text so reviewers can read it.`,
      };
    } else if (decoded !== undefined && INDICATORS.test(decoded)) {
      hit = {
        severity: "high",
        confidence: "high",
        message: `${kind} blob decodes to commands: "${preview(decoded)}". Encoding hides what the agent will run from reviewers. Replace it with plain text or remove it.`,
      };
    } else if (decoded !== undefined) {
      hit = {
        severity: "medium",
        confidence: "medium",
        message: `${kind}-encoded text (${bytes.length} bytes). Encoded instructions can't be reviewed. Replace it with plain text unless it is data the skill really needs.`,
      };
    } else {
      // Keys, hashes, nonces and signatures are under 100 bytes; data files carry binary base64 by design.
      const routine = bytes.length < 100 || file.type === "json" || BINARY_DATA_FILE.test(file.path);
      hit = {
        severity: routine ? "low" : "medium",
        confidence: "low",
        message: `${kind}-encoded binary blob (${bytes.length} bytes). It could hide a payload or a secret. Ship it as a reviewed file or remove it.`,
      };
    }
    add({ start: c.start, end: c.end, ...hit, redact: true });
  }

  return hits
    .sort((a, b) => a.start - b.start)
    .map((h) => {
      const finding = findingAt(rule, file, {
        offset: h.start,
        length: h.end - h.start,
        message: h.message,
        confidence: h.confidence,
        severity: h.severity,
      });
      return h.redact ? { ...finding, snippet: redactedSnippet(file, h.start, h.end) } : finding;
    });
}

/** Consecutive lines that are entirely base64 (wrapped blocks), joined into one candidate. */
function wrappedBlocks(file: ParsedFile) {
  const blocks: Array<{ start: number; end: number; blob: string; encoding: "base64" }> = [];
  let current: { start: number; end: number; parts: string[] } | undefined;
  for (let i = 0; i < file.lineStarts.length; i++) {
    const m = WRAPPED_LINE.exec(lineText(file.text, file.lineStarts, i + 1));
    if (m) {
      const start = file.lineStarts[i]! + m.index + m[0].indexOf(m[1]!);
      if (!current) current = { start, end: start + m[1]!.length, parts: [] };
      current.parts.push(m[1]!);
      current.end = start + m[1]!.length;
      if (!m[1]!.endsWith("=")) continue;
    }
    if (current && current.parts.length > 1) {
      blocks.push({ start: current.start, end: current.end, blob: current.parts.join(""), encoding: "base64" });
    }
    current = undefined;
  }
  if (current && current.parts.length > 1) {
    blocks.push({ start: current.start, end: current.end, blob: current.parts.join(""), encoding: "base64" });
  }
  return blocks;
}

/** Real base64 data mixes cases and digits and has high entropy; identifiers and words don't. */
function looksLikeBase64(blob: string): boolean {
  const body = blob.replace(/=+$/, "");
  if (!/[A-Z]/.test(body) || !/[a-z]/.test(body) || !/[0-9]/.test(body)) return false;
  if (body.length % 4 === 1) return false;
  return entropy(body) >= 4.5;
}

function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Decoded bytes as text if they are (almost) all printable ASCII/UTF-8, otherwise undefined. */
function asText(bytes: Buffer): string | undefined {
  if (bytes.length === 0) return undefined;
  const text = bytes.toString("utf8");
  if (text.includes("\uFFFD")) return undefined;
  let printable = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp === 9 || cp === 10 || cp === 13 || (cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp < 0xa0))) printable++;
  }
  return printable / [...text].length >= 0.95 ? text : undefined;
}

function decodeUtf16(b64: string): string | undefined {
  const bytes = Buffer.from(b64, "base64");
  const text = bytes.toString("utf16le");
  return asText(Buffer.from(text, "utf8"));
}

function preview(decoded: string): string {
  const flat = decoded.replace(/\s+/g, " ").trim();
  return escapeInvisible(flat.length > 60 ? flat.slice(0, 60) + "…" : flat);
}

/** Snippet with the blob shortened to its first characters, so secrets are never printed in full. */
function redactedSnippet(file: ParsedFile, start: number, end: number): string {
  const { line, column } = locate(file.lineStarts, start);
  const text = lineText(file.text, file.lineStarts, line);
  const from = column - 1;
  const to = Math.min(text.length, from + (end - start));
  const blob = text.slice(from, to);
  if (blob.length <= 24) return makeSnippet(text, from, to);
  const short = `${blob.slice(0, 12)}…[${end - start} chars]`;
  const redacted = text.slice(0, from) + short + text.slice(to);
  return makeSnippet(redacted, from, from + short.length);
}
