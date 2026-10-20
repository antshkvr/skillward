import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { escapeInvisible } from "../text.js";
import { findingAt } from "./helpers.js";

type Category = "tag" | "bidi-control" | "bidi-mark" | "variation-selector" | "zero-width";

const NAMES: Record<number, string> = {
  0x061c: "ARABIC LETTER MARK",
  0x115f: "HANGUL CHOSEONG FILLER",
  0x1160: "HANGUL JUNGSEONG FILLER",
  0x17b4: "KHMER VOWEL INHERENT AQ",
  0x17b5: "KHMER VOWEL INHERENT AA",
  0x180e: "MONGOLIAN VOWEL SEPARATOR",
  0x200b: "ZERO WIDTH SPACE",
  0x200c: "ZERO WIDTH NON-JOINER",
  0x200d: "ZERO WIDTH JOINER",
  0x200e: "LEFT-TO-RIGHT MARK",
  0x200f: "RIGHT-TO-LEFT MARK",
  0x202a: "LEFT-TO-RIGHT EMBEDDING",
  0x202b: "RIGHT-TO-LEFT EMBEDDING",
  0x202c: "POP DIRECTIONAL FORMATTING",
  0x202d: "LEFT-TO-RIGHT OVERRIDE",
  0x202e: "RIGHT-TO-LEFT OVERRIDE",
  0x2060: "WORD JOINER",
  0x2061: "FUNCTION APPLICATION",
  0x2062: "INVISIBLE TIMES",
  0x2063: "INVISIBLE SEPARATOR",
  0x2064: "INVISIBLE PLUS",
  0x2066: "LEFT-TO-RIGHT ISOLATE",
  0x2067: "RIGHT-TO-LEFT ISOLATE",
  0x2068: "FIRST STRONG ISOLATE",
  0x2069: "POP DIRECTIONAL ISOLATE",
  0x3164: "HANGUL FILLER",
  0xfeff: "ZERO WIDTH NO-BREAK SPACE",
  0xffa0: "HALFWIDTH HANGUL FILLER",
};

function categorize(cp: number): Category | undefined {
  if (cp >= 0xe0000 && cp <= 0xe007f) return "tag";
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return "bidi-control";
  if (cp === 0x200e || cp === 0x200f || cp === 0x061c) return "bidi-mark";
  if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) return "variation-selector";
  if (
    (cp >= 0x200b && cp <= 0x200d) ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0x206a && cp <= 0x206f) ||
    (cp >= 0xfff9 && cp <= 0xfffb) ||
    [0xfeff, 0x180e, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x3164, 0xffa0].includes(cp)
  ) {
    return "zero-width";
  }
  return undefined;
}

const RTL_LETTER = /[\p{Script=Hebrew}\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}]/u;
/** Scripts where ZWJ/ZWNJ are part of normal spelling (Persian, Indic, …). */
const JOINING_SCRIPT =
  /[\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Mongolian}]/u;
const EMOJI = /[\p{Extended_Pictographic}\u{1F3FB}-\u{1F3FF}\uFE0F⃣]/u;
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;

interface Run {
  start: number;
  end: number;
  codePoints: number[];
}

const rule: Rule = {
  id: "SW001",
  name: "hidden-unicode",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Invisible Unicode: zero-width characters, bidirectional overrides, tag characters (U+E0000–E007F) and variation-selector runs. They hide text from human reviewers while the agent still reads it.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

function checkFile(file: ParsedFile): Finding[] {
  const text = file.text;
  const hasRtl = RTL_LETTER.test(text);
  const findings: Finding[] = [];

  for (const run of findRuns(text)) {
    const cps = run.codePoints;
    const prev = codePointBefore(text, run.start);
    const next = text.codePointAt(run.end);

    // Emoji subdivision flags (🏴 + tags + CANCEL TAG) are legitimate tag-character use.
    if (prev === 0x1f3f4 && cps.every((c) => c >= 0xe0020 && c <= 0xe007f) && cps.at(-1) === 0xe007f) continue;
    // ZWJ inside emoji sequences, e.g. 👩\u200D💻.
    if (cps.every((c) => c === 0x200d || c === 0xfe0f) && isChar(prev, EMOJI) && isChar(next, PICTOGRAPHIC)) continue;
    // ZWJ/ZWNJ inside words of scripts that need them.
    if (cps.every((c) => c === 0x200c || c === 0x200d) && isChar(prev, JOINING_SCRIPT) && isChar(next, JOINING_SCRIPT)) {
      continue;
    }
    // A single variation selector after a character is ordinary emoji/CJK presentation.
    const selectors = cps.filter((c) => categorize(c) === "variation-selector");
    const others = cps.filter((c) => categorize(c) !== "variation-selector");
    if (others.length === 0 && selectors.length === 1 && prev !== undefined) continue;
    // Direction marks are normal in right-to-left text.
    if (hasRtl && cps.every((c) => categorize(c) === "bidi-mark" || c === 0xfe0f)) continue;

    const verdict = assess(cps, hasRtl);
    if (file.script && insideCharacterClass(text, run.start, run.end)) {
      // `/[<U+200B>-<U+200D>]/`: a scanner or sanitizer listing the characters it strips.
      verdict.severity = "low";
      verdict.confidence = "low";
      verdict.message = `Invisible characters (${describe(cps)}) inside a character class in code — usually a detector or sanitizer. Prefer \\u escapes.`;
    }
    findings.push(
      findingAt(rule, file, {
        offset: run.start,
        length: run.end - run.start,
        message: verdict.message,
        confidence: verdict.confidence,
        severity: verdict.severity,
      }),
    );
  }
  return findings;
}

function assess(cps: number[], hasRtl: boolean): { message: string; severity: Severity; confidence: Confidence } {
  const has = (c: Category) => cps.some((cp) => categorize(cp) === c);
  const listing = describe(cps);

  if (has("tag")) {
    const decoded = cps
      .filter((c) => c >= 0xe0020 && c <= 0xe007e)
      .map((c) => String.fromCodePoint(c - 0xe0000))
      .join("");
    const shown = decoded.length > 60 ? decoded.slice(0, 60) + "…" : decoded;
    return {
      message:
        `Hidden Unicode tag characters (${cps.length}) carry invisible text` +
        (shown ? `: "${escapeInvisible(shown)}"` : "") +
        ". The agent reads it, reviewers don't see it. Remove them.",
      severity: "high",
      confidence: "high",
    };
  }
  if (has("bidi-control")) {
    return {
      message: `Bidirectional control characters (${listing}) make the text display differently from what the agent reads (Trojan Source). Remove them.`,
      severity: "high",
      confidence: hasRtl ? "medium" : "high",
    };
  }
  const selectors = cps.filter((c) => categorize(c) === "variation-selector").length;
  if (selectors > 1) {
    return {
      message: `A run of ${selectors} invisible variation selectors can smuggle hidden data (one byte per selector). Remove it.`,
      severity: "high",
      confidence: "high",
    };
  }
  if (has("bidi-mark") && !has("zero-width")) {
    return {
      message: `Invisible direction marks (${listing}) in text without right-to-left script. Remove them unless intentional.`,
      severity: "medium",
      confidence: "medium",
    };
  }
  if (cps.length === 1) {
    return {
      message: `Invisible character (${listing}), often a copy-paste artifact but also used to split keywords and evade review. Remove it.`,
      severity: "low",
      confidence: "medium",
    };
  }
  return {
    message: `Run of ${cps.length} invisible characters (${listing}) can hide or encode text. Remove them.`,
    // Two or three zero-width spaces are a common translation/copy-paste artifact; encoding needs longer runs.
    severity: cps.length >= 4 ? "high" : "medium",
    confidence: cps.length >= 8 ? "high" : cps.length >= 4 ? "medium" : "low",
  };
}

/** The run sits between `[` and `]` on its line, as in a regex character class. */
function insideCharacterClass(text: string, start: number, end: number): boolean {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const lineEnd = text.indexOf("\n", end);
  const before = text.slice(lineStart, start);
  const after = text.slice(end, lineEnd === -1 ? text.length : lineEnd);
  return before.lastIndexOf("[") > before.lastIndexOf("]") && after.includes("]");
}

function findRuns(text: string): Run[] {
  const runs: Run[] = [];
  let current: Run | undefined;
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i)!;
    const width = cp > 0xffff ? 2 : 1;
    if (categorize(cp)) {
      if (current && current.end === i) {
        current.end = i + width;
        current.codePoints.push(cp);
      } else {
        current = { start: i, end: i + width, codePoints: [cp] };
        runs.push(current);
      }
    }
    i += width;
  }
  return runs;
}

function codePointBefore(text: string, index: number): number | undefined {
  if (index === 0) return undefined;
  const low = text.charCodeAt(index - 1);
  if (low >= 0xdc00 && low <= 0xdfff && index >= 2) return text.codePointAt(index - 2);
  return low;
}

function isChar(cp: number | undefined, re: RegExp): boolean {
  return cp !== undefined && re.test(String.fromCodePoint(cp));
}

function describe(cps: number[]): string {
  const counts = new Map<number, number>();
  for (const cp of cps) counts.set(cp, (counts.get(cp) ?? 0) + 1);
  const parts = [...counts].map(([cp, n]) => {
    const hex = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
    const name = NAMES[cp];
    return (name ? `${hex} ${name}` : hex) + (n > 1 ? ` ×${n}` : "");
  });
  return parts.length > 3 ? parts.slice(0, 3).join(", ") + ", …" : parts.join(", ");
}
