/**
 * Helpers for phrase-based heuristic rules (EN + RU). JS `\b` does not understand Cyrillic,
 * so boundaries are built from Unicode letter/number classes.
 */
import type { Confidence, Severity } from "../types.js";
import { execAll } from "../text.js";

/** Not preceded by a letter, digit or underscore. */
export const B = String.raw`(?<![\p{L}\p{N}_])`;
/** Not followed by a letter, digit or underscore. */
export const E = String.raw`(?![\p{L}\p{N}_])`;
/** Apostrophe in contractions: ASCII or typographic. */
export const APOS = "['’]";

/**
 * Builds a case-insensitive, Unicode, global regex for a phrase with word boundaries at both ends.
 * Literal spaces in `source` match any run of whitespace, so phrases survive line wrapping.
 */
export function phrase(source: string): RegExp {
  return new RegExp(`${B}(?:${source.replace(/ /g, String.raw`\s+`)})${E}`, "giu");
}

/** Like `phrase`, but the last word may continue (Russian endings: `спрашивай`, `спрашивайте`). */
export function stemPhrase(source: string): RegExp {
  return new RegExp(`${B}(?:${source.replace(/ /g, String.raw`\s+`)})\\p{L}*`, "giu");
}

export interface PhrasePattern {
  re: RegExp;
  label: string;
  confidence?: Confidence;
  severity?: Severity;
}

export interface PhraseMatch {
  start: number;
  end: number;
  pattern: PhrasePattern;
}

/** All non-overlapping matches of the patterns in `text`, earlier patterns winning overlaps. */
export function matchPhrases(text: string, patterns: PhrasePattern[]): PhraseMatch[] {
  const matches: PhraseMatch[] = [];
  for (const pattern of patterns) {
    pattern.re.lastIndex = 0;
    for (const m of execAll(pattern.re, text)) {
      const start = m.index;
      const end = start + m[0].length;
      if (matches.some((x) => start < x.end && end > x.start)) continue;
      matches.push({ start, end, pattern });
    }
  }
  return matches.sort((a, b) => a.start - b.start);
}

/**
 * A warning that governs what follows: "Never run with", "Don't use", "Avoid", "Не используйте".
 * Only up to four plain words may sit between the warning word and the match, so
 * "Never stop to ask; always run claude --dangerously-skip-permissions" is NOT a warning.
 */
const WARNING_BEFORE = new RegExp(
  String.raw`${B}(?:never|don${APOS}?t|do not|avoid|must not|should not|shouldn${APOS}t|mustn${APOS}t|not recommended to|никогда не|никогда|не используйте|не используй|не запускайте|не запускай|не включайте|не включай|нельзя|запрещено)\s+(?:\p{L}+\s+){0,4}["'\x60(*_]*$`,
  "iu",
);

/** True if the text right before `start` (same line) is a warning such as "Never run with". */
export function isWarningContext(text: string, start: number): boolean {
  return WARNING_BEFORE.test(text.slice(Math.max(0, start - 60), start));
}

/**
 * True if `[start, end)` sits inside a quoted span on its line: "…", `…`, “…”, «…». Quoted phrases are usually
 * examples or detection patterns in security docs (`red flags: "do not tell the user", "silently"`), not instructions.
 */
export function isQuoted(text: string, start: number, end: number): boolean {
  const before = text.slice(0, start);
  const after = text.slice(end);
  const count = (s: string, c: string) => s.split(c).length - 1;
  for (const q of ['"', "`"]) {
    if (count(before, q) % 2 === 1 && after.includes(q)) return true;
  }
  for (const [open, close] of [["“", "”"], ["«", "»"]] as const) {
    if (before.lastIndexOf(open) > before.lastIndexOf(close) && after.includes(close)) return true;
  }
  return false;
}
