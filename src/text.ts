/** Helpers for working with file text: positions, lines and safe snippets. */

export function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  return starts;
}

/** 1-based line and column (UTF-16 code units, as in SARIF's default) for an offset. */
export function locate(lineStarts: number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - lineStarts[lo]! + 1 };
}

/** Text of a 1-based line without its line terminator. */
export function lineText(text: string, lineStarts: number[], line: number): string {
  const start = lineStarts[line - 1];
  if (start === undefined) return "";
  const next = lineStarts[line];
  const end = next === undefined ? text.length : next - 1;
  return text.slice(start, end).replace(/\r$/, "");
}

/**
 * Like `text.matchAll(re)`, but without cloning the regex. `matchAll` copies its RegExp on every call,
 * which recompiles big Unicode patterns for every line scanned — measured at ~70% of a phrase rule's time.
 * `re` must be global. Don't use the same regex again inside the loop.
 */
export function* execAll(re: RegExp, text: string): Generator<RegExpExecArray> {
  if (!re.global) throw new TypeError(`execAll needs a global regex: ${re}`);
  re.lastIndex = 0;
  try {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === "") re.lastIndex++;
      yield m;
    }
  } finally {
    re.lastIndex = 0;
  }
}

export interface LogicalLine {
  text: string;
  /** Offset in the file of each character of `text`. */
  offsets: number[];
  /** 1-based line where the logical line starts. */
  line: number;
}

/**
 * Splits text into lines, joining shell (`\`) and PowerShell (`` ` ``) line continuations,
 * so `curl … \` + `| bash` on the next line is seen as one command.
 */
export function logicalLines(text: string): LogicalLine[] {
  const result: LogicalLine[] = [];
  let current: LogicalLine | undefined;
  let lineNo = 1;
  let pos = 0;
  while (pos <= text.length) {
    let end = text.indexOf("\n", pos);
    if (end === -1) end = text.length;
    let contentEnd = end;
    if (contentEnd > pos && text.charCodeAt(contentEnd - 1) === 13 /* \r */) contentEnd--;
    const raw = text.slice(pos, contentEnd);
    // A PowerShell continuation backtick follows whitespace; this keeps markdown `inline code` intact.
    const continued = /(?:\\|\s`)$/.test(raw);
    const piece = continued ? raw.slice(0, -1) : raw;

    if (!current) current = { text: "", offsets: [], line: lineNo };
    for (let i = 0; i < piece.length; i++) {
      current.text += piece[i];
      current.offsets.push(pos + i);
    }
    if (continued) {
      current.text += " ";
      current.offsets.push(pos + piece.length);
    } else {
      result.push(current);
      current = undefined;
    }
    if (end === text.length) break;
    pos = end + 1;
    lineNo++;
  }
  if (current) result.push(current);
  return result;
}

const INVISIBLE =
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFB]|\udb40[\udc00-\uddef]/g;

const INVISIBLE_RUN = new RegExp(`(?:${INVISIBLE.source}){4,}`, "g");

const hex = (ch: string) => `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;

/**
 * Replaces control and invisible characters with `<U+XXXX>` so output cannot hide or inject anything.
 * Long runs are collapsed, e.g. `<43 hidden chars U+E0046…U+E007F>`.
 */
export function escapeInvisible(value: string): string {
  return value
    .replace(/\t/g, " ")
    .replace(INVISIBLE_RUN, (run) => {
      const chars = [...run];
      return `<${chars.length} hidden chars ${hex(chars[0]!)}…${hex(chars.at(-1)!)}>`;
    })
    .replace(INVISIBLE, (ch) => `<${hex(ch)}>`);
}

export const SNIPPET_MAX = 120;

/**
 * Builds a short, safe snippet around [start, end) of a line.
 * Long lines are cut around the match; invisible characters are escaped.
 */
export function makeSnippet(line: string, start = 0, end = line.length, max = SNIPPET_MAX): string {
  let from = 0;
  let to = line.length;
  if (to - from > max) {
    const matchLen = Math.min(end - start, max);
    from = Math.max(0, start - Math.floor((max - matchLen) / 2));
    to = Math.min(line.length, from + max);
    from = Math.max(0, to - max);
  }
  let snippet = escapeInvisible(line.slice(from, to).trim());
  if (from > 0) snippet = "…" + snippet;
  if (to < line.length) snippet += "…";
  return snippet;
}
