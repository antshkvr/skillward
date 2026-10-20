import type { Finding, ParsedFile } from "../types.js";

/**
 * Inline suppressions, in any comment syntax:
 *
 *   <!-- skillward-ignore SW004: security docs show this attack -->   next line (or next fenced code block)
 *   curl … | sh  # skillward-ignore SW004: reason                     this line
 *   <!-- skillward-ignore-file SW005: reason -->                      the whole file
 *
 * Rule IDs are mandatory — there is deliberately no "ignore everything". Suppressed findings are never
 * dropped silently: they are reported separately, because a malicious skill can add these comments too.
 */
const DIRECTIVE = /skillward-ignore(-file)?\s+(SW\d{3}(?:\s*,\s*SW\d{3})*)(?:\s*:\s*(.*?))?\s*(?:-->|\*\/)?\s*$/;
const FENCE = /^ {0,3}(`{3,}|~{3,})/;
/** Text before a directive that makes it a standalone comment line rather than a trailing comment. */
const COMMENT_START = /^\s*(?:<!--|#|\/\/|\/\*|--|;|REM\b|::)?\s*$/i;

export interface Suppression {
  ruleIds: string[];
  reason?: string;
  /** 1-based line of the directive. */
  line: number;
}

export interface SuppressedFinding extends Finding {
  suppression: Suppression;
}

interface Scope {
  suppression: Suppression;
  /** Inclusive line range, or the whole file. */
  from: number;
  to: number;
}

export function parseSuppressions(file: ParsedFile): Scope[] {
  const lines = file.text.split("\n").map((l) => l.replace(/\r$/, ""));
  const scopes: Scope[] = [];
  lines.forEach((text, idx) => {
    const m = DIRECTIVE.exec(text);
    if (!m) return;
    const line = idx + 1;
    const suppression: Suppression = {
      ruleIds: m[2]!.split(",").map((s) => s.trim()),
      line,
      ...(m[3] ? { reason: m[3].trim() } : {}),
    };
    if (m[1]) {
      scopes.push({ suppression, from: 1, to: Number.MAX_SAFE_INTEGER });
      return;
    }
    if (!COMMENT_START.test(text.slice(0, m.index))) {
      scopes.push({ suppression, from: line, to: line });
      return;
    }
    // Standalone comment: applies to the next non-blank line, or to a whole fenced code block.
    let next = idx + 1;
    while (next < lines.length && lines[next]!.trim() === "") next++;
    if (next >= lines.length) return;
    const fence = FENCE.exec(lines[next]!);
    let end = next;
    if (fence) {
      const close = new RegExp(`^ {0,3}${fence[1]![0] === "`" ? "`" : "~"}{${fence[1]!.length},}\\s*$`);
      end = next + 1;
      while (end < lines.length && !close.test(lines[end]!)) end++;
      end = Math.min(end, lines.length - 1);
    }
    scopes.push({ suppression, from: next + 1, to: end + 1 });
  });
  return scopes;
}

/** Splits findings into active and suppressed according to the files' inline directives. */
export function applySuppressions(
  findings: Finding[],
  files: ParsedFile[],
): { active: Finding[]; suppressed: SuppressedFinding[] } {
  const scopesByFile = new Map<string, Scope[]>();
  for (const file of files) {
    if (!file.text.includes("skillward-ignore")) continue;
    const scopes = parseSuppressions(file);
    if (scopes.length) scopesByFile.set(file.path, scopes);
  }
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const finding of findings) {
    const scope = scopesByFile
      .get(finding.file)
      ?.find((s) => s.suppression.ruleIds.includes(finding.ruleId) && finding.line >= s.from && finding.line <= s.to);
    if (scope) suppressed.push({ ...finding, suppression: scope.suppression });
    else active.push(finding);
  }
  return { active, suppressed };
}
