import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { lineText, locate, makeSnippet } from "../text.js";

export interface FindingInput {
  /** Offset of the match in `file.text`. */
  offset: number;
  /** Length of the match, used to center the snippet. */
  length: number;
  message: string;
  confidence: Confidence;
  /** Defaults to the rule's severity. */
  severity?: Severity;
}

export function findingAt(rule: Rule, file: ParsedFile, input: FindingInput): Finding {
  const { line, column } = locate(file.lineStarts, input.offset);
  const text = lineText(file.text, file.lineStarts, line);
  return {
    ruleId: rule.id,
    severity: input.severity ?? rule.severity,
    file: file.path,
    line,
    column,
    message: input.message,
    snippet: makeSnippet(text, column - 1, column - 1 + input.length),
    confidence: input.confidence,
  };
}

const LINE_COMMENT: Record<string, RegExp> = {
  shell: /^\s*#(?!!)/,
  python: /^\s*#(?!!)/,
  ruby: /^\s*#(?!!)/,
  perl: /^\s*#(?!!)/,
  powershell: /^\s*(?:#|<#)/,
  batch: /^\s*(?:@?rem\b|::)/i,
  lua: /^\s*--/,
};
/** JavaScript, TypeScript, Go, Rust, PHP; also the fallback for unknown interpreters. */
const C_STYLE_COMMENT = /^\s*(?:\/\/|\/\*|\*|#(?!!))/;

/** True if `line` of a script file is a comment-only line (documentation, not code that runs). */
export function isScriptCommentLine(file: ParsedFile, line: string): boolean {
  const language = file.script?.language;
  if (!language) return false;
  return (LINE_COMMENT[language] ?? C_STYLE_COMMENT).test(line);
}
