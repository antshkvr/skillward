export type Severity = "info" | "low" | "medium" | "high";
export type Confidence = "low" | "medium" | "high";

export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high"];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

export type TargetKind = "skill" | "instructions" | "mcp-config" | "settings" | "plugin-manifest";

export const TARGET_KINDS: readonly TargetKind[] = [
  "skill",
  "instructions",
  "mcp-config",
  "settings",
  "plugin-manifest",
];

/** A file on disk that belongs to a target. */
export interface SourceFile {
  /** Absolute path on disk. */
  absPath: string;
  /** Path shown to the user: relative to the scan root, forward slashes (or `~/.claude/...`). */
  path: string;
}

/** A discovered scan target, before parsing. */
export interface Target {
  kind: TargetKind;
  /** Display path of the target: skill directory or the file itself. */
  path: string;
  files: SourceFile[];
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export type FileType = "markdown" | "json" | "script" | "text";

export interface CodeBlock {
  /** Info string language, lowercased; empty if none. */
  lang: string;
  /** Content between the fences. */
  content: string;
  /** Offset of `content` within the file text. */
  offset: number;
  /** 1-based line of the first content line. */
  line: number;
}

export interface HtmlComment {
  /** Text between `<!--` and `-->`. */
  content: string;
  offset: number;
  line: number;
}

export interface MarkdownInfo {
  frontmatter?: {
    raw: string;
    data: unknown;
    error?: string;
    /** 1-based lines of the opening and closing `---`. */
    startLine: number;
    endLine: number;
  };
  /** Offset of the body (after frontmatter) within the file text. */
  bodyOffset: number;
  codeBlocks: CodeBlock[];
  htmlComments: HtmlComment[];
}

export interface ParsedFile extends SourceFile {
  type: FileType;
  /** File content as UTF-8, with a leading BOM removed. Line endings are kept as-is. */
  text: string;
  /** Offsets of the first character of every line. */
  lineStarts: number[];
  markdown?: MarkdownInfo;
  json?: { value?: unknown; error?: string };
  script?: { language: string };
  /**
   * If set, only findings on these 1-based inclusive line ranges are kept. Used for files where only a
   * part is agent configuration, e.g. the `mcpServers` sections of `~/.claude.json` (the rest is history).
   */
  lineRanges?: Array<[number, number]>;
}

export interface ParsedTarget {
  kind: TargetKind;
  path: string;
  files: ParsedFile[];
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  column?: number;
  message: string;
  /** Short, truncated, with invisible/control characters escaped. */
  snippet: string;
  confidence: Confidence;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  appliesTo: TargetKind[];
  description: string;
  check(target: ParsedTarget): Finding[];
}
