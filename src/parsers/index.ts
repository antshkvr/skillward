import { readFile, stat } from "node:fs/promises";
import { basename, extname } from "node:path";
import type { ParsedFile, SourceFile } from "../types.js";
import { computeLineStarts, locate } from "../text.js";
import {
  claudeJsonDescend,
  claudeJsonMcpSections,
  parseJsonTree,
  setJsonTree,
  shiftTree,
  toValue,
  type JsonEntry,
  type JsonObject,
} from "./json-tree.js";
import { parseMarkdown } from "./markdown.js";
import { detectScriptLanguage } from "./script.js";

/** Files above this size are skipped: agent instructions are small, and this bounds memory use. */
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
/** `~/.claude.json` keeps growing with history; only its `mcpServers` sections are scanned. */
export const MAX_CLAUDE_JSON_BYTES = 50 * 1024 * 1024;
export const CLAUDE_JSON = ".claude.json";

export type ParseResult = { ok: true; file: ParsedFile } | { ok: false; reason: string };

/** Reads a file as inert data and extracts structure. Nothing is ever executed or imported. */
export async function parseFile(source: SourceFile): Promise<ParseResult> {
  let size: number;
  try {
    size = (await stat(source.absPath)).size;
  } catch (err) {
    return { ok: false, reason: `cannot read: ${errorMessage(err)}` };
  }
  const limit = basename(source.absPath) === CLAUDE_JSON ? MAX_CLAUDE_JSON_BYTES : MAX_FILE_BYTES;
  if (size > limit) return { ok: false, reason: `larger than ${limit} bytes` };

  let buffer: Buffer;
  try {
    buffer = await readFile(source.absPath);
  } catch (err) {
    return { ok: false, reason: `cannot read: ${errorMessage(err)}` };
  }
  if (isBinary(buffer)) return { ok: false, reason: "binary file" };

  let text = buffer.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return { ok: true, file: parseText(source, text) };
}

/** Parses already-loaded text. Exposed for tests. */
export function parseText(source: SourceFile, text: string): ParsedFile {
  const lineStarts = computeLineStarts(text);
  const name = basename(source.path);
  const ext = extname(name).toLowerCase();
  const file: ParsedFile = { ...source, type: "text", text, lineStarts };

  if (ext === ".md" || ext === ".mdx" || ext === ".markdown") {
    file.type = "markdown";
    file.markdown = parseMarkdown(text, lineStarts);
  } else if (name === CLAUDE_JSON) {
    file.type = "json";
    parseClaudeJson(file);
  } else if (ext === ".json") {
    file.type = "json";
    try {
      file.json = { value: JSON.parse(text) };
    } catch (err) {
      file.json = { error: errorMessage(err) };
    }
  } else {
    const language = detectScriptLanguage(name, text);
    if (language) {
      file.type = "script";
      file.script = { language };
    }
  }
  return file;
}

/**
 * `~/.claude.json` mixes MCP config with history and state. Only the `mcpServers` sections are
 * exposed to rules: every other line is blanked (line numbers and columns are kept), `json.value`
 * is reduced to those sections and `lineRanges` limits findings to them.
 */
function parseClaudeJson(file: ParsedFile): void {
  const original = file.text;
  const root = parseJsonTree(original, { descend: claudeJsonDescend });
  const sections = root ? claudeJsonMcpSections(root) : [];
  const ranges: Array<[number, number]> = sections.map(({ node }) => [
    locate(file.lineStarts, node.start).line,
    locate(file.lineStarts, node.end - 1).line,
  ]);

  const oldStarts = file.lineStarts;
  const keep = (line: number) => ranges.some(([a, b]) => line >= a && line <= b);
  file.text = original
    .split("\n")
    .map((line, idx) => (keep(idx + 1) ? line : ""))
    .join("\n");
  file.lineStarts = computeLineStarts(file.text);
  file.lineRanges = ranges;

  if (!root) {
    file.json = { error: "invalid JSON" };
    setJsonTree(file, null);
    return;
  }

  // Re-parse each section at its new offset, and assemble { mcpServers, projects: { p: { mcpServers } } }.
  const top: JsonEntry[] = [];
  const projects: JsonEntry[] = [];
  const value: { mcpServers?: unknown; projects?: Record<string, { mcpServers: unknown }> } = {};
  sections.forEach(({ scope, node }, idx) => {
    const line = ranges[idx]![0];
    const newStart = file.lineStarts[line - 1]! + (node.start - oldStarts[line - 1]!);
    const parsed = parseJsonTree(original.slice(node.start, node.end));
    if (!parsed) return;
    shiftTree(parsed, newStart);
    if (scope === undefined) {
      top.push({ key: "mcpServers", keyStart: newStart, value: parsed });
      value.mcpServers = toValue(parsed);
    } else {
      const project: JsonObject = { kind: "object", start: newStart, end: parsed.end, entries: [{ key: "mcpServers", keyStart: newStart, value: parsed }] };
      projects.push({ key: scope, keyStart: newStart, value: project });
      (value.projects ??= {})[scope] = { mcpServers: toValue(parsed) };
    }
  });
  if (projects.length > 0) {
    const first = projects[0]!.value;
    top.push({ key: "projects", keyStart: first.start, value: { kind: "object", start: first.start, end: projects.at(-1)!.value.end, entries: projects } });
  }
  setJsonTree(file, { kind: "object", start: 0, end: file.text.length, entries: top });
  file.json = { value };
}

function isBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8000);
  // UTF-16 text has NULs too, but agent instruction files are UTF-8 in practice.
  return sample.includes(0);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
