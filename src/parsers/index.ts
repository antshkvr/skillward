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
import { describeScript } from "./script-shape.js";
import { detectScriptLanguage } from "./script.js";
import { parseTomlTree } from "./toml.js";

/** Codex configuration: TOML, read as a config tree (other TOML files, such as Gemini commands, stay text). */
export const CODEX_CONFIG = /(?:^|\/)\.codex\/config\.toml$/;

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
  if (source.hookTarget) return parseHookTarget(source, size);
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

/** A hook target that big is not a script anyone reviewed; read it only to describe it. */
export const MAX_HOOK_TARGET_BYTES = 64 * 1024 * 1024;

/**
 * Scripts that hooks run are described even when large or binary (SW017 needs their shape); their content is
 * parsed for the other rules only within the usual text limit.
 */
async function parseHookTarget(source: SourceFile, size: number): Promise<ParseResult> {
  if (size > MAX_HOOK_TARGET_BYTES) return { ok: false, reason: `larger than ${MAX_HOOK_TARGET_BYTES} bytes` };
  let buffer: Buffer;
  try {
    buffer = await readFile(source.absPath);
  } catch (err) {
    return { ok: false, reason: `cannot read: ${errorMessage(err)}` };
  }
  const binary = isBinary(buffer);
  const scannable = !binary && size <= MAX_FILE_BYTES;
  const info = describeScript(buffer, binary, scannable);
  if (!scannable) {
    // Content isn't scanned, but the file still belongs to the target: SW017 reports its shape.
    const file: ParsedFile = { ...source, type: "script", text: "", lineStarts: [0], script: { language: "unknown" }, hookScript: info };
    return { ok: true, file };
  }
  let text = buffer.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const file = parseText(source, text);
  file.hookScript = info;
  if (file.type === "text") {
    // A hook runs it, whatever its extension.
    file.type = "script";
    file.script = { language: "unknown" };
  }
  return { ok: true, file };
}

/** Parses already-loaded text. Exposed for tests. */
export function parseText(source: SourceFile, text: string): ParsedFile {
  const lineStarts = computeLineStarts(text);
  const name = basename(source.path);
  const ext = extname(name).toLowerCase();
  const file: ParsedFile = { ...source, type: "text", text, lineStarts };

  if (ext === ".md" || ext === ".mdx" || ext === ".markdown" || ext === ".mdc") {
    file.type = "markdown";
    file.markdown = parseMarkdown(text, lineStarts);
  } else if (CODEX_CONFIG.test(source.path)) {
    // A JSON-shaped tree, so the config rules read MCP servers, hooks and settings as in JSON configs.
    file.type = "json";
    const parsed = parseTomlTree(text);
    if ("tree" in parsed) {
      file.json = { value: parsed.value };
      setJsonTree(file, parsed.tree);
    } else {
      file.json = { error: parsed.error };
      setJsonTree(file, null);
    }
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
