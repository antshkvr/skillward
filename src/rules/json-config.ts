import { jsonTreeOf, member, type JsonNode, type JsonObject } from "../parsers/json-tree.js";
import type { ParsedFile } from "../types.js";

/** An MCP server entry in `mcpServers` (top-level, or per project in `~/.claude.json`). */
export interface McpServer {
  name: string;
  /** Offset of the server's key. */
  keyOffset: number;
  config: JsonObject;
  /** Project path for project-scoped servers in `~/.claude.json`. */
  project?: string;
}

export function stringValue(node: JsonNode | undefined): string | undefined {
  return node?.kind === "string" ? (node.value as string) : undefined;
}

export function mcpServers(file: ParsedFile): McpServer[] {
  const root = jsonTreeOf(file);
  if (!root) return [];
  const servers: McpServer[] = [];
  const collect = (section: JsonNode | undefined, project?: string) => {
    // Plugins may point `mcpServers` at another file (a string); that file is not resolved here.
    if (section?.kind !== "object") return;
    for (const entry of section.entries) {
      if (entry.value.kind !== "object") continue;
      servers.push({ name: entry.key, keyOffset: entry.keyStart, config: entry.value, ...(project ? { project } : {}) });
    }
  };
  collect(member(root, "mcpServers"));
  // VS Code / GitHub Copilot `.vscode/mcp.json` keeps them under `servers`.
  if (/(?:^|\/)\.vscode\/mcp\.json$/.test(file.path)) collect(member(root, "servers"));
  const projects = member(root, "projects");
  if (projects?.kind === "object") {
    for (const p of projects.entries) collect(member(p.value, "mcpServers"), p.key);
  }
  return servers;
}

/** A command (or URL) a hook or status line runs. */
export interface HookCommand {
  /** Hook event, e.g. `PreToolUse`; `statusLine` for the status line command. */
  event: string;
  matcher?: string;
  /** `command` for command hooks, `url` for HTTP hooks. */
  type: "command" | "url";
  value: string;
  /** Offset of the command/URL string in the file. */
  offset: number;
}

/**
 * Hooks from `hooks` (settings, `plugin.json`, plugin `hooks/hooks.json`) and `statusLine`:
 * `{ "hooks": { "<Event>": [ { "matcher"?: "…", "hooks": [ { "type": "command", "command": "…" } ] } ] } }`.
 */
export function hookCommands(file: ParsedFile): HookCommand[] {
  const root = jsonTreeOf(file);
  if (!root) return [];
  const result: HookCommand[] = [];

  const hooks = member(root, "hooks");
  if (hooks?.kind === "object") {
    for (const { key: event, value: groups } of hooks.entries) {
      if (groups.kind !== "array") continue;
      for (const group of groups.items) {
        const matcher = stringValue(member(group, "matcher"));
        // Claude Code nests hooks in groups (`{matcher, hooks: [...]}`); Cursor lists them directly (`[{command}]`).
        const list = member(group, "hooks");
        const items = list?.kind === "array" ? list.items : member(group, "command") ? [group] : [];
        for (const hook of items) {
          // Codex handlers may add a Windows-only `commandWindows`, a command of its own.
          for (const [key, type] of [["command", "command"], ["commandWindows", "command"], ["url", "url"]] as const) {
            const node = member(hook, key);
            if (node?.kind === "string") {
              result.push({ event, ...(matcher ? { matcher } : {}), type, value: node.value as string, offset: node.start });
            }
          }
        }
      }
    }
  }

  const status = member(member(root, "statusLine"), "command");
  if (status?.kind === "string") {
    result.push({ event: "statusLine", type: "command", value: status.value as string, offset: status.start });
  }
  return result;
}

/** Hooks declared in markdown frontmatter (skills and agents can carry `hooks:` in YAML). */
export function frontmatterHookCommands(file: ParsedFile): HookCommand[] {
  const fm = file.markdown?.frontmatter;
  const hooks = (fm?.data as { hooks?: unknown } | undefined)?.hooks;
  if (!fm || typeof hooks !== "object" || hooks === null || Array.isArray(hooks)) return [];
  const result: HookCommand[] = [];
  const fmStart = file.lineStarts[fm.startLine - 1] ?? 0;
  for (const [event, groups] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups as Array<Record<string, unknown>>) {
      const matcher = typeof group?.matcher === "string" ? group.matcher : undefined;
      if (!Array.isArray(group?.hooks)) continue;
      for (const hook of group.hooks as Array<Record<string, unknown>>) {
        for (const type of ["command", "url"] as const) {
          const value = hook?.[type];
          if (typeof value !== "string") continue;
          // YAML has no offsets here; locate the text, falling back to the frontmatter start.
          const found = file.text.indexOf(value, fmStart);
          result.push({ event, ...(matcher ? { matcher } : {}), type, value, offset: found === -1 ? fmStart : found });
        }
      }
    }
  }
  return result;
}

const SECRET_NAME = String.raw`[\w-]*(?:token|secret|password|passwd|pwd|api[_-]?key|apikey|auth|authorization|credential|bearer|private[_-]?key|session|cookie)[\w-]*`;

/**
 * Masks values that look like credentials in a snippet: JSON/YAML/env pairs with secret-like names,
 * `--token VALUE` flags, `Bearer …`, URL userinfo and secret-like query parameters.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(new RegExp(String.raw`("${SECRET_NAME}"\s*:\s*")([^"]*)(")`, "gi"), (_, a: string, v: string, b: string) => a + mask(v) + b)
    .replace(new RegExp(String.raw`(\b${SECRET_NAME}=)([^\s"'&]+)`, "gi"), (_, a: string, v: string) => a + mask(v))
    .replace(new RegExp(String.raw`(--${SECRET_NAME}(?:=|"?\s*,?\s*"?\s*))([^\s"',]+)`, "gi"), (_, a: string, v: string) => a + mask(v))
    .replace(/(\bBearer\s+)([\w.~+/=-]+)/gi, (_, a: string, v: string) => a + mask(v))
    .replace(/(\bhttps?:\/\/)([^\s/@"']+)@/gi, (_, a: string) => `${a}***@`);
}

function mask(value: string): string {
  if (value.length === 0) return value;
  return value.length <= 4 ? "***" : value.slice(0, 2) + "***";
}

/** Shortens a command for a message. */
export function shorten(value: string, max = 80): string {
  const oneLine = value.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? oneLine.slice(0, max - 1) + "…" : oneLine;
}
