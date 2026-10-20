/**
 * Position-aware JSON parser. `JSON.parse` loses offsets, but findings need line numbers, and for
 * `~/.claude.json` we need the ranges of a few keys inside a large file of unrelated history.
 * Linear time; containers that are not of interest can be skipped without building nodes.
 */

export type JsonPath = ReadonlyArray<string | number>;

interface Base {
  /** Offset of the first character of the value. */
  start: number;
  /** Offset just past the last character of the value. */
  end: number;
}

export interface JsonObject extends Base {
  kind: "object";
  entries: JsonEntry[];
  /** True when the content was not parsed because `descend` returned false. */
  skipped?: boolean;
}

export interface JsonArray extends Base {
  kind: "array";
  items: JsonNode[];
  skipped?: boolean;
}

export interface JsonScalar extends Base {
  kind: "string" | "number" | "boolean" | "null";
  value: string | number | boolean | null;
}

export type JsonNode = JsonObject | JsonArray | JsonScalar;

export interface JsonEntry {
  key: string;
  keyStart: number;
  value: JsonNode;
}

export interface JsonTreeOptions {
  /** Return false to skip a container's content (it still gets a node with its range). */
  descend?: (path: JsonPath) => boolean;
  /** Nesting limit for parsed containers; deeper input is treated as invalid. */
  maxDepth?: number;
}

class JsonSyntaxError extends Error {}

/** Parses JSON text with offsets. Returns undefined for invalid JSON. */
export function parseJsonTree(text: string, options: JsonTreeOptions = {}): JsonNode | undefined {
  const descend = options.descend ?? (() => true);
  const maxDepth = options.maxDepth ?? 256;
  let i = 0;

  const fail = (): never => {
    throw new JsonSyntaxError(`invalid JSON at offset ${i}`);
  };

  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i++;
      else break;
    }
  };

  /** Returns the offset just past the closing quote of the string starting at `i`. */
  const scanString = (): number => {
    let j = i + 1;
    while (j < text.length) {
      const c = text.charCodeAt(j);
      if (c === 34 /* " */) return j + 1;
      if (c === 92 /* \ */) j += 2;
      else if (c < 32) fail();
      else j++;
    }
    return fail();
  };

  const readString = (): string => {
    const end = scanString();
    const raw = text.slice(i, end);
    i = end;
    // Fast path without escapes.
    if (!raw.includes("\\")) return raw.slice(1, -1);
    try {
      return JSON.parse(raw) as string;
    } catch {
      return fail();
    }
  };

  /** Skips a container starting at `i` without building nodes; strings are respected. */
  const skipContainer = () => {
    let depth = 0;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 34) {
        i = scanString();
        continue;
      }
      if (c === 123 || c === 91) depth++;
      else if (c === 125 || c === 93) {
        depth--;
        if (depth === 0) {
          i++;
          return;
        }
      }
      i++;
    }
    fail();
  };

  const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

  const value = (path: (string | number)[], depth: number): JsonNode => {
    ws();
    const start = i;
    const c = text[i];
    if (c === "{" || c === "[") {
      if (!descend(path)) {
        skipContainer();
        return c === "{"
          ? { kind: "object", start, end: i, entries: [], skipped: true }
          : { kind: "array", start, end: i, items: [], skipped: true };
      }
      if (depth >= maxDepth) fail();
      i++;
      ws();
      if (c === "{") {
        const entries: JsonEntry[] = [];
        if (text[i] === "}") {
          i++;
          return { kind: "object", start, end: i, entries };
        }
        for (;;) {
          ws();
          if (text[i] !== '"') fail();
          const keyStart = i;
          const key = readString();
          ws();
          if (text[i] !== ":") fail();
          i++;
          path.push(key);
          entries.push({ key, keyStart, value: value(path, depth + 1) });
          path.pop();
          ws();
          if (text[i] === ",") {
            i++;
            continue;
          }
          if (text[i] === "}") {
            i++;
            return { kind: "object", start, end: i, entries };
          }
          fail();
        }
      }
      const items: JsonNode[] = [];
      if (text[i] === "]") {
        i++;
        return { kind: "array", start, end: i, items };
      }
      for (let index = 0; ; index++) {
        path.push(index);
        items.push(value(path, depth + 1));
        path.pop();
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return { kind: "array", start, end: i, items };
        }
        fail();
      }
    }
    if (c === '"') return { kind: "string", start, value: readString(), end: i };
    if (text.startsWith("true", i)) {
      i += 4;
      return { kind: "boolean", start, end: i, value: true };
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return { kind: "boolean", start, end: i, value: false };
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return { kind: "null", start, end: i, value: null };
    }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) return fail();
    i += m[0].length;
    return { kind: "number", start, end: i, value: Number(m[0]) };
  };

  try {
    const root = value([], 0);
    ws();
    if (i !== text.length) fail();
    return root;
  } catch (err) {
    if (err instanceof JsonSyntaxError || err instanceof RangeError) return undefined;
    throw err;
  }
}

/** In `~/.claude.json`, only `mcpServers` and `projects.<path>.mcpServers` are agent configuration. */
export function claudeJsonDescend(path: JsonPath): boolean {
  if (path.length === 0) return true;
  if (path[0] === "mcpServers") return true;
  if (path[0] !== "projects") return false;
  return path.length <= 2 || path[2] === "mcpServers";
}

export function member(node: JsonNode | undefined, key: string): JsonNode | undefined {
  if (node?.kind !== "object") return undefined;
  // Last duplicate wins, as in JSON.parse.
  for (let k = node.entries.length - 1; k >= 0; k--) if (node.entries[k]!.key === key) return node.entries[k]!.value;
  return undefined;
}

/** Plain JS value of a fully parsed node (skipped containers become empty). */
export function toValue(node: JsonNode): unknown {
  switch (node.kind) {
    case "object":
      return Object.fromEntries(node.entries.map((e) => [e.key, toValue(e.value)]));
    case "array":
      return node.items.map(toValue);
    default:
      return node.value;
  }
}

/** `mcpServers` value nodes of a `~/.claude.json` tree: top-level and per project. */
export function claudeJsonMcpSections(root: JsonNode): Array<{ scope?: string; node: JsonNode }> {
  const sections: Array<{ scope?: string; node: JsonNode }> = [];
  const top = member(root, "mcpServers");
  if (top) sections.push({ node: top });
  const projects = member(root, "projects");
  if (projects?.kind === "object") {
    for (const p of projects.entries) {
      const servers = member(p.value, "mcpServers");
      if (servers) sections.push({ scope: p.key, node: servers });
    }
  }
  return sections;
}

/** Shifts all offsets of a tree by `delta` (for trees parsed from a slice). */
export function shiftTree(node: JsonNode, delta: number): JsonNode {
  node.start += delta;
  node.end += delta;
  if (node.kind === "object") {
    for (const e of node.entries) {
      e.keyStart += delta;
      shiftTree(e.value, delta);
    }
  } else if (node.kind === "array") {
    for (const item of node.items) shiftTree(item, delta);
  }
  return node;
}

const trees = new WeakMap<object, JsonNode | null>();

/** Parsed tree of a JSON file's text, cached per file. A parser may provide one up front. */
export function jsonTreeOf(file: { type: string; text: string }): JsonNode | undefined {
  if (file.type !== "json") return undefined;
  let tree = trees.get(file);
  if (tree === undefined) {
    tree = parseJsonTree(file.text) ?? null;
    trees.set(file, tree);
  }
  return tree ?? undefined;
}

export function setJsonTree(file: object, tree: JsonNode | null): void {
  trees.set(file, tree);
}
