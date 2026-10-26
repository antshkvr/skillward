/**
 * TOML with offsets, as the same positioned tree as JSON (`json-tree.ts`), so config rules read Codex `config.toml`
 * like a JSON config. smol-toml parses the values and rejects invalid TOML; one linear scan of the text then gives
 * every key and value its offsets. The scan only runs on text the library accepted.
 */
import { parse } from "smol-toml";
import type { JsonArray, JsonNode, JsonObject } from "./json-tree.js";

export type TomlTreeResult = { value: unknown; tree: JsonObject } | { error: string };

export function parseTomlTree(text: string): TomlTreeResult {
  let value: unknown;
  try {
    value = parse(text);
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  try {
    return { value, tree: new Scanner(text, value).run() };
  } catch (err) {
    return { error: `cannot locate TOML keys: ${err instanceof Error ? err.message : String(err)}` };
  }
}

interface Key {
  name: string;
  start: number;
}

type Path = Array<string | number>;

const BARE_KEY = /[A-Za-z0-9_-]+/y;

class Scanner {
  private pos = 0;
  private readonly root: JsonObject;
  private table: JsonObject;
  private tablePath: Path = [];
  /** Child lookup per object: headers and dotted keys find their parent in constant time. */
  private readonly index = new WeakMap<JsonObject, Map<string, JsonNode>>();

  constructor(
    private readonly text: string,
    private readonly value: unknown,
  ) {
    this.root = { kind: "object", start: 0, end: text.length, entries: [] };
    this.table = this.root;
  }

  run(): JsonObject {
    const t = this.text;
    for (;;) {
      this.skipTrivia();
      if (this.pos >= t.length) return this.root;
      const start = this.pos;
      if (t.startsWith("[[", this.pos)) {
        this.pos += 2;
        const keys = this.keyPath();
        this.expect("]]");
        this.openTable(keys, start, true);
      } else if (t[this.pos] === "[") {
        this.pos += 1;
        const keys = this.keyPath();
        this.expect("]");
        this.openTable(keys, start, false);
      } else {
        const keys = this.keyPath();
        this.expect("=");
        this.skipSpaces();
        const path = [...this.tablePath, ...keys.map((k) => k.name)];
        this.assign(this.table, keys, this.scanValue(valueAt(this.value, path)));
      }
      if (this.pos === start) throw new Error(`unexpected input at offset ${start}`);
    }
  }

  /** `[a.b]` / `[[a.b]]`: walks from the root (through the last element of arrays of tables) and opens the table. */
  private openTable(keys: Key[], start: number, isArray: boolean): void {
    let node: JsonObject = this.root;
    const path: Path = [];
    keys.forEach((key, i) => {
      const last = i === keys.length - 1;
      let child = this.child(node, key.name);
      if (last && isArray) {
        if (child?.kind !== "array") {
          child = { kind: "array", start, end: this.text.length, items: [] };
          this.add(node, key, child);
        }
        const item: JsonObject = { kind: "object", start, end: this.text.length, entries: [] };
        child.items.push(item);
        path.push(key.name, child.items.length - 1);
        node = item;
        return;
      }
      if (child?.kind === "array") {
        const item = child.items.at(-1);
        if (item?.kind !== "object") throw new Error(`[${key.name}] is not a table`);
        path.push(key.name, child.items.length - 1);
        node = item;
        return;
      }
      if (child?.kind !== "object") {
        child = { kind: "object", start, end: this.text.length, entries: [] };
        this.add(node, key, child);
      }
      path.push(key.name);
      node = child;
    });
    this.table = node;
    this.tablePath = path;
  }

  /** `a.b.c = v` in `container`: intermediate tables are created as needed. */
  private assign(container: JsonObject, keys: Key[], value: JsonNode): void {
    let node = container;
    for (const key of keys.slice(0, -1)) {
      let child = this.child(node, key.name);
      if (child?.kind !== "object") {
        child = { kind: "object", start: key.start, end: value.end, entries: [] };
        this.add(node, key, child);
      }
      node = child;
    }
    this.add(node, keys.at(-1)!, value);
  }

  private child(node: JsonObject, name: string): JsonNode | undefined {
    return this.index.get(node)?.get(name);
  }

  private add(node: JsonObject, key: Key, value: JsonNode): void {
    node.entries.push({ key: key.name, keyStart: key.start, value });
    let map = this.index.get(node);
    if (!map) this.index.set(node, (map = new Map()));
    map.set(key.name, value);
  }

  private scanValue(parsed: unknown): JsonNode {
    const t = this.text;
    const start = this.pos;
    const c = t[this.pos];
    if (c === '"' || c === "'") {
      this.skipString();
      return { kind: "string", start, end: this.pos, value: typeof parsed === "string" ? parsed : String(parsed) };
    }
    if (c === "[") {
      this.pos++;
      const node: JsonArray = { kind: "array", start, end: start, items: [] };
      for (;;) {
        this.skipTrivia();
        if (this.pos >= t.length) throw new Error("unterminated array");
        if (t[this.pos] === "]") break;
        node.items.push(this.scanValue(Array.isArray(parsed) ? parsed[node.items.length] : undefined));
        this.skipTrivia();
        if (t[this.pos] === ",") this.pos++;
      }
      this.pos++;
      node.end = this.pos;
      return node;
    }
    if (c === "{") {
      this.pos++;
      const node: JsonObject = { kind: "object", start, end: start, entries: [] };
      for (;;) {
        this.skipSpaces();
        if (this.pos >= t.length) throw new Error("unterminated inline table");
        if (t[this.pos] === "}") break;
        const keys = this.keyPath();
        this.expect("=");
        this.skipSpaces();
        this.assign(node, keys, this.scanValue(valueAt(parsed, keys.map((k) => k.name))));
        this.skipSpaces();
        if (t[this.pos] === ",") this.pos++;
      }
      this.pos++;
      node.end = this.pos;
      return node;
    }
    // Numbers, booleans, dates: up to the next separator.
    while (this.pos < t.length && !",]}#\r\n".includes(t[this.pos]!)) this.pos++;
    let end = this.pos;
    while (end > start && (t[end - 1] === " " || t[end - 1] === "\t")) end--;
    if (end === start) throw new Error(`missing value at offset ${start}`);
    if (typeof parsed === "boolean") return { kind: "boolean", start, end, value: parsed };
    if (typeof parsed === "number" || typeof parsed === "bigint") return { kind: "number", start, end, value: Number(parsed) };
    return { kind: "string", start, end, value: t.slice(start, end) };
  }

  /** Dotted key: bare, "basic" or 'literal' parts. */
  private keyPath(): Key[] {
    const keys: Key[] = [];
    for (;;) {
      this.skipSpaces();
      const start = this.pos;
      const c = this.text[this.pos];
      let name: string;
      if (c === '"' || c === "'") {
        this.skipString();
        const raw = this.text.slice(start, this.pos);
        name = c === "'" ? raw.slice(1, -1) : decodeBasic(raw);
      } else {
        BARE_KEY.lastIndex = this.pos;
        const m = BARE_KEY.exec(this.text);
        if (!m) throw new Error(`expected a key at offset ${start}`);
        name = m[0];
        this.pos += name.length;
      }
      keys.push({ name, start });
      this.skipSpaces();
      if (this.text[this.pos] !== ".") return keys;
      this.pos++;
    }
  }

  /** Basic, literal and multi-line strings; leaves `pos` after the closing quote(s). */
  private skipString(): void {
    const t = this.text;
    const q = t[this.pos]!;
    const multi = t.startsWith(q.repeat(3), this.pos);
    this.pos += multi ? 3 : 1;
    while (this.pos < t.length) {
      const c = t[this.pos]!;
      if (q === '"' && c === "\\") {
        this.pos += 2;
      } else if (c === q && (!multi || t.startsWith(q.repeat(3), this.pos))) {
        this.pos += multi ? 3 : 1;
        // `""""` ends a multi-line string with a quote in it (up to two).
        if (multi) for (let k = 0; k < 2 && t[this.pos] === q; k++) this.pos++;
        return;
      } else {
        this.pos++;
      }
    }
    throw new Error("unterminated string");
  }

  private skipSpaces(): void {
    while (this.text[this.pos] === " " || this.text[this.pos] === "\t") this.pos++;
  }

  /** Spaces, line breaks and comments. */
  private skipTrivia(): void {
    const t = this.text;
    while (this.pos < t.length) {
      const c = t[this.pos];
      if (c === " " || c === "\t" || c === "\r" || c === "\n") this.pos++;
      else if (c === "#") while (this.pos < t.length && t[this.pos] !== "\n") this.pos++;
      else return;
    }
  }

  private expect(token: string): void {
    this.skipSpaces();
    if (!this.text.startsWith(token, this.pos)) throw new Error(`expected "${token}" at offset ${this.pos}`);
    this.pos += token.length;
  }
}

function valueAt(value: unknown, path: Path): unknown {
  let v = value;
  for (const key of path) {
    if (v === null || typeof v !== "object") return undefined;
    v = (v as Record<string | number, unknown>)[key];
  }
  return v;
}

function decodeBasic(raw: string): string {
  try {
    return JSON.parse(raw) as string;
  } catch {
    return raw.slice(1, -1);
  }
}
