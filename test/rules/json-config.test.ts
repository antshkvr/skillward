import { describe, expect, it } from "vitest";
import { claudeJsonDescend, member, parseJsonTree, toValue, type JsonObject } from "../../src/parsers/json-tree.js";
import { parseText } from "../../src/parsers/index.js";
import { hookCommands, mcpServers, redactSecrets } from "../../src/rules/json-config.js";

const file = (text: string, path = ".mcp.json") => parseText({ absPath: path, path }, text);

describe("parseJsonTree", () => {
  it("matches JSON.parse and keeps offsets", () => {
    const text = '{ "a": [1, -2.5e3, true, null, "x\\"y"], "b": { "c": "\\u00e9" }, "a2": {} }';
    const tree = parseJsonTree(text)!;
    expect(toValue(tree)).toEqual(JSON.parse(text));
    const c = member(member(tree, "b"), "c")!;
    expect(text.slice(c.start, c.end)).toBe('"\\u00e9"');
    const entry = (tree as JsonObject).entries[1]!;
    expect(text.slice(entry.keyStart, entry.keyStart + 3)).toBe('"b"');
  });

  it.each(["", "{", '{"a":}', "[1,]", '{"a":1} x', "tru", '"unterminated', '{"a" 1}', "01"])("rejects %j", (text) => {
    expect(parseJsonTree(text)).toBeUndefined();
  });

  it("rejects absurd nesting instead of overflowing the stack", () => {
    expect(parseJsonTree("[".repeat(10000) + "]".repeat(10000))).toBeUndefined();
  });

  it("skips containers that are not of interest, keeping their ranges", () => {
    const text = '{"history":[{"display":"cat ~/.ssh/id_rsa"}],"mcpServers":{"s":{"command":"npx"}},"projects":{"/p":{"history":["x"],"mcpServers":{}}}}';
    const tree = parseJsonTree(text, { descend: claudeJsonDescend })!;
    const history = member(tree, "history")!;
    expect(history).toMatchObject({ kind: "array", items: [], skipped: true });
    expect(text.slice(history.start, history.end)).toBe('[{"display":"cat ~/.ssh/id_rsa"}]');
    expect(toValue(member(tree, "mcpServers")!)).toEqual({ s: { command: "npx" } });
    expect(member(member(member(tree, "projects"), "/p"), "history")).toMatchObject({ skipped: true });
  });
});

describe("json-config helpers", () => {
  it("iterates MCP servers, skipping string references and non-objects", () => {
    const f = file(JSON.stringify({ mcpServers: { a: { command: "x" }, b: "nope" }, projects: { "/p": { mcpServers: { c: { url: "u" } } } } }));
    expect(mcpServers(f).map((s) => [s.name, s.project])).toEqual([
      ["a", undefined],
      ["c", "/p"],
    ]);
    expect(mcpServers(file(JSON.stringify({ mcpServers: "./mcp.json" }), ".claude-plugin/plugin.json"))).toEqual([]);
  });

  it("iterates hooks and the status line", () => {
    const f = file(
      JSON.stringify({
        hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "a" }, { type: "prompt", prompt: "p" }] }] },
        statusLine: { type: "command", command: "s" },
      }),
      ".claude/settings.json",
    );
    expect(hookCommands(f).map((h) => [h.event, h.matcher, h.value])).toEqual([
      ["PreToolUse", "Bash", "a"],
      ["statusLine", undefined, "s"],
    ]);
  });

  it.each([
    ['"API_KEY": "FAKE_KEY_123456"', '"API_KEY": "FA***"'],
    ["TOKEN=FAKE_KEY_123456 run", "TOKEN=FA*** run"],
    ['"--api-key", "FAKE_KEY_123456"', '"--api-key", "FA***"'],
    ["--token=FAKE_KEY_123456", "--token=FA***"],
    ["Authorization: Bearer FAKE_KEY_123456", "Authorization: Bearer FA***"],
    ["https://user:pass@example.invalid/x", "https://***@example.invalid/x"],
  ])("redacts %s", (input, expected) => {
    expect(redactSecrets(input)).toBe(expected);
  });
});
