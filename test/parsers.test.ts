import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MAX_FILE_BYTES, parseFile, parseText } from "../src/parsers/index.js";
import { detectScriptLanguage } from "../src/parsers/script.js";

const md = (text: string) => parseText({ absPath: "SKILL.md", path: "SKILL.md" }, text);

describe("markdown parser", () => {
  it("extracts frontmatter, code blocks and HTML comments with line numbers", () => {
    const file = md(
      [
        "---",
        "name: demo",
        "description: Demo skill",
        "---",
        "# Title",
        "<!-- hidden note -->",
        "```bash",
        "echo hi",
        "<!-- not a comment -->",
        "```",
        "~~~~",
        "plain",
        "~~~~",
        "end <!-- multi",
        "line -->",
      ].join("\n"),
    );
    expect(file.type).toBe("markdown");
    const info = file.markdown!;
    expect(info.frontmatter).toMatchObject({ data: { name: "demo", description: "Demo skill" }, startLine: 1, endLine: 4 });
    expect(info.codeBlocks).toEqual([
      expect.objectContaining({ lang: "bash", content: "echo hi\n<!-- not a comment -->", line: 8 }),
      expect.objectContaining({ lang: "", content: "plain", line: 12 }),
    ]);
    expect(info.htmlComments.map((c) => [c.content.trim(), c.line])).toEqual([
      ["hidden note", 6],
      ["multi\nline", 14],
    ]);
  });

  it("keeps a frontmatter YAML error instead of throwing", () => {
    const file = md("---\nname: [unclosed\n---\nbody\n");
    expect(file.markdown!.frontmatter!.error).toBeTruthy();
    expect(file.markdown!.bodyOffset).toBe("---\nname: [unclosed\n---\n".length);
  });

  it("treats a missing closing --- as no frontmatter", () => {
    expect(md("---\nname: x\nbody\n").markdown!.frontmatter).toBeUndefined();
  });

  it("handles CRLF and an unclosed fence", () => {
    const info = md("---\r\nname: x\r\n---\r\n```py\r\nprint(1)\r\n").markdown!;
    expect(info.frontmatter!.data).toEqual({ name: "x" });
    expect(info.codeBlocks[0]).toMatchObject({ lang: "py", line: 5 });
    expect(info.codeBlocks[0]!.content).toContain("print(1)");
  });

  it("treats an unclosed HTML comment as running to the end of the file", () => {
    expect(md("text <!-- never closed\nmore").markdown!.htmlComments[0]!.content).toBe(" never closed\nmore");
  });
});

describe("json and script detection", () => {
  it("parses JSON and records errors without throwing", () => {
    expect(parseText({ absPath: "a.json", path: "a.json" }, '{"a":1}').json).toEqual({ value: { a: 1 } });
    expect(parseText({ absPath: "b.json", path: "b.json" }, "{nope").json!.error).toBeTruthy();
  });

  it("detects script language by extension and shebang", () => {
    expect(detectScriptLanguage("run.py", "")).toBe("python");
    expect(detectScriptLanguage("install", "#!/bin/bash\n")).toBe("shell");
    expect(detectScriptLanguage("tool", "#!/usr/bin/env -S python3 -u\n")).toBe("python");
    expect(detectScriptLanguage("tool", "#!/usr/bin/env node\n")).toBe("javascript");
    expect(detectScriptLanguage("notes.txt", "hello")).toBeUndefined();
  });
});

describe("parseFile", () => {
  const dir = mkdtempSync(join(tmpdir(), "skillward-parse-"));

  it("strips a UTF-8 BOM", async () => {
    const p = join(dir, "bom.md");
    writeFileSync(p, "\uFEFF# Hi\n");
    const result = await parseFile({ absPath: p, path: "bom.md" });
    expect(result.ok && result.file.text).toBe("# Hi\n");
  });

  it("skips binary and oversized files", async () => {
    const bin = join(dir, "logo.png");
    writeFileSync(bin, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
    expect(await parseFile({ absPath: bin, path: "logo.png" })).toEqual({ ok: false, reason: "binary file" });

    const big = join(dir, "big.md");
    writeFileSync(big, "a".repeat(MAX_FILE_BYTES + 1));
    const result = await parseFile({ absPath: big, path: "big.md" });
    expect(result.ok).toBe(false);
  });
});
