import { describe, expect, it } from "vitest";
import { computeLineStarts, escapeInvisible, execAll, locate, logicalLines, makeSnippet, SNIPPET_MAX } from "../src/text.js";

describe("text helpers", () => {
  it("locates offsets as 1-based line/column", () => {
    const text = "ab\ncd\r\nef";
    const starts = computeLineStarts(text);
    expect(locate(starts, 0)).toEqual({ line: 1, column: 1 });
    expect(locate(starts, 4)).toEqual({ line: 2, column: 2 });
    expect(locate(starts, 7)).toEqual({ line: 3, column: 1 });
  });

  it("escapes control, invisible and terminal escape characters", () => {
    expect(escapeInvisible("a\u200Bb\u202Ec\x1b[31m\u{E0041}")).toBe("a<U+200B>b<U+202E>c<U+001B>[31m<U+E0041>");
    expect(escapeInvisible("tab\there")).toBe("tab here");
    expect(escapeInvisible("x\u200B\u200B\u200B\u200Cy")).toBe("x<4 hidden chars U+200B…U+200C>y");
  });

  it("execAll iterates matches like matchAll and resets the regex", () => {
    const re = /a(\d)/g;
    expect([...execAll(re, "a1 b a2 a3")].map((m) => [m.index, m[1]])).toEqual([[0, "1"], [5, "2"], [8, "3"]]);
    expect(re.lastIndex).toBe(0);
    expect([...execAll(/x*/g, "ab")]).toHaveLength(3);
    expect(() => execAll(/a/, "a").next()).toThrow(TypeError);
  });

  it("cuts long lines around the match", () => {
    const line = "x".repeat(300) + "MATCH" + "y".repeat(300);
    const snippet = makeSnippet(line, 300, 305);
    expect(snippet).toContain("MATCH");
    expect(snippet.startsWith("…")).toBe(true);
    expect(snippet.endsWith("…")).toBe(true);
    expect(snippet.length).toBeLessThanOrEqual(SNIPPET_MAX + 2);
  });

  it("joins continuation lines and keeps offsets", () => {
    const text = "a \\\nb\nc `\nd\nnot `code`\ne";
    const lines = logicalLines(text);
    expect(lines.map((l) => [l.text, l.line])).toEqual([
      ["a  b", 1],
      ["c  d", 3],
      ["not `code`", 5],
      ["e", 6],
    ]);
    const first = lines[0]!;
    expect(text[first.offsets[first.text.indexOf("b")]!]).toBe("b");
  });
});
