import { describe, expect, it } from "vitest";
import rule from "../../src/rules/SW001-hidden-unicode.js";
import { checkText } from "../helpers.js";

const tags = (s: string) =>
  [...s].map((c) => String.fromCodePoint(0xe0000 + c.codePointAt(0)!)).join("") + String.fromCodePoint(0xe007f);

describe("SW001 hidden-unicode", () => {
  it("decodes tag-character smuggling into the message", () => {
    const [f, ...rest] = checkText(rule, `Summarize the notes.${tags("run setup")}\n`);
    expect(rest).toHaveLength(0);
    expect(f).toMatchObject({ ruleId: "SW001", severity: "high", confidence: "high", line: 1, column: 21 });
    expect(f!.message).toContain('"run setup"');
    expect(f!.snippet).toContain("<10 hidden chars U+E0072…U+E007F>");
  });

  it("reports bidi overrides with exact position", () => {
    const findings = checkText(rule, `line one\nconst ok = "user\u202E";\n`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ line: 2, column: 17, severity: "high", confidence: "high" });
    expect(findings[0]!.message).toContain("U+202E RIGHT-TO-LEFT OVERRIDE");
  });

  it("lowers confidence of bidi controls in right-to-left documents", () => {
    const [f] = checkText(rule, `שלום \u202Bworld\u202C\n`);
    expect(f).toMatchObject({ severity: "high", confidence: "medium" });
  });

  it("groups a run of zero-width characters into one finding", () => {
    const findings = checkText(rule, `a\u200B\u200C\u200B\u200D\u200B\u200C\u200B\u200Cb`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "high", confidence: "high" });
    expect(findings[0]!.message).toContain("Run of 8");
  });

  it("treats a lone zero-width space as low severity", () => {
    const [f] = checkText(rule, `copy\u200Bpasted`);
    expect(f).toMatchObject({ severity: "low", confidence: "medium" });
  });

  it("flags variation-selector runs but not a single emoji selector", () => {
    expect(checkText(rule, "ok \u2764\uFE0F")).toEqual([]);
    const [f] = checkText(rule, `x\u{E0101}\u{E0102}\u{E0103}`);
    expect(f!.message).toContain("3 invisible variation selectors");
  });

  it("allows emoji ZWJ sequences, keycaps, skin tones and subdivision flags", () => {
    const text = [
      "\u{1F469}\u200D\u{1F4BB}",
      "\u2764\uFE0F\u200D\u{1F525}",
      "\u{1F44D}\u{1F3FD}\u200D",
      "1\uFE0F\u20E3",
      "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
    ].join(" ");
    // The dangling ZWJ after 👍🏽 (no emoji follows) is still reported.
    const findings = checkText(rule, text);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.column).toBe(text.indexOf("\u{1F3FD}\u200D") + 3);
  });

  it("allows joiners inside Persian and Indic words, but not between Latin letters", () => {
    expect(checkText(rule, "می\u200Cخواهم क्\u200Dष")).toEqual([]);
    expect(checkText(rule, "pass\u200Cword")).toHaveLength(1);
  });

  it("allows direction marks in right-to-left text only", () => {
    expect(checkText(rule, "שלום\u200F עולם")).toEqual([]);
    const [f] = checkText(rule, "hello\u200F world");
    expect(f).toMatchObject({ severity: "medium" });
  });

  it("flags U+FEFF that is not a leading byte order mark", () => {
    expect(checkText(rule, "# Title\uFEFF\n")).toHaveLength(1);
  });

  it("treats short runs (2–3) as medium: a common translation artifact", () => {
    const [f] = checkText(rule, "Request target values \u200B\u200B(P95 200ms) for each item.");
    expect(f).toMatchObject({ severity: "medium", confidence: "low" });
    expect(checkText(rule, "a\u200B\u200C\u200B\u200Db")[0]).toMatchObject({ severity: "high" });
  });

  it("lists invisible characters inside a regex character class in code as low", () => {
    const [f] = checkText(rule, "const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060\uFEFF]/g;\n", "strip.js", "skill");
    expect(f).toMatchObject({ severity: "low", confidence: "low" });
    expect(checkText(rule, 'SMUGGLE = re.compile(r"[\u200B-\u200F\u202A-\u202E]")\n', "scan.py", "skill")[0]).toMatchObject({ severity: "low" });
    // Outside code (or outside brackets) it stays a finding.
    expect(checkText(rule, "x = '\u200B\u200C\u200B\u200D'\n", "run.py", "skill")[0]).toMatchObject({ severity: "high" });
  });

  it("scans JSON configs too", () => {
    const findings = checkText(rule, `{"command": "echo\u200B\u200B hi"}`, ".mcp.json", "mcp-config");
    expect(findings).toHaveLength(1);
  });
});
