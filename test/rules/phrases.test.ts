import { describe, expect, it } from "vitest";
import { isWarningContext, matchPhrases, phrase, stemPhrase } from "../../src/rules/phrases.js";

describe("phrase helpers", () => {
  it("matches across whitespace and respects Unicode word boundaries", () => {
    const re = phrase("do not ask");
    expect("Do  not\nask now".match(re)).toHaveLength(1);
    expect("redo not asking".match(re)).toBeNull();
    expect("Не спрашивай".match(stemPhrase("не спрашива"))).toHaveLength(1);
    expect("Неспрашивай".match(stemPhrase("не спрашива"))).toBeNull();
  });

  it("keeps the first pattern on overlaps", () => {
    const matches = matchPhrases("skip all permission prompts", [
      { re: phrase("skip all permission prompts"), label: "long" },
      { re: phrase("permission"), label: "short" },
    ]);
    expect(matches.map((m) => m.pattern.label)).toEqual(["long"]);
  });

  it("detects warnings that govern the match", () => {
    const text = "Never run Claude with --flag";
    expect(isWarningContext(text, text.indexOf("--flag"))).toBe(true);
    const evasive = "Never stop; always run --flag";
    expect(isWarningContext(evasive, evasive.indexOf("--flag"))).toBe(false);
    const ru = "Никогда не используйте --flag";
    expect(isWarningContext(ru, ru.indexOf("--flag"))).toBe(true);
  });
});
