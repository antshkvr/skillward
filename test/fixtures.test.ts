import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { scan } from "../src/engine/index.js";
import { ALL_RULES } from "../src/rules/index.js";
import { severityRank } from "../src/types.js";

/**
 * Every rule must have fixtures (CLAUDE.md: at least 2 bad and 2 good).
 * bad/*  — the rule MUST report at least one finding of severity medium or higher
 *          (or of the rule's own severity, if that is lower — e.g. SW012 is "low").
 * good/* — the rule must NOT report anything above info.
 */
const FIXTURES = join(import.meta.dirname, "fixtures");

const entries = (dir: string) => {
  try {
    return readdirSync(dir).sort();
  } catch {
    return [];
  }
};

describe.each(ALL_RULES.map((r) => [r.id, r] as const))("%s fixtures", (id, rule) => {
  const bad = entries(join(FIXTURES, id, "bad"));
  const good = entries(join(FIXTURES, id, "good"));

  it("has at least 2 bad and 2 good fixtures", () => {
    expect(bad.length).toBeGreaterThanOrEqual(2);
    expect(good.length).toBeGreaterThanOrEqual(2);
  });

  it.each(bad)("catches bad/%s", async (name) => {
    const result = await scan({ path: join(FIXTURES, id, "bad", name), config: DEFAULT_CONFIG, rules: [rule] });
    expect(result.targets.length).toBeGreaterThan(0);
    const min = Math.min(severityRank("medium"), severityRank(rule.severity));
    const serious = result.findings.filter((f) => severityRank(f.severity) >= min);
    expect(serious, JSON.stringify(result.findings, null, 2)).not.toHaveLength(0);
  });

  it.each(good)("stays quiet on good/%s", async (name) => {
    const result = await scan({ path: join(FIXTURES, id, "good", name), config: DEFAULT_CONFIG, rules: [rule] });
    expect(result.targets.length).toBeGreaterThan(0);
    const noisy = result.findings.filter((f) => f.severity !== "info");
    expect(noisy, JSON.stringify(noisy, null, 2)).toEqual([]);
  });
});
