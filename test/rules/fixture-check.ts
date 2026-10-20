import { readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config/index.js";
import { scan } from "../../src/engine/index.js";
import { severityRank, type Rule } from "../../src/types.js";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");

/** Same contract as test/fixtures.test.ts, for a rule that is not registered yet. */
export function fixtureChecks(rule: Rule): void {
  const list = (kind: string) => readdirSync(join(FIXTURES, rule.id, kind)).sort();

  it.each(list("bad"))(`${rule.id} catches bad/%s`, async (name) => {
    const result = await scan({ path: join(FIXTURES, rule.id, "bad", name), config: DEFAULT_CONFIG, rules: [rule] });
    const min = Math.min(severityRank("medium"), severityRank(rule.severity));
    const serious = result.findings.filter((f) => severityRank(f.severity) >= min);
    expect(serious, JSON.stringify(result.findings, null, 2)).not.toHaveLength(0);
  });

  it.each(list("good"))(`${rule.id} stays quiet on good/%s`, async (name) => {
    const result = await scan({ path: join(FIXTURES, rule.id, "good", name), config: DEFAULT_CONFIG, rules: [rule] });
    expect(result.targets.length).toBeGreaterThan(0);
    const noisy = result.findings.filter((f) => f.severity !== "info");
    expect(noisy, JSON.stringify(noisy, null, 2)).toEqual([]);
  });
}
