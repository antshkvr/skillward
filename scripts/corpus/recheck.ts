// Re-runs one rule on the corpus files where a rule reported findings, and compares severities before/after.
// For tuning a rule against real data without rescanning the whole corpus. Read-only: results/ is not touched.
//   npm run corpus:recheck -- --rule SW005 [--severity high] [--samples 20] [--grep pattern]
//   --on SW007 --on-grep paste   run SW010 on the files SW007 flagged for paste sites (a new signal's reach)
import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { Config } from "../../src/config/index.js";
import { scan } from "../../src/engine/index.js";
import { ALL_RULES } from "../../src/rules/index.js";
import { SEVERITIES, isSeverity, type Finding, type Severity } from "../../src/types.js";
import { corpusArgs, paths, readJson } from "./common.js";
import { pool, repoDirName, type ScanReport } from "./lib.js";

const { dir, values } = corpusArgs({
  rule: { type: "string" },
  on: { type: "string" },
  "on-grep": { type: "string" },
  severity: { type: "string", default: "high" },
  samples: { type: "string", default: "15" },
  grep: { type: "string" },
  concurrency: { type: "string", default: "4" },
});
const rule = ALL_RULES.find((r) => r.id === values.rule);
if (!rule) throw new Error(`--rule must be one of ${ALL_RULES.map((r) => r.id).join(", ")}`);
const source = (values.on as string | undefined) ?? rule.id;
const onGrep = values["on-grep"] ? new RegExp(values["on-grep"] as string, "i") : undefined;
const show = values.severity as string;
if (show !== "*" && !isSeverity(show)) throw new Error("--severity must be a severity or *");
const grep = values.grep ? new RegExp(values.grep as string, "i") : undefined;

const AUDIT_CONFIG: Config = { ignore: [], rules: {}, inlineIgnore: false };
const p = paths(dir);
const zero = () => Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
const before = zero();
const after = zero();
const samples = new Map<string, { n: number; ex: string[] }>();

const files = (await readdir(p.results)).filter((f) => f.endsWith(".json"));
await pool(files, Number(values.concurrency), async (f) => {
  const report = await readJson<ScanReport & { repo: string; root: string }>(join(p.results, f));
  const selected = report.findings.filter((x) => x.ruleId === source && (!onGrep || onGrep.test(x.message)));
  if (!selected.length) return;
  for (const x of report.findings) if (x.ruleId === rule.id && selected.some((s) => s.file === x.file)) before[x.severity]++;
  const root = join(p.checkouts, repoDirName(report.repo));
  const onlyFiles = new Set(selected.map((x) => resolve(root, x.file)));
  const result = await scan({ path: root, config: AUDIT_CONFIG, rules: [rule], onlyFiles });
  for (const x of result.findings as Finding[]) {
    after[x.severity]++;
    if (show !== "*" && x.severity !== show) continue;
    const line = `${report.repo}:${x.file}:${x.line}  ${x.snippet}`;
    if (grep && !grep.test(line + " " + x.message)) continue;
    const key = `${x.severity}/${x.confidence} ${x.message.replace(/"[^"]*"/g, '"…"').replace(/\(.*?\)/g, "(…)").slice(0, 110)}`;
    const g = samples.get(key) ?? { n: 0, ex: [] };
    g.n++;
    if (g.ex.length < 400) g.ex.push(line);
    samples.set(key, g);
  }
});

console.log(`${rule.id} on files ${source} flagged before${onGrep ? ` (${onGrep})` : ""}:`);
console.log(`  before: ${SEVERITIES.map((s) => `${s} ${before[s]}`).join(", ")}`);
console.log(`  after:  ${SEVERITIES.map((s) => `${s} ${after[s]}`).join(", ")}`);
const n = Number(values.samples);
for (const [key, g] of [...samples].sort((a, b) => b[1].n - a[1].n).slice(0, 10)) {
  console.log(`\n### ${g.n} ${key}`);
  // Spread samples over the list instead of showing the first repos alphabetically.
  const step = Math.max(1, Math.floor(g.ex.length / n));
  for (let i = 0, shown = 0; i < g.ex.length && shown < n; i += step, shown++) console.log("  " + g.ex[i]!.slice(0, 240));
}
