// Precision check: draw a reproducible random sample of findings from a scanned corpus, with the lines around each
// one, for labelling by hand; then report the share that point at a genuinely dangerous pattern, with a 95 % interval.
// The context is read at the scanned commit from raw.githubusercontent.com (checkouts may be gone after a pipeline
// run), kept only in the sample file, with secrets masked and invisible characters escaped. Nothing is executed.
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --severity high --n 100 --seed 1 --name high-1
//   (label: set each item's "label" in labels/high-1.json to malicious | dangerous | offensive | benign | unclear)
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --report high-1
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { redactSecrets as redactConfigSecrets } from "../../src/rules/json-config.js";
import { redactSecrets } from "../../src/rules/SW016-secret-in-config.js";
import { escapeInvisible } from "../../src/text.js";
import { SEVERITIES, isSeverity } from "../../src/types.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import { contextLines, pool, sampleIndices, wilson, type ReportFinding, type ScanReport } from "./lib.js";

const LABELS = ["malicious", "dangerous", "offensive", "benign", "unclear"] as const;
type Label = (typeof LABELS)[number];
/** Labels that count as a correct high finding: the pattern is genuinely dangerous, whatever the author's intent. */
const TRUE_POSITIVE: Label[] = ["malicious", "dangerous", "offensive"];

interface SampleItem {
  id: number;
  repo: string;
  sha: string;
  file: string;
  line: number;
  ruleId: string;
  severity: string;
  confidence: string;
  message: string;
  snippet: string;
  /** Findings in the whole population with the same rule and snippet: vendored copies of the same content. */
  copies: number;
  copyKey: string;
  context: { n: number; text: string }[] | null;
  contextError?: string;
  label: Label | null;
  note: string;
}

interface SampleFile {
  name: string;
  createdAt: string;
  /** The scanner version that produced the results (not the checkout running this script). */
  tool: string;
  severity: string;
  seed: number;
  population: number;
  repos: number;
  items: SampleItem[];
}

const { dir, values } = corpusArgs({
  severity: { type: "string", default: "high" },
  n: { type: "string", default: "100" },
  seed: { type: "string", default: "1" },
  name: { type: "string" },
  radius: { type: "string", default: "8" },
  report: { type: "string" },
});
const p = paths(dir);
const labelsDir = join(dir, "labels");

const clean = (s: string) => escapeInvisible(redactConfigSecrets(redactSecrets(s)));

if (values.report) {
  const sample = await readJson<SampleFile>(join(labelsDir, `${values.report}.json`));
  const counts = Object.fromEntries([...LABELS, "unlabelled"].map((l) => [l, 0])) as Record<Label | "unlabelled", number>;
  const byRule = new Map<string, { tp: number; fp: number; unclear: number }>();
  for (const item of sample.items) {
    if (item.label && !LABELS.includes(item.label)) throw new Error(`item ${item.id}: unknown label "${item.label}"`);
    counts[item.label ?? "unlabelled"]++;
    const r = byRule.get(item.ruleId) ?? { tp: 0, fp: 0, unclear: 0 };
    if (item.label && TRUE_POSITIVE.includes(item.label)) r.tp++;
    else if (item.label === "benign") r.fp++;
    else r.unclear++;
    byRule.set(item.ruleId, r);
  }
  const tp = TRUE_POSITIVE.reduce((n, l) => n + counts[l], 0);
  const decided = tp + counts.benign;
  const ci = wilson(tp, decided);
  const pct = (x: number) => `${(100 * x).toFixed(1)} %`;
  console.log(`${sample.name}: ${sample.items.length} ${sample.severity} findings of ${sample.population} (seed ${sample.seed}, ${sample.tool})`);
  console.log(`labels: ${LABELS.map((l) => `${l} ${counts[l]}`).join(", ")}, unlabelled ${counts.unlabelled}`);
  console.log(`precision: ${tp}/${decided} = ${pct(ci.p)} (95 % CI ${pct(ci.low)}–${pct(ci.high)}), unclear and unlabelled left out`);
  // Vendored copies of one file count once per copy above; count each distinct rule + snippet once as well.
  const distinct = new Map<string, Label>();
  for (const item of sample.items) if (item.label && item.label !== "unclear") distinct.set(item.copyKey, item.label);
  const dtp = [...distinct.values()].filter((l) => TRUE_POSITIVE.includes(l)).length;
  const dci = wilson(dtp, distinct.size);
  console.log(`distinct content: ${dtp}/${distinct.size} = ${pct(dci.p)} (95 % CI ${pct(dci.low)}–${pct(dci.high)})`);
  console.log("by rule (true / false / unclear or unlabelled):");
  for (const [rule, r] of [...byRule].sort()) console.log(`  ${rule}  ${r.tp} / ${r.fp} / ${r.unclear}`);
  process.exit(0);
}

const severity = values.severity as string;
if (!isSeverity(severity)) throw new Error(`--severity must be one of ${SEVERITIES.join(", ")}`);
const name = (values.name as string | undefined) ?? `${severity}-${values.seed}`;
const n = Number(values.n);
const seed = Number(values.seed);
const radius = Number(values.radius);

// The population: every finding of this severity, in a stable order (results sorted by file name).
const population: { repo: string; sha: string; finding: ReportFinding }[] = [];
const repos = new Set<string>();
const versions = new Set<string>();
for (const f of (await readdir(p.results)).filter((x) => x.endsWith(".json")).sort()) {
  const report = await readJson<ScanReport & { repo: string; sha: string; tool?: { version: string } }>(join(p.results, f));
  versions.add(report.tool?.version ?? "unknown");
  for (const finding of report.findings) {
    if (finding.severity !== severity) continue;
    population.push({ repo: report.repo, sha: report.sha, finding });
    repos.add(report.repo);
  }
}
// A precision figure must name one scanner version; results from several versions are a partial rescan.
if (versions.size > 1) throw new Error(`results come from several skillward versions (${[...versions].join(", ")}); rescan first`);
const copyKey = (f: ReportFinding) => `${f.ruleId}\0${f.snippet}`;
const copies = new Map<string, number>();
for (const { finding } of population) copies.set(copyKey(finding), (copies.get(copyKey(finding)) ?? 0) + 1);

const picked = sampleIndices(population.length, n, seed).map((i) => population[i]!);
const files = new Map<string, Promise<string>>();
const rawUrl = (repo: string, sha: string, file: string) =>
  `https://raw.githubusercontent.com/${repo}/${sha}/${file.split("/").map(encodeURIComponent).join("/")}`;
async function fileText(repo: string, sha: string, file: string): Promise<string> {
  const res = await fetch(rawUrl(repo, sha, file), { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > 5_000_000) throw new Error("file over 5 MB");
  return text;
}

const items: SampleItem[] = picked.map(({ repo, sha, finding }, id) => ({
  id: id + 1,
  repo,
  sha,
  file: finding.file,
  line: finding.line,
  ruleId: finding.ruleId,
  severity: finding.severity,
  confidence: finding.confidence,
  message: finding.message,
  snippet: finding.snippet,
  copies: copies.get(copyKey(finding)) ?? 1,
  copyKey: copyKey(finding),
  context: null,
  label: null,
  note: "",
}));
await pool(items, 6, async (item) => {
  const key = `${item.repo}@${item.sha}:${item.file}`;
  if (!files.has(key)) files.set(key, fileText(item.repo, item.sha, item.file));
  try {
    item.context = contextLines(await files.get(key)!, item.line, radius).map((l) => ({ n: l.n, text: clean(l.text) }));
  } catch (err) {
    item.contextError = (err as Error).message;
  }
});

const sample: SampleFile = {
  name,
  createdAt: new Date().toISOString(),
  tool: `skillward ${[...versions][0] ?? "unknown"}`,
  severity,
  seed,
  population: population.length,
  repos: repos.size,
  items,
};
await writeJson(join(labelsDir, `${name}.json`), sample);

// A readable copy for labelling. Quoted content stays inside fences, with fence markers in it defused.
const fence = (s: string) => s.replace(/~~~/g, "~ ~~");
const md = [
  `# ${name}: ${items.length} random ${severity} findings`,
  "",
  `Population: ${population.length} ${severity} findings in ${repos.size} repositories; seed ${seed}; ${sample.tool}.`,
  `Label each item in ${name}.json: ${LABELS.join(" | ")}.`,
  "",
  "- **malicious**: built to harm the user (exfiltration, a payload, concealment of what it does).",
  "- **dangerous**: an honest instruction an agent would carry out that puts the user at real risk (piping a download",
  "  into a shell, reading or sending credentials, turning approvals off, persistence) — what a high finding is for.",
  "- **offensive**: security tooling whose purpose is attack techniques (pentest, red team); dangerous by design.",
  "- **benign**: the flagged text is not an instruction to do the dangerous thing (a warning, a detector, an example,",
  "  documentation of a fixed bug) or the action is harmless in context — a false positive at this severity.",
  "- **unclear**: the context is not enough to decide; left out of the precision figure.",
  "",
];
for (const item of items) {
  md.push(
    `## ${item.id}. ${item.ruleId} ${item.severity}/${item.confidence} — ${item.repo}`,
    "",
    `\`${clean(item.file).replace(/`/g, "'")}:${item.line}\` @ ${item.sha.slice(0, 12)}${item.copies > 1 ? ` — ${item.copies} copies in the corpus` : ""}`,
    "",
    `> ${clean(item.message)}`,
    "",
    "~~~",
    ...(item.context
      ? item.context.map((l) => `${l.n === item.line ? ">" : " "}${String(l.n).padStart(5)} | ${fence(l.text)}`)
      : [`(no context: ${item.contextError}) snippet: ${fence(clean(item.snippet))}`]),
    "~~~",
    "",
  );
}
await writeFile(join(labelsDir, `${name}.md`), md.join("\n"));
const missing = items.filter((i) => !i.context).length;
console.error(`${name}: ${items.length} of ${population.length} ${severity} findings → ${join(labelsDir, `${name}.md`)}${missing ? ` (${missing} without context)` : ""}`);
