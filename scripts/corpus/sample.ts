// Precision check: draw a reproducible random sample of findings from a scanned corpus, with the lines around each
// one, for labelling by hand; then report the share that point at a genuinely dangerous pattern, with a 95 % interval.
// The context is read at the scanned commit from raw.githubusercontent.com (checkouts may be gone after a pipeline
// run), kept only in the sample file, with secrets masked and invisible characters escaped. Nothing is executed.
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --severity high --n 100 --seed 1 --name high-1
//   (label: set each item's "label" in labels/high-1.json to malicious | dangerous | offensive | benign | unclear)
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --report high-1
// Per repository: --per-repo draws repositories with a finding of that severity, then one finding from each, so a few
// huge collections don't make up most of the sample.
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --severity high --per-repo --n 100 --seed 1 --name high-repo-1
// Second rater: a blind subsample of a labelled sample (no labels or notes copied), then agreement and Cohen's κ.
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --from high-1 --n 20 --seed 2 --name high-1-blind
//   npx tsx scripts/corpus/sample.ts --dir ~/corpus --agree high-1 --with high-1-blind
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { redactSecrets as redactConfigSecrets } from "../../src/rules/json-config.js";
import { redactSecrets } from "../../src/rules/SW016-secret-in-config.js";
import { escapeInvisible } from "../../src/text.js";
import { SEVERITIES, isSeverity } from "../../src/types.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import { cohenKappa, contextLines, pool, sampleIndices, wilson, type ReportFinding, type ScanReport } from "./lib.js";

const LABELS = ["malicious", "dangerous", "offensive", "benign", "unclear"] as const;
type Label = (typeof LABELS)[number];
/** Labels that count as a correct high finding: the pattern is genuinely dangerous, whatever the author's intent. */
const TRUE_POSITIVE: Label[] = ["malicious", "dangerous", "offensive"];
const isTrue = (l: Label) => TRUE_POSITIVE.includes(l);

interface SampleItem {
  id: number;
  /** In a blind subsample: the item's id in the sample it was drawn from. */
  sourceId?: number;
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
  /** What was drawn at random: findings, or repositories (one finding each). Older samples have no unit: findings. */
  unit?: "finding" | "repo";
  /** A blind subsample: the sample it was drawn from. */
  from?: string;
  population: number;
  repos: number;
  items: SampleItem[];
}

const { dir, values } = corpusArgs({
  severity: { type: "string", default: "high" },
  "per-repo": { type: "boolean", default: false },
  n: { type: "string", default: "100" },
  seed: { type: "string", default: "1" },
  name: { type: "string" },
  radius: { type: "string", default: "8" },
  report: { type: "string" },
  from: { type: "string" },
  agree: { type: "string" },
  with: { type: "string" },
});
const p = paths(dir);
const labelsDir = join(dir, "labels");

const clean = (s: string) => escapeInvisible(redactConfigSecrets(redactSecrets(s)));
const pct = (x: number) => `${(100 * x).toFixed(1)} %`;
const readSample = (name: string) => readJson<SampleFile>(join(labelsDir, `${name}.json`));

// A readable copy for labelling. Quoted content stays inside fences, with fence markers in it defused.
const fence = (s: string) => s.replace(/~~~/g, "~ ~~");
async function writeSample(sample: SampleFile): Promise<void> {
  await writeJson(join(labelsDir, `${sample.name}.json`), sample);
  const md = [
    `# ${sample.name}: ${sample.items.length} random ${sample.severity} findings${sample.unit === "repo" ? ", one per random repository" : ""}${sample.from ? ` (blind subsample of ${sample.from})` : ""}`,
    "",
    `Population: ${sample.population} ${sample.severity} findings in ${sample.repos} repositories; drawn by ${sample.unit ?? "finding"}; seed ${sample.seed}; ${sample.tool}.`,
    `Label each item in ${sample.name}.json: ${LABELS.join(" | ")}.`,
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
  for (const item of sample.items) {
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
  await writeFile(join(labelsDir, `${sample.name}.md`), md.join("\n"));
}

if (values.report) {
  const sample = await readSample(values.report as string);
  const counts = Object.fromEntries([...LABELS, "unlabelled"].map((l) => [l, 0])) as Record<Label | "unlabelled", number>;
  const byRule = new Map<string, { tp: number; fp: number; unclear: number }>();
  for (const item of sample.items) {
    if (item.label && !LABELS.includes(item.label)) throw new Error(`item ${item.id}: unknown label "${item.label}"`);
    counts[item.label ?? "unlabelled"]++;
    const r = byRule.get(item.ruleId) ?? { tp: 0, fp: 0, unclear: 0 };
    if (item.label && isTrue(item.label)) r.tp++;
    else if (item.label === "benign") r.fp++;
    else r.unclear++;
    byRule.set(item.ruleId, r);
  }
  const tp = TRUE_POSITIVE.reduce((n, l) => n + counts[l], 0);
  const decided = tp + counts.benign;
  const ci = wilson(tp, decided);
  console.log(`${sample.name}: ${sample.items.length} ${sample.severity} findings of ${sample.population} (seed ${sample.seed}, ${sample.tool})`);
  console.log(`labels: ${LABELS.map((l) => `${l} ${counts[l]}`).join(", ")}, unlabelled ${counts.unlabelled}`);
  console.log(`precision: ${tp}/${decided} = ${pct(ci.p)} (95 % CI ${pct(ci.low)}–${pct(ci.high)}), unclear and unlabelled left out`);
  // Vendored copies of one file count once per copy above; count each distinct rule + snippet once as well.
  const distinct = new Map<string, Label>();
  for (const item of sample.items) if (item.label && item.label !== "unclear") distinct.set(item.copyKey, item.label);
  const dtp = [...distinct.values()].filter(isTrue).length;
  const dci = wilson(dtp, distinct.size);
  console.log(`distinct content: ${dtp}/${distinct.size} = ${pct(dci.p)} (95 % CI ${pct(dci.low)}–${pct(dci.high)})`);
  console.log("by rule (true / false / unclear or unlabelled):");
  for (const [rule, r] of [...byRule].sort()) console.log(`  ${rule}  ${r.tp} / ${r.fp} / ${r.unclear}`);
  process.exit(0);
}

if (values.from) {
  const source = await readSample(values.from as string);
  const seed = Number(values.seed);
  const name = (values.name as string | undefined) ?? `${source.name}-blind`;
  // Only what the first rater saw before labelling: no labels, no notes.
  const items = sampleIndices(source.items.length, Number(values.n), seed).map((i, k): SampleItem => {
    const item = source.items[i]!;
    return { ...item, id: k + 1, sourceId: item.id, label: null, note: "" };
  });
  await writeSample({ ...source, name, createdAt: new Date().toISOString(), seed, from: source.name, items });
  console.error(`${name}: ${items.length} of ${source.items.length} items of ${source.name}, labels blank → ${join(labelsDir, `${name}.md`)}`);
  process.exit(0);
}

if (values.agree) {
  if (!values.with) throw new Error("--agree <sample> needs --with <blind subsample>");
  const first = await readSample(values.agree as string);
  const second = await readSample(values.with as string);
  if (second.from !== first.name) throw new Error(`${second.name} is not a subsample of ${first.name}`);
  const byId = new Map(first.items.map((i) => [i.id, i]));
  const pairs: { id: number; ruleId: string; a: Label; b: Label }[] = [];
  for (const item of second.items) {
    const a = byId.get(item.sourceId ?? -1)?.label;
    if (a && item.label) pairs.push({ id: item.sourceId!, ruleId: item.ruleId, a, b: item.label });
  }
  const all = cohenKappa(pairs.map((x): [Label, Label] => [x.a, x.b]));
  // The true/false split leaves out pairs where either rater said "unclear", as the precision figure does.
  const decided = pairs.filter((x) => x.a !== "unclear" && x.b !== "unclear");
  const split = cohenKappa(decided.map((x): [boolean, boolean] => [isTrue(x.a), isTrue(x.b)]));
  const missing = second.items.length - pairs.length;
  console.log(`${first.name} vs ${second.name}: ${pairs.length} items labelled by both${missing ? `, ${missing} not` : ""}`);
  console.log(`five labels: agreement ${pct(all.agreement)}, κ ${all.kappa.toFixed(2)}`);
  console.log(`true / false (${decided.length} items without "unclear"): agreement ${pct(split.agreement)}, κ ${split.kappa.toFixed(2)}`);
  const differ = pairs.filter((x) => x.a !== x.b);
  if (differ.length) console.log("disagreements (id in the first sample, rule, first → second):");
  for (const x of differ) console.log(`  ${x.id}  ${x.ruleId}  ${x.a} → ${x.b}`);
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

const perRepo = values["per-repo"] as boolean;
// Per repository: repositories in result-file order, then one finding of each, drawn with a seed of its own.
const byRepo = new Map<string, typeof population>();
for (const x of population) {
  const list = byRepo.get(x.repo);
  if (list) list.push(x);
  else byRepo.set(x.repo, [x]);
}
const repoList = [...byRepo.values()];
const picked = perRepo
  ? sampleIndices(repoList.length, n, seed).map((i) => {
      const findings = repoList[i]!;
      return findings[sampleIndices(findings.length, 1, seed * 100_003 + i)[0]!]!;
    })
  : sampleIndices(population.length, n, seed).map((i) => population[i]!);
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

await writeSample({
  name,
  createdAt: new Date().toISOString(),
  tool: `skillward ${[...versions][0] ?? "unknown"}`,
  severity,
  seed,
  unit: perRepo ? "repo" : "finding",
  population: population.length,
  repos: repos.size,
  items,
});
const missing = items.filter((i) => !i.context).length;
console.error(`${name}: ${items.length} of ${population.length} ${severity} findings → ${join(labelsDir, `${name}.md`)}${missing ? ` (${missing} without context)` : ""}`);
