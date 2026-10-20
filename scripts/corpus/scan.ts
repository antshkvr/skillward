// Step 3: scan every fetched repo in-process and aggregate. Audit settings: repo configs and inline
// `skillward-ignore` comments are not honoured, so a repository cannot hide its own findings.
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../../src/config/index.js";
import { scan } from "../../src/engine/index.js";
import { jsonReport } from "../../src/reporters/json.js";
import { isSeverity } from "../../src/types.js";
import { VERSION } from "../../src/version.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import type { FetchMeta } from "./fetch.js";
import { renderReview, renderSummary, repoDirName, summarize, type RepoReport, type ScanReport } from "./lib.js";

const { dir, values } = corpusArgs({
  review: { type: "string", default: "medium" },
  rescan: { type: "boolean", default: false },
  // `--shard 1/3`: scan every third repo only and skip the summary; run shards in parallel, then once without.
  shard: { type: "string" },
});
const p = paths(dir);
const review = values.review as string;
if (!isSeverity(review)) throw new Error(`--review must be a severity, got ${review}`);

const AUDIT_CONFIG: Config = { ignore: [], rules: {}, inlineIgnore: false };

const metas = await Promise.all(
  (await readdir(p.meta)).filter((f) => f.endsWith(".json")).map((f) => readJson<FetchMeta>(join(p.meta, f))),
);
const shard = values.shard ? (values.shard as string).split("/").map(Number) : undefined;
if (shard && !(shard.length === 2 && shard[0]! >= 1 && shard[0]! <= shard[1]!)) throw new Error("--shard must look like 1/3");
const fetched = metas
  .filter((m) => m.status === "ok")
  .sort((a, b) => (a.repo < b.repo ? -1 : 1))
  .filter((_, index) => !shard || index % shard[1]! === shard[0]! - 1);

const reports: RepoReport[] = [];
let i = 0;
for (const meta of fetched) {
  i++;
  const resultPath = join(p.results, `${repoDirName(meta.repo)}.json`);
  let report: ScanReport | undefined;
  if (!values.rescan) report = await readJson<ScanReport & { sha?: string }>(resultPath).then((r) => (r.sha === meta.sha ? r : undefined), () => undefined);
  if (!report) {
    const started = Date.now();
    const result = await scan({ path: join(p.checkouts, repoDirName(meta.repo)), config: AUDIT_CONFIG });
    const scanMs = Date.now() - started;
    report = { ...jsonReport({ result, failOn: "high", color: false }), repo: meta.repo, sha: meta.sha, scanMs } as unknown as ScanReport;
    await writeJson(resultPath, report);
    console.error(`[${i}/${fetched.length}] ${meta.repo}: ${report.findings.length} findings (${scanMs} ms)`);
  }
  reports.push({ repo: meta.repo, sha: meta.sha!, report });
}

if (shard) process.exit(0);

const summary = summarize(reports, { noisiest: 30 });
const generatedAt = new Date().toISOString();
const fetchCounts = { ok: 0, empty: 0, error: 0 };
for (const m of metas) fetchCounts[m.status]++;
await writeJson(join(dir, "summary.json"), { generatedAt, tool: `skillward ${VERSION}`, fetch: fetchCounts, ...summary });
await writeFile(
  join(dir, "summary.md"),
  renderSummary(summary, { generatedAt, tool: `skillward ${VERSION}` }) +
    `\nFetched: ${fetchCounts.ok} with agent files, ${fetchCounts.empty} without, ${fetchCounts.error} failed.\n`,
);
await writeFile(join(dir, `review-${review}.md`), renderReview(reports, review));
console.error(`summary: ${summary.findings} findings in ${summary.repos} repos → ${join(dir, "summary.md")}`);
