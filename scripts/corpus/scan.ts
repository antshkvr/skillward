// Step 3: scan every fetched repo in-process (audit settings, see scan-repo.ts) and aggregate. Results that already
// match the fetched commit are reused, so after pipeline.ts this only writes the summary.
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { isSeverity } from "../../src/types.js";
import { VERSION } from "../../src/version.js";
import { corpusArgs, paths, readJson, writeJson } from "./common.js";
import type { FetchMeta } from "./fetch-repo.js";
import { scanCheckout } from "./scan-repo.js";
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
    const stored = await scanCheckout(join(p.checkouts, repoDirName(meta.repo)), meta);
    await writeJson(resultPath, stored);
    report = stored;
    console.error(`[${i}/${fetched.length}] ${meta.repo}: ${stored.findings.length} findings (${stored.scanMs} ms)`);
  }
  reports.push({ repo: meta.repo, sha: meta.sha!, report });
}

if (shard) process.exit(0);

const summary = summarize(reports, { noisiest: 30 });
const generatedAt = new Date().toISOString();
const fetchCounts = { ok: 0, empty: 0, error: 0, truncatedRepos: 0, truncatedFiles: 0, hookScripts: 0 };
for (const m of metas) {
  fetchCounts[m.status]++;
  if (m.truncated) fetchCounts.truncatedRepos++;
  fetchCounts.truncatedFiles += m.truncated ?? 0;
  fetchCounts.hookScripts += m.hookScripts ?? 0;
}
await writeJson(join(dir, "summary.json"), { generatedAt, tool: `skillward ${VERSION}`, fetch: fetchCounts, ...summary });
await writeFile(
  join(dir, "summary.md"),
  renderSummary(summary, { generatedAt, tool: `skillward ${VERSION}` }) +
    `\nFetched: ${fetchCounts.ok} with agent files, ${fetchCounts.empty} without, ${fetchCounts.error} failed; ` +
    `${fetchCounts.hookScripts} scripts named by hook commands; ${fetchCounts.truncatedRepos} repos over the file cap ` +
    `(${fetchCounts.truncatedFiles} files not fetched).\n`,
);
await writeFile(join(dir, `review-${review}.md`), renderReview(reports, review));
console.error(`summary: ${summary.findings} findings in ${summary.repos} repos → ${join(dir, "summary.md")}`);
