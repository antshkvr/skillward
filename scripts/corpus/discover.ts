// Step 1: build the list of candidate repositories (repos.json) from seeds, awesome lists and GitHub code search.
// Uses the GitHub API through `gh` (must be logged in); code search is throttled to its 10 requests/minute limit.
import { join } from "node:path";
import { corpusArgs, paths, readJson, REPO_ROOT, run, sleep, writeJson } from "./common.js";
import { isRepoName, parseRepoLinks, selectCandidates, type Candidate } from "./lib.js";

interface Sources {
  maxRepos: number;
  seeds: string[];
  lists: string[];
  searches: { q: string; sizes: string[] }[];
}

const SEARCH_INTERVAL_MS = 6_500;
const SEARCH_PAGES = 10; // code search returns at most 1000 results per query

const { dir, values } = corpusArgs({ sources: { type: "string" }, max: { type: "string" } });
const sources = await readJson<Sources>((values.sources as string | undefined) ?? join(REPO_ROOT, "scripts/corpus/sources.json"));
const max = values.max ? Number(values.max) : sources.maxRepos;

async function gh(args: string[]): Promise<string> {
  for (let attempt = 0; ; attempt++) {
    const res = await run("gh", ["api", ...args], { timeoutMs: 60_000 });
    if (res.code === 0) return res.stdout;
    const limited = /rate limit|secondary|abuse|HTTP 403|HTTP 429/i.test(res.stderr);
    if (!limited || attempt >= 4) throw new Error(`gh api ${args.join(" ")}: ${res.stderr.trim()}`);
    console.error(`  rate limited, waiting 65s…`);
    await sleep(65_000);
  }
}

const seeds: Candidate[] = sources.seeds.map((repo) => ({ repo, sources: ["seed"] }));

const listed: Candidate[] = [];
for (const list of sources.lists) {
  const readme = await gh([`repos/${list}/readme`, "-H", "Accept: application/vnd.github.raw"]);
  const repos = parseRepoLinks(readme).filter((r) => r.toLowerCase() !== list.toLowerCase());
  console.error(`list ${list}: ${repos.length} repos`);
  listed.push(...repos.map((repo) => ({ repo, sources: [`list:${list}`] })));
}

const searched: Candidate[] = [];
for (const search of sources.searches) {
  const buckets = search.sizes.length ? search.sizes.map((s) => `${search.q} size:${s}`) : [search.q];
  for (const q of buckets) {
    let found = 0;
    let total = 0;
    for (let page = 1; page <= SEARCH_PAGES; page++) {
      await sleep(SEARCH_INTERVAL_MS);
      const body = JSON.parse(
        await gh(["-X", "GET", "search/code", "-f", `q=${q}`, "-f", "per_page=100", "-f", `page=${page}`]),
      ) as { total_count: number; items: { repository: { full_name: string; fork: boolean } }[] };
      total = body.total_count;
      for (const item of body.items) {
        if (item.repository.fork || !isRepoName(item.repository.full_name)) continue;
        searched.push({ repo: item.repository.full_name, sources: [`search:${search.q}`] });
        found++;
      }
      if (body.items.length < 100 || page * 100 >= Math.min(total, 1000)) break;
    }
    console.error(`search "${q}": ${found} hits of ${total}`);
  }
}

const candidates = selectCandidates(
  [
    { priority: true, candidates: [...seeds, ...listed] },
    { priority: false, candidates: searched },
  ],
  max,
);
await writeJson(paths(dir).candidates, {
  generatedAt: new Date().toISOString(),
  maxRepos: max,
  sources,
  counts: { seeds: seeds.length, listed: listed.length, searchHits: searched.length, selected: candidates.length },
  candidates,
});
console.error(`wrote ${candidates.length} candidates to ${paths(dir).candidates}`);
