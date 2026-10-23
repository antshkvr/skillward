// Scans one fetched repository with audit settings: the repository's config and inline `skillward-ignore` comments
// are not honoured, so a repository cannot hide its own findings.
import type { Config } from "../../src/config/index.js";
import { scan } from "../../src/engine/index.js";
import { jsonReport } from "../../src/reporters/json.js";
import type { ScanReport } from "./lib.js";

const AUDIT_CONFIG: Config = { ignore: [], rules: {}, inlineIgnore: false };

export type StoredReport = ScanReport & { repo: string; sha?: string; scanMs: number };

export async function scanCheckout(checkout: string, meta: { repo: string; sha?: string }): Promise<StoredReport> {
  const started = Date.now();
  const result = await scan({ path: checkout, config: AUDIT_CONFIG });
  const scanMs = Date.now() - started;
  return { ...(jsonReport({ result, failOn: "high", color: false }) as unknown as ScanReport), repo: meta.repo, sha: meta.sha, scanMs };
}
