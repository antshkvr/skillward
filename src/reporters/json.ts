import { exitCodeFor } from "../engine/index.js";
import { SEVERITIES, type Severity } from "../types.js";
import { VERSION } from "../version.js";
import { configJson } from "./config-note.js";
import type { ReportContext, Reporter } from "./types.js";

/** Version of the JSON report format. Bump on breaking changes; adding fields is not breaking. */
export const JSON_REPORT_VERSION = 1;

/** The JSON report as an object (also embedded in the `verify` JSON report). */
export function jsonReport({ result, failOn, config }: ReportContext) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of result.findings) bySeverity[f.severity]++;
  return {
    version: JSON_REPORT_VERSION,
    tool: { name: "skillward", version: VERSION },
    root: result.root,
    ...(config ? { config: configJson(config) } : {}),
    summary: {
      targets: result.targets.length,
      files: result.targets.reduce((n, t) => n + t.files.length, 0),
      findings: result.findings.length,
      suppressed: result.suppressed.length,
      baselined: result.baseline?.findings.length ?? 0,
      ...(result.baseline ? { baselineStale: result.baseline.stale } : {}),
      bySeverity,
      failOn,
      failed: exitCodeFor(result.findings, failOn) === 1,
    },
    targets: result.targets,
    findings: result.findings,
    suppressed: result.suppressed,
    baselined: result.baseline?.findings ?? [],
    skipped: result.skipped,
    errors: result.errors,
  };
}

export const jsonReporter: Reporter = (ctx) => JSON.stringify(jsonReport(ctx), null, 2) + "\n";
