import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import type { ScanResult } from "../engine/index.js";
import type { SuppressedFinding } from "../engine/suppressions.js";
import { ALL_RULES } from "../rules/index.js";
import type { Finding, Severity } from "../types.js";
import { VERSION } from "../version.js";
import type { Reporter } from "./types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub code scanning maps this to critical/high/medium/low. */
const SECURITY_SEVERITY: Record<Severity, string> = { high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

const SRCROOT = "%SRCROOT%";

export interface SarifOptions {
  /** Base directory for relative URIs; GitHub expects paths relative to the repository root (the CI cwd). */
  cwd?: string;
}

/** SARIF 2.1.0, as accepted by GitHub code scanning (`github/codeql-action/upload-sarif`). */
export function sarifReport(result: ScanResult, options: SarifOptions = {}): object {
  const cwd = resolve(options.cwd ?? process.cwd());
  const ruleIndex = new Map(ALL_RULES.map((r, i) => [r.id, i]));

  const location = (f: Finding) => {
    const abs = f.file.startsWith("~/") ? join(result.homeDir, f.file.slice(2)) : resolve(result.root, f.file);
    const rel = relative(cwd, abs);
    const inside = rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
    const artifactLocation = inside
      ? { uri: rel.split(sep).map(encodeURIComponent).join("/"), uriBaseId: SRCROOT }
      : { uri: pathToFileURL(abs).href };
    return {
      physicalLocation: {
        artifactLocation,
        region: {
          startLine: f.line,
          ...(f.column ? { startColumn: f.column } : {}),
          ...(f.snippet ? { snippet: { text: f.snippet } } : {}),
        },
      },
    };
  };

  const known = new Set<Finding>(result.baseline?.findings);
  const toResult = (f: Finding | SuppressedFinding) => {
    const loc = location(f);
    const fingerprint = createHash("sha256")
      .update(`${f.ruleId}\0${loc.physicalLocation.artifactLocation.uri}\0${f.snippet}`)
      .digest("hex");
    const suppression = "suppression" in f ? f.suppression : undefined;
    return {
      ruleId: f.ruleId,
      ...(ruleIndex.has(f.ruleId) ? { ruleIndex: ruleIndex.get(f.ruleId) } : {}),
      level: LEVEL[f.severity],
      message: { text: f.message },
      locations: [loc],
      partialFingerprints: { "skillward/v1": fingerprint },
      properties: { severity: f.severity, confidence: f.confidence },
      ...(result.baseline && !suppression ? { baselineState: known.has(f) ? "unchanged" : "new" } : {}),
      ...(suppression
        ? { suppressions: [{ kind: "inSource", ...(suppression.reason ? { justification: suppression.reason } : {}) }] }
        : known.has(f)
          ? { suppressions: [{ kind: "external", justification: "in the skillward baseline" }] }
          : {}),
    };
  };

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "skillward",
            version: VERSION,
            semanticVersion: VERSION,
            informationUri: "https://www.npmjs.com/package/skillward",
            rules: ALL_RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.name },
              fullDescription: { text: r.description },
              help: { text: r.description },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                tags: ["security", "ai-agents"],
                precision: "medium",
                "security-severity": SECURITY_SEVERITY[r.severity],
              },
            })),
          },
        },
        originalUriBaseIds: { [SRCROOT]: { uri: pathToFileURL(cwd + sep).href } },
        columnKind: "utf16CodeUnits",
        invocations: [
          {
            executionSuccessful: result.errors.length === 0,
            toolExecutionNotifications: result.errors.map((e) => ({
              level: "error",
              message: { text: `${e.ruleId ? `${e.ruleId} ` : ""}failed on ${e.path}: ${e.message}` },
            })),
          },
        ],
        results: [...result.findings, ...(result.baseline?.findings ?? []), ...result.suppressed].map(toResult),
      },
    ],
  };
}

export const sarifReporter: Reporter = ({ result }) => JSON.stringify(sarifReport(result), null, 2) + "\n";
