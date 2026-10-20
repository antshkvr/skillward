import { parseText } from "../src/parsers/index.js";
import type { Finding, Rule, TargetKind } from "../src/types.js";

/** Runs one rule over in-memory text, as if it were a single-file target. */
export function checkText(rule: Rule, text: string, path = "CLAUDE.md", kind: TargetKind = "instructions"): Finding[] {
  const file = parseText({ absPath: path, path }, text);
  return rule.check({ kind, path, files: [file] });
}
