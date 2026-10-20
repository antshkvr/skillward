import type { ScanResult } from "../engine/index.js";
import type { Severity } from "../types.js";

export interface ReportContext {
  result: ScanResult;
  failOn: Severity;
  /** Enable ANSI colors (text reporter only). */
  color: boolean;
}

export type Reporter = (ctx: ReportContext) => string;
