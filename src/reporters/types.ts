import type { ScanResult } from "../engine/index.js";
import type { ConfigInfo } from "./config-note.js";
import type { Severity } from "../types.js";

export interface ReportContext {
  result: ScanResult;
  failOn: Severity;
  /** Enable ANSI colors (text reporter only). */
  color: boolean;
  /** The config the scan used; reports say what it turned off. */
  config?: ConfigInfo;
}

export type Reporter = (ctx: ReportContext) => string;
