import { jsonReporter } from "./json.js";
import { sarifReporter } from "./sarif.js";
import { textReporter } from "./text.js";
import type { Reporter } from "./types.js";

export type ReportFormat = "text" | "json" | "sarif";

export const REPORTERS: Record<ReportFormat, Reporter> = {
  text: textReporter,
  json: jsonReporter,
  sarif: sarifReporter,
};

export type { Reporter, ReportContext } from "./types.js";
