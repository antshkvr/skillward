import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isSeverity, type Severity } from "../types.js";

export const CONFIG_FILE_NAME = "skillward.config.json";

export type RuleSetting = "off" | Severity;

export interface Config {
  /** gitignore-style patterns, relative to the scan root. */
  ignore: string[];
  /** Per-rule override: turn off or change severity. */
  rules: Record<string, RuleSetting>;
  failOn?: Severity;
  /** Honour inline `skillward-ignore` comments (default true). Turn off when auditing third-party skills. */
  inlineIgnore?: boolean;
}

export const DEFAULT_CONFIG: Config = { ignore: [], rules: {} };

export class ConfigError extends Error {}

/**
 * Loads `--config <file>` if given, otherwise `skillward.config.json` from the scan root if present.
 * The config is plain JSON — it is never executed.
 */
export async function loadConfig(options: { configPath?: string; root?: string }): Promise<{
  config: Config;
  path?: string;
}> {
  let path = options.configPath;
  let required = true;
  if (!path) {
    if (!options.root) return { config: DEFAULT_CONFIG };
    path = join(options.root, CONFIG_FILE_NAME);
    required = false;
  }

  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (!required && (err as NodeJS.ErrnoException).code === "ENOENT") return { config: DEFAULT_CONFIG };
    throw new ConfigError(`cannot read config ${path}: ${(err as Error).message}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(raw.replace(/^\uFEFF/, ""));
  } catch (err) {
    throw new ConfigError(`invalid JSON in ${path}: ${(err as Error).message}`);
  }
  return { config: validateConfig(data, path), path };
}

export function validateConfig(data: unknown, source = "config"): Config {
  const fail = (msg: string): never => {
    throw new ConfigError(`${source}: ${msg}`);
  };
  if (typeof data !== "object" || data === null || Array.isArray(data)) fail("must be a JSON object");
  const obj = data as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (!["ignore", "rules", "failOn", "inlineIgnore", "$schema"].includes(key)) fail(`unknown key "${key}"`);
  }

  const config: Config = { ignore: [], rules: {} };

  if (obj.ignore !== undefined) {
    if (!Array.isArray(obj.ignore) || !obj.ignore.every((p) => typeof p === "string")) {
      fail(`"ignore" must be an array of strings`);
    }
    config.ignore = obj.ignore as string[];
  }

  if (obj.rules !== undefined) {
    if (typeof obj.rules !== "object" || obj.rules === null || Array.isArray(obj.rules)) {
      fail(`"rules" must be an object like {"SW012": "off"}`);
    }
    for (const [id, value] of Object.entries(obj.rules as Record<string, unknown>)) {
      if (value !== "off" && !isSeverity(value)) {
        fail(`rule ${id}: expected "off", "info", "low", "medium" or "high", got ${JSON.stringify(value)}`);
      }
      config.rules[id] = value as RuleSetting;
    }
  }

  if (obj.failOn !== undefined) {
    if (!isSeverity(obj.failOn)) fail(`"failOn" must be one of info, low, medium, high`);
    config.failOn = obj.failOn as Severity;
  }

  if (obj.inlineIgnore !== undefined) {
    if (typeof obj.inlineIgnore !== "boolean") fail(`"inlineIgnore" must be true or false`);
    config.inlineIgnore = obj.inlineIgnore as boolean;
  }

  return config;
}
