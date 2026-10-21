import { relative, sep } from "node:path";
import { createColors } from "picocolors";
import type { Config } from "../config/index.js";
import { escapeInvisible } from "../text.js";

/** Which config a scan used, so reports can say what it changed. */
export interface ConfigInfo {
  config: Config;
  /** Config file that was applied, if any. */
  path?: string;
  /** The applied config was found in the scanned folder (not passed with `--config`). */
  fromScannedFolder?: boolean;
  /** `--untrusted`: a config file in the scanned folder that was deliberately not read. */
  ignoredPath?: string;
  untrusted: boolean;
}

/**
 * A config can hide findings (rules off or downgraded, ignored paths). When it comes with the scanned folder it is
 * the scanned party's own choice, so reports always say what it changed instead of hiding it silently.
 */
export function configNotes(info: ConfigInfo | undefined, root: string, color: boolean): string[] {
  if (!info) return [];
  const c = createColors(color);
  const show = (p: string) => {
    const rel = relative(root, p);
    return escapeInvisible(rel && !rel.startsWith("..") ? rel.split(sep).join("/") : p);
  };
  if (info.ignoredPath) return [c.dim(`Not using ${show(info.ignoredPath)} from the scanned folder (--untrusted).`)];
  const changes = configChanges(info.config);
  if (!info.path || !changes.length) return [];
  const hint = info.fromScannedFolder ? " Pass --untrusted when scanning someone else's code." : "";
  return [c.dim(`Config ${show(info.path)}: ${changes.join("; ")}.${hint}`)];
}

/** What a config changes that can hide findings, in words. */
export function configChanges(config: Config): string[] {
  const off = Object.entries(config.rules).filter(([, v]) => v === "off").map(([id]) => id);
  const changed = Object.entries(config.rules).filter(([, v]) => v !== "off").map(([id, v]) => `${id} → ${v}`);
  const out: string[] = [];
  if (off.length) out.push(`turns off ${off.map(escapeInvisible).join(", ")}`);
  if (changed.length) out.push(`sets severity ${changed.map(escapeInvisible).join(", ")}`);
  if (config.ignore.length) out.push(`ignores ${config.ignore.map(escapeInvisible).join(", ")}`);
  return out;
}

/** The `config` section of JSON reports. */
export function configJson(info: ConfigInfo | undefined) {
  if (!info) return undefined;
  return {
    path: info.path ?? null,
    untrusted: info.untrusted,
    ...(info.ignoredPath ? { ignoredPath: info.ignoredPath } : {}),
    rules: info.config.rules,
    ignore: info.config.ignore,
    inlineIgnore: info.config.inlineIgnore !== false,
  };
}
