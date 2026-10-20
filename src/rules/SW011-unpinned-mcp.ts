import { member } from "../parsers/json-tree.js";
import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { findingAt } from "./helpers.js";
import { mcpServers, redactSecrets, stringValue, type McpServer } from "./json-config.js";

const rule: Rule = {
  id: "SW011",
  name: "unpinned-mcp",
  severity: "medium",
  appliesTo: ["mcp-config", "settings", "plugin-manifest"],
  description:
    "MCP servers started through npx/bunx/pnpm dlx/yarn dlx/uvx/pipx run/docker run without a pinned version (no version, @latest, a range, or a mutable image tag). Every start can pull new, unreviewed code.",
  check(target) {
    return target.files.flatMap((file) => (file.type === "json" ? checkFile(file) : []));
  },
};

export default rule;

interface Arg {
  value: string;
  offset: number;
}

type Ecosystem = "npm" | "python" | "docker";

interface Launch {
  launcher: string;
  ecosystem: Ecosystem;
  spec?: Arg;
}

interface Verdict {
  severity: Severity;
  confidence: Confidence;
  problem: string;
  fix: string;
}

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const server of mcpServers(file)) {
    const launch = analyze(server);
    if (!launch?.spec) continue;
    const verdict = judge(launch);
    if (!verdict) continue;
    const where = server.project ? ` (project ${server.project})` : "";
    const finding = findingAt(rule, file, {
      offset: launch.spec.offset,
      length: launch.spec.value.length + 2,
      severity: verdict.severity,
      confidence: verdict.confidence,
      message: `MCP server "${server.name}"${where} runs ${launch.spec.value} via ${launch.launcher} ${verdict.problem}. Each start can fetch different code. ${verdict.fix}`,
    });
    findings.push({ ...finding, snippet: redactSecrets(finding.snippet) });
  }
  return findings;
}

/** Splits `command` + `args` into tokens with offsets; handles `cmd /c npx …` and a command string with spaces. */
function tokens(server: McpServer): Arg[] {
  const command = member(server.config, "command");
  const commandValue = stringValue(command);
  if (!command || commandValue === undefined) return [];
  const result: Arg[] = [];
  const args = member(server.config, "args");
  if (args?.kind === "array") {
    result.push({ value: commandValue, offset: command.start });
    for (const item of args.items) {
      if (item.kind === "string") result.push({ value: item.value as string, offset: item.start });
    }
  } else {
    // "command": "npx -y some-server" — split on whitespace, offsets inside the string literal.
    for (const m of commandValue.matchAll(/\S+/g)) result.push({ value: m[0], offset: command.start + 1 + m.index });
  }
  const first = baseName(result[0]?.value ?? "");
  if ((first === "cmd" || first === "cmd.exe") && /^\/[cC]$/.test(result[1]?.value ?? "")) result.splice(0, 2);
  return result;
}

function baseName(path: string): string {
  return path
    .split(/[\\/]/)
    .pop()!
    .replace(/\.(cmd|exe|ps1)$/i, "")
    .toLowerCase();
}

function analyze(server: McpServer): Launch | undefined {
  const all = tokens(server);
  if (all.length === 0) return undefined;
  const cmd = baseName(all[0]!.value);
  const sub = all[1]?.value;

  if (cmd === "npx" || cmd === "bunx") return { launcher: cmd, ecosystem: "npm", spec: npmSpec(all.slice(1)) };
  if ((cmd === "pnpm" || cmd === "yarn") && sub === "dlx") return { launcher: `${cmd} dlx`, ecosystem: "npm", spec: npmSpec(all.slice(2)) };
  if (cmd === "bun" && sub === "x") return { launcher: "bun x", ecosystem: "npm", spec: npmSpec(all.slice(2)) };
  if (cmd === "npm" && (sub === "exec" || sub === "x")) return { launcher: `npm ${sub}`, ecosystem: "npm", spec: npmSpec(all.slice(2)) };
  if (cmd === "uvx" || (cmd === "uv" && sub === "tool" && all[2]?.value === "run")) {
    return { launcher: "uvx", ecosystem: "python", spec: pythonSpec(all.slice(cmd === "uvx" ? 1 : 3), "--from") };
  }
  if (cmd === "pipx" && sub === "run") return { launcher: "pipx run", ecosystem: "python", spec: pythonSpec(all.slice(2), "--spec") };
  if ((cmd === "docker" || cmd === "podman") && sub === "run") return { launcher: `${cmd} run`, ecosystem: "docker", spec: dockerImage(all.slice(2)) };
  return undefined;
}

function npmSpec(args: Arg[]): Arg | undefined {
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (a.value === "--") return args[k + 1];
    if (a.value === "-p" || a.value === "--package") return args[k + 1];
    if (a.value.startsWith("--package=")) return { value: a.value.slice(10), offset: a.offset };
    if (a.value.startsWith("-")) continue; // -y, --yes, -q, --no-install, …
    return a;
  }
  return undefined;
}

function pythonSpec(args: Arg[], fromFlag: string): Arg | undefined {
  const withValue = new Set([fromFlag, "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--pip-args"]);
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (a.value === fromFlag) return args[k + 1];
    if (a.value.startsWith(fromFlag + "=")) return { value: a.value.slice(fromFlag.length + 1), offset: a.offset };
    if (withValue.has(a.value)) {
      k++;
      continue;
    }
    if (a.value.startsWith("-")) continue;
    return a;
  }
  return undefined;
}

const DOCKER_FLAGS_WITH_VALUE = new Set([
  "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net",
  "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label", "--cpus", "-m", "--memory",
  "--add-host", "--cap-add", "--cap-drop", "--security-opt", "--tmpfs", "--device", "-h", "--hostname", "--pull",
  "--ulimit", "--shm-size", "--log-driver", "--restart", "--gpus",
]);

function dockerImage(args: Arg[]): Arg | undefined {
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (DOCKER_FLAGS_WITH_VALUE.has(a.value)) {
      k++;
      continue;
    }
    if (a.value.startsWith("-")) continue;
    return a;
  }
  return undefined;
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/;
const LOCAL = /^(?:\.{1,2}[\\/]|[\\/]|~|[A-Za-z]:[\\/]|file:)/;
const PINNED_COMMIT = /#[0-9a-f]{40}$|@[0-9a-f]{40}$/i;

function judge(launch: Launch): Verdict | undefined {
  const spec = launch.spec!.value;
  if (LOCAL.test(spec) || spec.startsWith("$")) return undefined;

  if (/^(?:git\+|github:|gitlab:|bitbucket:|https?:)/.test(spec)) {
    if (PINNED_COMMIT.test(spec)) return undefined;
    return {
      severity: "medium",
      confidence: "high",
      problem: "from a git/URL source without a commit pin",
      fix: "Pin a full commit SHA or use a registry version.",
    };
  }

  if (launch.ecosystem === "docker") {
    if (/@sha256:[0-9a-f]{64}$/i.test(spec)) return undefined;
    const lastSlash = spec.lastIndexOf("/");
    const colon = spec.indexOf(":", lastSlash + 1);
    const tag = colon === -1 ? "" : spec.slice(colon + 1);
    if (tag === "" || tag === "latest") {
      return { severity: "medium", confidence: "high", problem: tag ? "with the :latest tag" : "without a tag", fix: "Pin an image digest (@sha256:…)." };
    }
    return { severity: "info", confidence: "medium", problem: `with the mutable tag :${tag}`, fix: "Tags can be re-pushed; pin a digest (@sha256:…) for immutability." };
  }

  if (launch.ecosystem === "python") {
    const m = /^([A-Za-z0-9][\w.-]*)(\[[^\]]*\])?(.*)$/.exec(spec);
    const rest = m?.[3] ?? "";
    if (/^(?:==|@)v?\d+(?:\.\d+)*(?:[\w.+-]*)$/.test(rest)) return undefined;
    if (rest === "" || /^@latest$/.test(rest)) {
      return { severity: "medium", confidence: "high", problem: "without a version", fix: `Pin an exact version (e.g. ${m?.[1] ?? spec}==1.2.3).` };
    }
    return { severity: "low", confidence: "high", problem: `with a version range (${rest})`, fix: "Pin an exact version (==)." };
  }

  // npm: name, name@version, @scope/name, @scope/name@version
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  const name = at === -1 ? spec : spec.slice(0, at);
  const version = at === -1 ? "" : spec.slice(at + 1);
  if (EXACT_SEMVER.test(version)) return undefined;
  if (version === "" || /^[a-z][\w-]*$/i.test(version)) {
    return {
      severity: "medium",
      confidence: "high",
      problem: version ? `with the moving tag @${version}` : "without a version",
      fix: `Pin an exact version (e.g. ${name}@1.2.3).`,
    };
  }
  return { severity: "low", confidence: "high", problem: `with a version range (@${version})`, fix: `Pin an exact version (e.g. ${name}@1.2.3).` };
}
