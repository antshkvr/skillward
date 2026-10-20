import { describe, expect, it } from "vitest";
import rule from "../../src/rules/SW011-unpinned-mcp.js";
import { checkText } from "../helpers.js";
import { fixtureChecks } from "./fixture-check.js";

const mcp = (server: Record<string, unknown>) => JSON.stringify({ mcpServers: { s: server } }, null, 2);
const check = (server: Record<string, unknown>) => checkText(rule, mcp(server), ".mcp.json", "mcp-config");

describe("SW011 unpinned-mcp", () => {
  fixtureChecks(rule);

  it.each([
    [{ command: "npx", args: ["-y", "pkg"] }, "medium", "without a version"],
    [{ command: "npx", args: ["pkg@latest"] }, "medium", "@latest"],
    [{ command: "npx", args: ["-y", "@scope/pkg@next"] }, "medium", "@next"],
    [{ command: "npx", args: ["-p", "@scope/pkg", "pkg-bin"] }, "medium", "@scope/pkg"],
    [{ command: "npx", args: ["--package=other", "bin"] }, "medium", "other"],
    [{ command: "npx", args: ["pkg@^1.2.0"] }, "low", "range"],
    [{ command: "npx", args: ["pkg@1"] }, "low", "range"],
    [{ command: "bunx", args: ["pkg"] }, "medium", "bunx"],
    [{ command: "yarn", args: ["dlx", "pkg"] }, "medium", "yarn dlx"],
    [{ command: "C:\\Program Files\\nodejs\\npx.cmd", args: ["-y", "pkg"] }, "medium", "npx"],
    [{ command: "npx -y pkg" }, "medium", "pkg"],
    [{ command: "cmd", args: ["/c", "npx", "-y", "pkg"] }, "medium", "pkg"],
    [{ command: "npx", args: ["github:owner/repo"] }, "medium", "git/URL"],
    [{ command: "uvx", args: ["mcp-server-git"] }, "medium", "without a version"],
    [{ command: "uvx", args: ["--from", "pkg>=1.0", "cmd"] }, "low", "range"],
    [{ command: "pipx", args: ["run", "pkg"] }, "medium", "pipx run"],
    [{ command: "docker", args: ["run", "-i", "--rm", "-e", "TOKEN", "img"] }, "medium", "without a tag"],
    [{ command: "docker", args: ["run", "--name", "x", "img:latest"] }, "medium", ":latest"],
    [{ command: "docker", args: ["run", "registry.example.invalid:5000/team/img:1.4"] }, "info", "mutable tag"],
  ])("flags %j as %s", (server, severity, text) => {
    const findings = check(server);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SW011", severity });
    expect(findings[0]!.message).toContain(text);
  });

  it.each([
    { command: "npx", args: ["-y", "pkg@1.2.3"] },
    { command: "npx", args: ["@scope/pkg@0.6.0-beta.1"] },
    { command: "uvx", args: ["pkg==1.2.3"] },
    { command: "uvx", args: ["pkg@1.2.3"] },
    { command: "uvx", args: ["--from", "git+https://example.invalid/r@" + "b".repeat(40), "cmd"] },
    { command: "docker", args: ["run", "img@sha256:" + "c".repeat(64)] },
    { command: "npx", args: ["./local/server"] },
    { command: "node", args: ["server.js"] },
    { command: "npx", args: ["$SERVER_PKG"] },
    { type: "http", url: "https://example.invalid/mcp" },
  ])("accepts %j", (server) => {
    expect(check(server)).toEqual([]);
  });

  it("points at the package argument and names the server", () => {
    const text = mcp({ command: "npx", args: ["-y", "pkg"] });
    const [f] = checkText(rule, text, ".mcp.json", "mcp-config");
    expect(f!.line).toBe(text.split("\n").findIndex((l) => l.includes('"pkg"')) + 1);
    expect(f!.message).toContain('MCP server "s"');
  });

  it("covers project-scoped servers in ~/.claude.json and ignores invalid JSON", () => {
    const text = JSON.stringify({ projects: { "/work/app": { mcpServers: { db: { command: "npx", args: ["db-mcp"] } } } } }, null, 2);
    const [f] = checkText(rule, text, "~/.claude.json", "mcp-config");
    expect(f!.message).toContain("(project /work/app)");
    expect(checkText(rule, "{ not json", ".mcp.json", "mcp-config")).toEqual([]);
  });

  it("never prints secrets from the same line", () => {
    const text = '{"mcpServers":{"s":{"command":"npx","args":["pkg","--api-key","FAKE_KEY_123456"]}}}';
    const [f] = checkText(rule, text, ".mcp.json", "mcp-config");
    expect(f!.snippet).not.toContain("FAKE_KEY_123456");
  });
});
