import { describe, expect, it } from "vitest";
import rule from "../../src/rules/SW012-remote-mcp.js";
import { checkText } from "../helpers.js";
import { fixtureChecks } from "./fixture-check.js";

const check = (server: Record<string, unknown>) =>
  checkText(rule, JSON.stringify({ mcpServers: { api: server } }, null, 2), ".mcp.json", "mcp-config");

describe("SW012 remote-mcp", () => {
  fixtureChecks(rule);

  it("lists https servers as low with the host and auth header names", () => {
    const [f, ...rest] = check({ type: "http", url: "https://mcp.example.invalid/mcp", headers: { Authorization: "Bearer FAKE_KEY_1" } });
    expect(rest).toHaveLength(0);
    expect(f).toMatchObject({ ruleId: "SW012", severity: "low", confidence: "high" });
    expect(f!.message).toContain("mcp.example.invalid");
    expect(f!.message).toContain("Authorization");
    expect(f!.message).not.toContain("FAKE_KEY_1");
  });

  it("raises plain http to a remote host and credentials in the URL", () => {
    expect(check({ type: "sse", url: "http://203.0.113.20/sse" })[0]).toMatchObject({ severity: "medium" });
    const [f] = check({ url: "https://user:FAKE_PASS@example.invalid/mcp?token=FAKE_KEY_2" });
    expect(f).toMatchObject({ severity: "medium" });
    expect(f!.snippet).not.toContain("FAKE_KEY_2");
    expect(f!.snippet).not.toContain("FAKE_PASS");
    expect(f!.message).not.toContain("FAKE_PASS");
  });

  it("ignores local and stdio servers", () => {
    expect(check({ type: "http", url: "http://localhost:3000/mcp" })).toEqual([]);
    expect(check({ type: "http", url: "http://[::1]:3000/mcp" })).toEqual([]);
    expect(check({ command: "node", args: ["s.js"] })).toEqual([]);
  });

  it("skips empty placeholder URLs and names the variable of templated ones", () => {
    expect(check({ type: "http", url: "" })).toEqual([]);
    const [f] = check({ type: "http", url: "${TOOLS_URL}" });
    expect(f).toMatchObject({ severity: "low" });
    expect(f!.message).toContain("a URL from $TOOLS_URL");
    expect(check({ type: "http", url: "${TOOLS_URL:-https://mcp.example.invalid/mcp}" })[0]!.message).toContain(
      "a URL from $TOOLS_URL (default mcp.example.invalid)",
    );
    expect(check({ type: "http", url: "${TOOLS_URL:-http://localhost:3000/mcp}" })).toEqual([]);
  });
});
