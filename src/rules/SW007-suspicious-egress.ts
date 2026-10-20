import type { Confidence, Finding, ParsedFile, Rule, Severity } from "../types.js";
import { logicalLines, execAll } from "../text.js";
import { findingAt } from "./helpers.js";
import { withVocab } from "./vocabulary.js";

type Category = "ip" | "paste" | "catcher" | "tunnel" | "shortener" | "chat-webhook" | "ddns" | "raw-gist";

interface HostGroup {
  category: Category;
  /** Registrable domains; subdomains match too. A path prefix limits the match (`discord.com/api/webhooks`). */
  hosts: string[];
}

const GROUPS: HostGroup[] = [
  {
    category: "paste",
    hosts: [
      "pastebin.com", "pastebin.pl", "paste.ee", "hastebin.com", "rentry.co", "rentry.org", "dpaste.com", "dpaste.org",
      "termbin.com", "transfer.sh", "0x0.st", "file.io", "controlc.com", "ghostbin.com", "ghostbin.co", "privatebin.net",
      "paste.c-net.org", "ix.io", "sprunge.us", "paste.rs", "glot.io",
    ],
  },
  {
    category: "catcher",
    hosts: [
      "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "hookbin.com", "beeceptor.com", "canarytokens.com",
      "canarytokens.org", "interact.sh", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
      "burpcollaborator.net", "oastify.com", "requestcatcher.com", "postb.in", "ptsv2.com", "ptsv3.com",
    ],
  },
  {
    category: "tunnel",
    hosts: [
      "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok-free.dev", "trycloudflare.com", "loca.lt", "localtunnel.me",
      "serveo.net", "localhost.run", "lhr.life", "bore.pub", "pinggy.link",
    ],
  },
  {
    category: "shortener",
    hosts: [
      "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "ow.ly", "shorturl.at", "rb.gy",
      "tiny.cc", "t.ly", "buff.ly",
    ],
  },
  {
    category: "chat-webhook",
    hosts: ["discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot", "hooks.slack.com"],
  },
  { category: "ddns", hosts: ["duckdns.org", "ddns.net", "no-ip.com", "no-ip.org", "hopto.org", "zapto.org", "sytes.net", "dynu.net"] },
  { category: "raw-gist", hosts: ["gist.githubusercontent.com"] },
];

/** Paste-site hosts, shared with SW010 ("open this page and run the command in Terminal"). */
export const PASTE_HOSTS: readonly string[] = GROUPS.find((g) => g.category === "paste")!.hosts;

const DESCRIPTIONS: Record<Category, string> = {
  ip: "a bare public IP address",
  paste: "a paste service",
  catcher: "a request-catcher / webhook-testing service",
  tunnel: "a tunneling service",
  shortener: "a URL shortener",
  "chat-webhook": "a chat webhook",
  ddns: "a dynamic-DNS host",
  "raw-gist": "a raw gist",
};

const WHY: Record<Category, string> = {
  ip: "Hard-coded IPs bypass DNS-based review and are typical for exfiltration and payload servers.",
  paste: "Paste sites are a common way to exfiltrate data or host payloads.",
  catcher: "These services exist to collect incoming requests — a classic exfiltration endpoint.",
  tunnel: "Tunnels expose throwaway endpoints on someone's machine; the destination can't be vetted.",
  shortener: "Shorteners hide the real destination, which can change at any time.",
  "chat-webhook": "Chat webhooks accept data from anyone holding the URL — an easy exfiltration channel.",
  ddns: "Dynamic-DNS names point wherever their owner wants; they are common for attacker infrastructure.",
  "raw-gist": "Raw gists are mutable, unreviewed hosting often used for payloads.",
};

const BASE: Record<Category, [Severity, Confidence]> = {
  ip: ["high", "high"],
  paste: ["high", "high"],
  catcher: ["high", "high"],
  // Tunnels mostly receive webhooks during development; sending data to one is still worth a look.
  tunnel: ["medium", "medium"],
  shortener: ["medium", "medium"],
  "chat-webhook": ["medium", "medium"],
  ddns: ["medium", "medium"],
  "raw-gist": ["low", "medium"],
};

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `host` matches as a whole domain or subdomain: not `notwebhook.site`, not `webhook.site.example`. */
const HOST_PATTERNS = GROUPS.flatMap(({ category, hosts }) =>
  hosts.map((host) => {
    const [domain, ...path] = host.split("/");
    const pathPart = path.length ? `/${path.map(escapeRe).join("/")}` : "";
    return {
      category,
      host,
      /** Cheap substring check before running the regex — most lines mention none of these hosts. */
      needle: domain!.toLowerCase(),
      hasPath: path.length > 0,
      // Not a path component either: `$SCRIPT_DIR/transfer.sh` is a script, `https://transfer.sh` a host.
      re: new RegExp(String.raw`(?<![\w.-]|[\w.$}-]/)((?:[\w-]+\.)*${escapeRe(domain!)})(?![\w-]|\.[\w-])(${pathPart})`, "gi"),
    };
  }),
);

/** Commands that talk to the network; a bare host or IP next to one is a destination. */
const NETWORK_COMMAND = withVocab(
  /\b(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|__psFetch__|requests\.\w+|fetch|axios|urlopen|http\.get)\b|\/dev\/(?:tcp|udp)\//i,
);
/** Data on the line that makes a chat webhook look like exfiltration. */
const SENSITIVE_DATA =
  /(?:^|[\s"'=(@])(?:~\/|\$HOME)|(?<![\w.])\.env\b|\bprocess\.env\b|\bos\.environ\b|\$\{?\w*(?:KEY|TOKEN|SECRET|PASS\w*)\}?|\bid_(?:rsa|ed25519)\b|\bcredentials\b|(?:-d|--data(?:-binary)?|-F|--form|-T|--upload-file)\s+["']?@(?![^\s"']*\.json["'\s])|\b(?:cat|printenv|env)\b/i;

const URL_AUTHORITY = /\b(?:https?|wss?|ftp):\/\/(?:[^\s/?#@"'<>`]*@)?(\[[0-9a-fA-F:.]+\]|[^\s/?#:"'<>`)\]]+)/gi;
const BARE_IPV4 = /(?<![\w.:/-])((?:\d{1,3}\.){3}\d{1,3})(?![\w.-]|\.\d)(:\d{2,5})?/g;
const DEV_TCP = /\/dev\/(?:tcp|udp)\/((?:\d{1,3}\.){3}\d{1,3})\//gi;

/** Public DNS resolvers and placeholder addresses from docs (`"content": "1.2.3.4"` in a DNS API example). */
const BENIGN_IPS = new Set([
  "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
  "1.2.3.4", "4.3.2.1", "5.6.7.8", "1.2.3.5", "2.2.2.2", "123.123.123.123", "111.111.111.111", "123.45.67.89",
]);
/** Placeholder subdomains in docs: `abc123.oast.fun`, `your-id.ngrok-free.app`, `<id>.trycloudflare.com`. */
const PLACEHOLDER_LABEL =
  /^(?:abc\d*|xyz\d*|x{2,}|your[\w-]*|my[\w-]*|example|test|demo|random[\w-]*|subdomain|id|foo|bar|collab\w*|attacker|burp|<[^>]*>|\{[^}]*\}|\$\{?\w+\}?)$/i;
/** Test sources quote attack strings on purpose (`'Exfil via https://requestbin.com/r/abc'` in a detector's tests). */
const TEST_FILE = /(?:^|\/)(?:tests?|__tests__|spec)\/|[._-](?:test|spec)\.[cm]?[jt]sx?$|_test\.(?:py|go)$|(?:^|\/)test_[^/]+\.py$/i;
/** `198.18.0.0/15` — a network range in CIDR notation, not an address something connects to. */
const CIDR_AFTER = /^\/\d{1,2}(?!\d)/;
/** "(e.g., https://abc.ngrok-free.app)", "such as webhook.site" — an example, not a destination the skill uses. */
const EXAMPLE_BEFORE = /\b(?:e\.g\.|eg\.|for example|such as|for instance)[^.]*$/i;

const rule: Rule = {
  id: "SW007",
  name: "suspicious-egress",
  severity: "high",
  appliesTo: ["skill", "instructions", "mcp-config", "settings", "plugin-manifest"],
  description:
    "Network destinations typical for exfiltration or payload hosting: bare public IPs, paste services, request catchers (webhook.site, …), tunnels (ngrok, …), URL shorteners, chat webhooks, dynamic DNS.",
  check(target) {
    return target.files.flatMap((file) => checkFile(file));
  },
};

export default rule;

interface Hit {
  start: number;
  end: number;
  category: Category;
  host: string;
  severity: Severity;
  confidence: Confidence;
}

function checkFile(file: ParsedFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of logicalLines(file.text)) {
    const test = TEST_FILE.test(file.path);
    for (const hit of checkLine(line.text)) {
      findings.push(
        findingAt(rule, file, {
          offset: line.offsets[hit.start]!,
          length: hit.end - hit.start,
          message: `Connects to ${DESCRIPTIONS[hit.category]} (${hit.host}). ${WHY[hit.category]} Remove it or use a trusted, pinned destination.`,
          confidence: test ? "low" : hit.confidence,
          severity: test && hit.severity === "high" ? "medium" : hit.severity,
        }),
      );
    }
  }
  return findings;
}

/** Exported for tests and reuse: suspicious destinations on one logical line. */
export function checkLine(text: string): Hit[] {
  const hits: Hit[] = [];
  // Shell variables are not commands: `${NC}` (a color code) is not netcat.
  const network = NETWORK_COMMAND.test(text.replace(/\$\{?\w+\}?/g, "$V"));
  // The bot token in `https://api.telegram.org/bot$TOKEN/sendMessage` authenticates the call; it isn't data sent out.
  const sensitive = SENSITIVE_DATA.test(text.replace(/\bhttps?:\/\/[^\s"'`)]+/gi, " "));
  const add = (start: number, end: number, category: Category, host: string, override?: [Severity, Confidence]) => {
    // One finding per destination per line.
    if (hits.some((h) => (start < h.end && end > h.start) || h.host === host)) return;
    let [severity, confidence] = override ?? BASE[category];
    if (category === "chat-webhook" && sensitive) [severity, confidence] = ["high", "high"];
    // A paste-site link in prose is a reference; fetching from or posting to it is the risk.
    if (category === "paste" && !network) [severity, confidence] = ["medium", "medium"];
    const labels = host.split("/")[0]!.split(".").slice(0, -2);
    if ((category === "catcher" || category === "tunnel") && labels.some((l) => PLACEHOLDER_LABEL.test(l))) {
      [severity, confidence] = ["medium", "low"];
    }
    // `canarytokens.org/generate` creates a honeytoken (defensive); the tokens fire at other hosts.
    if (category === "catcher" && /^canarytokens\.(?:org|com)$/.test(host) && /canarytokens\.(?:org|com)\/generate/i.test(text)) {
      [severity, confidence] = ["low", "medium"];
    }
    if (!network && EXAMPLE_BEFORE.test(text.slice(0, start))) [severity, confidence] = ["low", "low"];
    hits.push({ start, end, category, host, severity, confidence });
  };

  // URLs: the authority decides.
  const urlAuthorities: Array<[number, number]> = [];
  for (const m of execAll(URL_AUTHORITY, text)) {
    const authority = m[1]!;
    const start = m.index + m[0].length - authority.length;
    urlAuthorities.push([start, start + authority.length]);
    const ip = authority.startsWith("[") ? authority.slice(1, -1) : authority;
    if (BENIGN_IPS.has(ip)) continue;
    if (isPublicIpv4(ip) || (authority.startsWith("[") && isPublicIpv6(ip))) add(m.index, m.index + m[0].length, "ip", ip);
  }
  const inUrl = (i: number) => urlAuthorities.some(([s, e]) => i >= s && i < e);

  // Known hosts: inside a URL, followed by a path/port, or next to a network command.
  const lower = text.toLowerCase();
  for (const { category, hasPath, needle, re } of HOST_PATTERNS) {
    if (!lower.includes(needle)) continue;
    for (const m of execAll(re, text)) {
      if (hasPath && !m[2]) continue;
      const end = m.index + m[0].length;
      const after = text[end];
      const destination = inUrl(m.index) || hasPath || after === "/" || after === ":" || network;
      if (!destination) continue;
      add(m.index, end, category, m[1]!.toLowerCase() + (m[2] ?? ""));
    }
  }

  // Bare IPs outside URLs: /dev/tcp/IP/port, `IP:port`, or next to a network command.
  for (const m of execAll(DEV_TCP, text)) {
    if (isPublicIpv4(m[1]!) && !BENIGN_IPS.has(m[1]!)) add(m.index, m.index + m[0].length, "ip", m[1]!);
  }
  for (const m of execAll(BARE_IPV4, text)) {
    if (inUrl(m.index) || !isPublicIpv4(m[1]!) || BENIGN_IPS.has(m[1]!)) continue;
    if (!m[2] && CIDR_AFTER.test(text.slice(m.index + m[0].length))) continue;
    if (!m[2] && !network) continue;
    // `91.215.85.17:8080 ESTABLISHED` in a log excerpt or a table is data, not a destination the skill talks to;
    // so is `-d "ipAddress=203.0.113.45"` (an IP looked up, not connected to).
    const asData = !m[2] && /[=:]\s*["']?$/.test(text.slice(0, m.index));
    add(m.index, m.index + m[0].length, "ip", m[1]!, network && !asData ? ["high", "high"] : ["medium", "low"]);
  }

  // Three or more of these services on one line without a network command is a catalog (an audit checklist, a
  // blocklist), not a destination.
  if (!network && new Set(hits.map((h) => h.host)).size >= 3) {
    for (const h of hits) [h.severity, h.confidence] = ["low", "low"];
  }

  return hits.sort((a, b) => a.start - b.start);
}

/** Public IPv4: not loopback, private, link-local, CGNAT, multicast or unspecified. TEST-NETs count as public. */
export function isPublicIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return false;
  const [a, b] = parts.map(Number) as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

/** Public IPv6: not loopback, unspecified, link-local (fe80::/10) or unique-local (fc00::/7). */
export function isPublicIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(lower) || !lower.includes(":")) return false;
  if (lower === "::1" || lower === "::") return false;
  if (/^fe[89ab]/.test(lower) || /^f[cd]/.test(lower)) return false;
  if (lower.startsWith("::ffff:")) return isPublicIpv4(lower.slice(7));
  return true;
}
