import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { northlineObservations } from "./demo-data.ts";
import { compileScan, isDemoQuery, isPublicIp, newId, normalizeTarget } from "./engine.ts";
import type {
  CheckResult,
  CollectorRun,
  DnsRecord,
  MapResult,
  Observations,
  Proof,
  ProofMethod,
} from "./types.ts";

const UA = "Prex passive-footprint (homepage, DNS, RDAP, and security.txt only)";
const HOST_GAP_MS = 8000;
const WINDOW_MS = 60_000;
const WINDOW_MAX = 8;

const lastHost = new Map<string, number>();
const windowHits: number[] = [];

function rateLimit(key: string): string | null {
  const now = Date.now();
  while (windowHits.length && now - (windowHits[0] ?? 0) > WINDOW_MS) windowHits.shift();
  if (windowHits.length >= WINDOW_MAX) return "Too many maps in a minute. Wait and try again.";
  const prev = lastHost.get(key) ?? 0;
  if (now - prev < HOST_GAP_MS) return "That host was mapped a moment ago. Wait a few seconds.";
  windowHits.push(now);
  lastHost.set(key, now);
  return null;
}

type Answer = { name: string; type: number; ttl: number; data: string };

async function doh(name: string, type: string): Promise<{ status: number; ad: boolean; answers: Answer[]; error?: string }> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return { status: res.status, ad: false, answers: [], error: `Resolver HTTP ${res.status}` };
    const json = (await res.json()) as {
      Status?: number;
      AD?: boolean;
      Answer?: { name: string; type: number; TTL: number; data: string }[];
    };
    return {
      status: json.Status ?? -1,
      ad: Boolean(json.AD),
      answers: (json.Answer ?? []).map((a) => ({
        name: a.name,
        type: a.type,
        ttl: a.TTL,
        data: String(a.data ?? "").replace(/^"|"$/g, ""),
      })),
    };
  } catch (error) {
    return { status: -1, ad: false, answers: [], error: error instanceof Error ? error.message : "DNS failed" };
  }
}

async function resolvePublic(host: string): Promise<{ ips: string[]; blocked: boolean; error?: string }> {
  const [v4, v6] = await Promise.all([doh(host, "A"), doh(host, "AAAA")]);
  const error = v4.error && v6.error ? v4.error : undefined;
  const ips = [...v4.answers, ...v6.answers].map((a) => a.data.trim()).filter(Boolean);
  if (ips.some((ip) => !isPublicIp(ip))) return { ips: ips.filter((ip) => isPublicIp(ip)), blocked: true, error };
  return { ips: ips.filter((ip) => isPublicIp(ip)), blocked: false, error };
}

function pinRequest(options: {
  protocol: "https" | "http";
  ip: string;
  hostname: string;
  path: string;
  timeoutMs: number;
  maxBytes: number;
  method?: "GET" | "HEAD";
}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  const lib = options.protocol === "https" ? https : http;
  const family = options.ip.includes(":") ? 6 : 4;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        host: options.ip,
        family,
        servername: options.hostname,
        port: options.protocol === "https" ? 443 : 80,
        method: options.method ?? "GET",
        path: options.path,
        headers: {
          host: options.hostname,
          "user-agent": UA,
          accept: "text/html,application/json;q=0.8,*/*;q=0.5",
        },
        timeout: options.timeoutMs,
        rejectUnauthorized: true,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          if (options.maxBytes === 0) {
            res.destroy();
            return;
          }
          size += chunk.length;
          if (size > options.maxBytes) {
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8").slice(0, options.maxBytes),
          });
        });
        res.on("error", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8").slice(0, options.maxBytes),
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

function header(headers: http.IncomingHttpHeaders, name: string): string {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(", ").slice(0, 180);
  return (value ?? "").slice(0, 180);
}

const HEADER_ALLOW = [
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "server",
  "x-powered-by",
  "via",
  "cf-ray",
  "cf-cache-status",
  "x-vercel-id",
  "x-amz-cf-id",
  "access-control-allow-origin",
  "alt-svc",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy",
  "content-type",
];

function parseCookies(headers: http.IncomingHttpHeaders) {
  const raw = headers["set-cookie"] ?? [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list.slice(0, 8).map((line) => {
    const [first, ...rest] = line.split(";");
    const name = (first ?? "").split("=")[0]?.trim() || "cookie";
    const attrs = rest.map((p) => p.trim().toLowerCase());
    const same = attrs.find((a) => a.startsWith("samesite="));
    return {
      name: name.slice(0, 40),
      secure: attrs.includes("secure"),
      httpOnly: attrs.includes("httponly"),
      sameSite: same ? same.split("=")[1] ?? null : null,
    };
  });
}

function technologies(headers: { name: string; value: string }[], html: string) {
  const found: { name: string; confidence: number; evidence: string }[] = [];
  const add = (name: string, confidence: number, evidence: string) => {
    if (!found.some((f) => f.name === name)) found.push({ name, confidence, evidence });
  };
  const server = headers.find((h) => h.name === "server")?.value ?? "";
  const powered = headers.find((h) => h.name === "x-powered-by")?.value ?? "";
  if (/cloudflare/i.test(server) || headers.some((h) => h.name === "cf-ray")) {
    add("Cloudflare", 0.9, "Cloudflare header or server token on the response.");
  }
  if (headers.some((h) => h.name === "x-vercel-id")) add("Vercel", 0.85, "x-vercel-id header.");
  if (headers.some((h) => h.name === "x-amz-cf-id")) add("Amazon CloudFront", 0.85, "CloudFront header.");
  if (/fastly/i.test(headers.find((h) => h.name === "via")?.value ?? "")) add("Fastly", 0.8, "Via header mentions Fastly.");
  if (/nginx/i.test(server)) add("nginx", /\d/.test(server) ? 0.8 : 0.6, "Server header.");
  if (/apache/i.test(server)) add("Apache", 0.7, "Server header.");
  if (powered) add(powered.split("/")[0]?.slice(0, 40) || "x-powered-by", 0.7, "x-powered-by header. Version not treated as a vulnerability.");
  if (/\/_next\/|__NEXT_DATA__/.test(html)) add("Next.js", 0.85, "Homepage HTML referenced Next.js.");
  if (/wp-content|wp-includes/.test(html)) add("WordPress", 0.85, "Homepage HTML referenced WordPress paths.");
  if (/cdn\.shopify\.com/.test(html)) add("Shopify", 0.85, "Homepage HTML referenced Shopify.");
  return found.slice(0, 8);
}

function sameSiteScripts(host: string, html: string): { scripts: string[]; sourceMap: boolean } {
  const scripts: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) && scripts.length < 12) {
    const src = match[1] ?? "";
    if (src.startsWith("/") && !src.startsWith("//")) scripts.push(src.slice(0, 180));
    else {
      try {
        const url = new URL(src);
        if (url.hostname === host) scripts.push(url.pathname.slice(0, 180));
      } catch {
        /* ignore unparsable */
      }
    }
  }
  const sourceMap = /sourceMappingURL=/i.test(html) || scripts.some((s) => s.endsWith(".map"));
  return { scripts, sourceMap };
}

async function tlsProbe(ip: string, hostname: string) {
  return new Promise<{
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    daysRemaining: number | null;
    sans: string[];
    protocol: string | null;
    authorized: boolean;
    authError: string | null;
    hostnameMismatch: boolean;
    error?: string;
  }>((resolve) => {
    const socket = tls.connect({
      host: ip,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 6000,
    });
    const finish = (error?: string) => {
      socket.destroy();
      resolve({
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        sans: [],
        protocol: null,
        authorized: false,
        authError: error ?? null,
        hostnameMismatch: false,
        error,
      });
    };
    socket.setTimeout(6000, () => finish("timeout"));
    socket.once("error", (error) => finish(error.message));
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const sans = String(cert.subjectaltname ?? "")
        .split(",")
        .map((s) => s.trim().replace(/^DNS:/i, ""))
        .filter(Boolean);
      const cn = typeof cert.subject?.CN === "string" ? cert.subject.CN : null;
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const days =
        validTo && !Number.isNaN(validTo.getTime())
          ? Math.round((validTo.getTime() - Date.now()) / 86_400_000)
          : null;
      const names = [...sans, ...(cn ? [cn] : [])].map((n) => n.toLowerCase());
      const host = hostname.toLowerCase();
      const covered = names.some((name) => {
        if (name.startsWith("*.")) {
          const rest = name.slice(2);
          return host.endsWith(`.${rest}`) && host.split(".").length === rest.split(".").length + 1;
        }
        return name === host;
      });
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError ? String(socket.authorizationError) : null;
      socket.end();
      resolve({
        subject: cn,
        issuer: typeof cert.issuer?.CN === "string" ? cert.issuer.CN : null,
        validFrom: cert.valid_from ?? null,
        validTo: cert.valid_to ?? null,
        daysRemaining: days,
        sans: sans.slice(0, 12),
        protocol,
        authorized,
        authError,
        hostnameMismatch: names.length > 0 && !covered,
      });
    });
  });
}

function txtJoin(answers: Answer[], typeNum: number): string[] {
  return answers.filter((a) => a.type === typeNum).map((a) => a.data.replace(/"\s*"/g, "").replaceAll('"', ""));
}

async function collectDomain(host: string, registrable: string, verified: boolean): Promise<Pick<
  Observations,
  | "collectors"
  | "dynamicPolicy"
  | "dns"
  | "rdap"
  | "http"
  | "tls"
  | "ctNames"
  | "ctError"
  | "securityTxt"
  | "robotsFound"
  | "lookalikes"
  | "repository"
  | "safeRecheck"
>> {
  const collectors: CollectorRun[] = [];
  const dynamicPolicy: Observations["dynamicPolicy"] = [];
  const timed = async <T>(id: string, title: string, run: () => Promise<{ status: CollectorRun["status"]; detail: string; value: T }>): Promise<T> => {
    const start = Date.now();
    try {
      const result = await run();
      collectors.push({ id, title, status: result.status, detail: result.detail, durationMs: Date.now() - start });
      return result.value;
    } catch (error) {
      const message = error instanceof Error ? error.message : "failed";
      collectors.push({ id, title, status: "error", detail: message, durationMs: Date.now() - start });
      throw error;
    }
  };

  const dns = await timed("dns", "DNS and mail posture", async () => {
    const [a, aaaa, ns, mx, txt, caa, cname, dmarc] = await Promise.all([
      doh(host, "A"),
      doh(host, "AAAA"),
      doh(host, "NS"),
      doh(host, "MX"),
      doh(host, "TXT"),
      doh(host, "CAA"),
      doh(host, "CNAME"),
      doh(`_dmarc.${host}`, "TXT"),
    ]);
    const failed = [a, aaaa, ns, mx, txt].every((r) => r.error);
    const records: DnsRecord[] = [];
    const push = (type: string, answers: Answer[]) => {
      for (const ans of answers) {
        if (type === "A" || type === "AAAA") {
          if (!isPublicIp(ans.data)) continue;
        }
        records.push({
          type,
          name: ans.name.replace(/\.$/, ""),
          value: ans.data.replace(/\.$/, "").slice(0, 200),
          ttl: String(ans.ttl),
        });
      }
    };
    push("A", a.answers.filter((x) => x.type === 1));
    push("AAAA", aaaa.answers.filter((x) => x.type === 28));
    push("NS", ns.answers.filter((x) => x.type === 2));
    push("MX", mx.answers.filter((x) => x.type === 15));
    push("TXT", txt.answers.filter((x) => x.type === 16));
    push("CAA", caa.answers);
    push("CNAME", cname.answers.filter((x) => x.type === 5));
    const spf = txtJoin(txt.answers, 16).find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
    const dmarcRecord = txtJoin(dmarc.answers, 16).find((t) => /v\s*=\s*dmarc1/i.test(t)) ?? null;
    const dangling: { host: string; target: string; reason: string }[] = [];
    for (const cn of cname.answers.filter((x) => x.type === 5).slice(0, 3)) {
      const target = cn.data.replace(/\.$/, "");
      const follow = await doh(target, "A");
      const publicAnswers = follow.answers.filter((x) => x.type === 1 && isPublicIp(x.data));
      if (!follow.error && publicAnswers.length === 0) {
        dangling.push({
          host,
          target,
          reason: "No public address followed the alias. Review required. Not a confirmed takeover.",
        });
      }
    }
    const ad = [a, aaaa, txt, dmarc].some((r) => r.ad);
    return {
      status: failed ? "error" : records.length ? "ok" : "empty",
      detail: failed ? (a.error ?? "DNS failed") : `${records.length} public record(s). Private addresses were dropped.`,
      value: {
        records,
        spf,
        dmarc: dmarcRecord,
        ad,
        dangling,
        error: failed ? a.error : undefined,
      },
    };
  }).catch(() => null);

  const resolved = dns && !dns.error ? await resolvePublic(host) : { ips: [] as string[], blocked: false, error: dns?.error };
  if (resolved.blocked) {
    dynamicPolicy.push({
      action: "Homepage and TLS observe",
      decision: "deny",
      reason: "Resolution included a non-public address. The connection was refused and those addresses are not shown.",
    });
  }
  const ip = resolved.blocked ? null : (resolved.ips[0] ?? null);

  let http: Observations["http"] = null;
  let tls: Observations["tls"] = null;
  let securityTxt: Observations["securityTxt"] = null;
  let robotsFound: boolean | null = null;
  let safeRecheck: Observations["safeRecheck"] = null;

  if (!ip) {
    collectors.push({
      id: "http",
      title: "Homepage headers",
      status: resolved.blocked ? "denied" : "skipped",
      detail: resolved.blocked ? "Blocked after DNS." : "No public address to connect to.",
      durationMs: 0,
    });
    collectors.push({
      id: "tls",
      title: "TLS observe",
      status: resolved.blocked ? "denied" : "skipped",
      detail: resolved.blocked ? "Blocked after DNS." : "No public address to connect to.",
      durationMs: 0,
    });
  } else {
    const again = await resolvePublic(host);
    if (again.blocked || !again.ips.includes(ip)) {
      dynamicPolicy.push({
        action: "Homepage and TLS observe",
        decision: "deny",
        reason: "DNS answers changed before connect or included a non-public address. Refused to avoid rebinding.",
      });
      collectors.push({
        id: "http",
        title: "Homepage headers",
        status: "denied",
        detail: "Second lookup did not confirm a stable public address.",
        durationMs: 0,
      });
    } else {
      tls = await timed("tls", "TLS observe", async () => {
        const value = await tlsProbe(ip, host);
        return {
          status: value.error ? "error" : "ok",
          detail: value.error ?? `${value.protocol ?? "TLS"} ${value.subject ?? host}`,
          value,
        };
      }).catch(() => null);

      http = await timed<NonNullable<Observations["http"]>>("http", "Homepage headers", async () => {
        const notes: string[] = [];
        let response: Awaited<ReturnType<typeof pinRequest>>;
        try {
          response = await pinRequest({
            protocol: "https",
            ip,
            hostname: host,
            path: "/",
            timeoutMs: 8000,
            maxBytes: 180_000,
          });
        } catch (error) {
          const message = error instanceof Error ? error.message : "request failed";
          return {
            status: "error" as const,
            detail: message,
            value: {
              url: `https://${host}/`,
              status: null,
              title: null,
              headers: [],
              cookies: [],
              technologies: [],
              scripts: [],
              sourceMap: false,
              redirectNotes: [],
              httpsToHttp: false,
              httpServesContent: false,
              httpRedirectsToHttps: false,
              error: message,
            },
          };
        }
        const location = header(response.headers, "location");
        if (response.status >= 300 && response.status < 400 && location) {
          notes.push(`HTTPS returned ${response.status} to ${location.slice(0, 180)}. Off-host redirects were not followed.`);
          try {
            const next = new URL(location, `https://${host}/`);
            if (next.protocol === "http:") notes.push("Redirect target is HTTP.");
          } catch {
            notes.push("Redirect target was not a valid URL.");
          }
        }
        let httpServesContent = false;
        let httpRedirectsToHttps = false;
        try {
          const clear = await pinRequest({
            protocol: "http",
            ip,
            hostname: host,
            path: "/",
            timeoutMs: 4000,
            maxBytes: 0,
            method: "HEAD",
          });
          const loc = header(clear.headers, "location");
          if (clear.status >= 300 && clear.status < 400 && loc.toLowerCase().startsWith("https://")) {
            httpRedirectsToHttps = true;
            notes.push("Port 80 redirected to HTTPS.");
          } else if (clear.status >= 200 && clear.status < 300) {
            httpServesContent = true;
            notes.push("Port 80 returned a successful status without an HTTPS redirect.");
          } else if (clear.status) {
            notes.push(`Port 80 returned ${clear.status}.`);
          }
        } catch {
          notes.push("Port 80 did not respond. That is recorded, not treated as a finding by itself.");
        }
        const headers = HEADER_ALLOW.map((name) => ({ name, value: header(response.headers, name) })).filter((h) => h.value);
        const html = /html/i.test(header(response.headers, "content-type")) ? response.body : "";
        const title = html.match(/<title[^>]*>([^<]{0,140})<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim() ?? null;
        const parsedScripts = sameSiteScripts(host, html);
        const httpsToHttp = notes.some((n) => n.includes("Redirect target is HTTP"));
        return {
          status: "ok" as const,
          detail: `HTTP ${response.status}`,
          value: {
            url: `https://${host}/`,
            status: response.status,
            title,
            headers,
            cookies: parseCookies(response.headers),
            technologies: technologies(headers, html),
            scripts: parsedScripts.scripts,
            sourceMap: parsedScripts.sourceMap,
            redirectNotes: notes,
            httpsToHttp,
            httpServesContent,
            httpRedirectsToHttps,
          },
        };
      }).catch(() => null);

      securityTxt = await timed("docs", "security.txt", async () => {
        try {
          const doc = await pinRequest({
            protocol: "https",
            ip,
            hostname: host,
            path: "/.well-known/security.txt",
            timeoutMs: 6000,
            maxBytes: 20_000,
          });
          const found = doc.status === 200 && /contact\s*:/i.test(doc.body);
          const contacts = [...doc.body.matchAll(/^contact:\s*(.+)$/gim)].map((m) => (m[1] ?? "").trim()).slice(0, 4);
          const safeContacts = contacts.map((c) => {
            const email = c.match(/[\w.+-]+@[\w.-]+/);
            if (!email) return c.slice(0, 120);
            const domain = email[0].split("@")[1]?.toLowerCase() ?? "";
            if (domain && (host === domain || host.endsWith(`.${domain}`) || domain.endsWith(host))) return c.slice(0, 120);
            return "contact withheld (mailbox is outside this host)";
          });
          return {
            status: found ? "ok" : "empty",
            detail: found ? "Contact field published." : `HTTP ${doc.status}, no Contact field.`,
            value: {
              found,
              contacts: safeContacts,
              excerpt: doc.body.replace(/\s+/g, " ").slice(0, 240),
            },
          };
        } catch (error) {
          return {
            status: "error" as const,
            detail: error instanceof Error ? error.message : "security.txt failed",
            value: null,
          };
        }
      }).catch(() => null);

      try {
        const robots = await pinRequest({
          protocol: "https",
          ip,
          hostname: host,
          path: "/robots.txt",
          timeoutMs: 5000,
          maxBytes: 0,
          method: "HEAD",
        });
        robotsFound = robots.status === 200;
      } catch {
        robotsFound = null;
      }

      if (verified) {
        safeRecheck = await timed("recheck", "Safe recheck", async () => {
          const againRes = await pinRequest({
            protocol: "https",
            ip,
            hostname: host,
            path: "/",
            timeoutMs: 8000,
            maxBytes: 0,
            method: "HEAD",
          });
          return {
            status: "ok" as const,
            detail: `Second fetch status ${againRes.status}. Body not stored.`,
            value: { status: againRes.status, note: "Verified control. A second homepage request was made and discarded after the status line." },
          };
        }).catch(() => null);
      } else {
        collectors.push({
          id: "recheck",
          title: "Safe recheck",
          status: "denied",
          detail: "Proof of control was not accepted on this pass.",
          durationMs: 0,
        });
      }
    }
  }

  const ct = await timed("ct", "Certificate log", async () => {
    try {
      const url = `https://crt.sh/?q=${encodeURIComponent(registrable)}&output=json`;
      const res = await fetch(url, {
        headers: { accept: "application/json", "user-agent": UA },
        signal: AbortSignal.timeout(7000),
        redirect: "manual",
      });
      if (res.status >= 300 && res.status < 400) {
        return { status: "error" as const, detail: "Certificate log redirected. Not followed.", value: { names: [] as string[], error: "redirect" } };
      }
      if (!res.ok) {
        return { status: "error" as const, detail: `Certificate log HTTP ${res.status}. No names were added.`, value: { names: [] as string[], error: `HTTP ${res.status}` } };
      }
      const reader = res.body?.getReader();
      if (!reader) return { status: "empty" as const, detail: "Certificate log returned no body.", value: { names: [] as string[], error: "empty" } };
      const chunks: Uint8Array[] = [];
      let received = 0;
      while (true) {
        const step = await reader.read();
        if (step.done) break;
        received += step.value.byteLength;
        if (received > 400_000) {
          await reader.cancel();
          return { status: "empty" as const, detail: "Certificate log was too large and was discarded.", value: { names: [] as string[], error: "oversized" } };
        }
        chunks.push(step.value);
      }
      const text = new TextDecoder().decode(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
      if (!text.trim().startsWith("[")) return { status: "empty" as const, detail: "Certificate log did not return a list.", value: { names: [] as string[], error: "not a list" } };
      const rows = JSON.parse(text) as { name_value?: string; common_name?: string }[];
      const names = new Set<string>();
      for (const row of rows.slice(0, 150)) {
        for (const part of String(row.name_value ?? row.common_name ?? "").split("\n")) {
          const name = part.trim().toLowerCase().replace(/^\*\./, "");
          if (!name || name.includes("*") || name === host) continue;
          if (!(name === registrable || name.endsWith(`.${registrable}`))) continue;
          names.add(name);
          if (names.size >= 12) break;
        }
      }
      return {
        status: names.size ? "ok" : "empty",
        detail: names.size ? `${names.size} name(s), labeled suspected.` : "No additional names.",
        value: { names: [...names], error: undefined as string | undefined },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "certificate log failed";
      return { status: "error" as const, detail: message, value: { names: [] as string[], error: message } };
    }
  }).catch(() => ({ names: [] as string[], error: "certificate log failed" }));

  const rdap = await timed<NonNullable<Observations["rdap"]>>("rdap", "RDAP", async () => {
    const domain = await readRdap(`https://rdap.org/domain/${encodeURIComponent(host)}`);
    const address = ip ? await readRdap(`https://rdap.org/ip/${encodeURIComponent(ip)}`) : null;
    if (domain.error && !address) {
      return { status: "error" as const, detail: domain.error, value: emptyRdap(domain.error) };
    }
    return {
      status: "ok" as const,
      detail: domain.registrar ?? address?.asn ?? "Registration metadata received.",
      value: {
        registrar: domain.registrar,
        statuses: domain.statuses,
        nameservers: domain.nameservers,
        dates: domain.dates,
        entityNote: domain.entityNote,
        asn: address?.asn ?? null,
        networkName: address?.networkName ?? null,
        error: undefined,
      },
    };
  }).catch(() => null);

  collectors.push({ id: "ports", title: "Port scan", status: "denied", detail: "Not part of Prex.", durationMs: 0 });
  collectors.push({
    id: "fuzz",
    title: "Endpoint fuzzing",
    status: "denied",
    detail: "Not part of Prex.",
    durationMs: 0,
  });

  return {
    collectors,
    dynamicPolicy,
    dns,
    rdap,
    http,
    tls,
    ctNames: ct?.names ?? [],
    ctError: ct?.error,
    securityTxt,
    robotsFound,
    lookalikes: [],
    repository: null,
    safeRecheck,
  };
}

function emptyRdap(error: string) {
  return {
    registrar: null,
    statuses: [],
    nameservers: [],
    dates: [],
    entityNote: "Registration data was not available.",
    asn: null,
    networkName: null,
    error,
  };
}

async function readRdap(url: string, depth = 0): Promise<{
  registrar: string | null;
  statuses: string[];
  nameservers: string[];
  dates: { label: string; value: string }[];
  entityNote: string;
  asn: string | null;
  networkName: string | null;
  error?: string;
}> {
  if (depth > 2) return { ...emptyRdap("RDAP redirect limit"), error: "RDAP redirect limit" };
  try {
    const res = await fetch(url, {
      headers: { accept: "application/rdap+json, application/json", "user-agent": UA },
      signal: AbortSignal.timeout(7000),
      redirect: "manual",
    });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { ...emptyRdap("RDAP redirect was empty"), error: "RDAP redirect was empty" };
      const next = new URL(loc, url);
      if (next.protocol !== "https:") return { ...emptyRdap("RDAP redirect was not HTTPS"), error: "RDAP redirect was not HTTPS" };
      if (isUnsafeRdapHost(next.hostname)) return { ...emptyRdap("RDAP redirect host was refused"), error: "RDAP redirect host was refused" };
      return readRdap(next.toString(), depth + 1);
    }
    if (!res.ok) return { ...emptyRdap(`RDAP HTTP ${res.status}`), error: `RDAP HTTP ${res.status}` };
    const json = (await res.json()) as Record<string, unknown>;
    const statuses = Array.isArray(json.status) ? json.status.map(String).slice(0, 8) : [];
    const nameservers = Array.isArray(json.nameservers)
      ? json.nameservers
          .map((ns) => (ns && typeof ns === "object" && "ldhName" in ns ? String(ns.ldhName) : ""))
          .filter(Boolean)
          .slice(0, 6)
      : [];
    const dates = Array.isArray(json.events)
      ? json.events
          .map((event) => {
            if (!event || typeof event !== "object") return null;
            const action = "eventAction" in event ? String(event.eventAction) : "event";
            const date = "eventDate" in event ? String(event.eventDate).slice(0, 25) : "";
            return date ? { label: action, value: date } : null;
          })
          .filter((x): x is { label: string; value: string } => Boolean(x))
          .slice(0, 6)
      : [];
    const entityNote = redactEntities(json.entities);
    const networkName = typeof json.name === "string" ? json.name.slice(0, 80) : null;
    let asn: string | null = null;
    if (typeof json.asn === "number" || typeof json.asn === "string") asn = `AS${json.asn}`;
    const registrar =
      findRole(json.entities, "registrar") ??
      (typeof json.port43 === "string" ? null : null);
    return { registrar, statuses, nameservers, dates, entityNote, asn, networkName };
  } catch (error) {
    const message = error instanceof Error ? error.message : "RDAP failed";
    return { ...emptyRdap(message), error: message };
  }
}

function isUnsafeRdapHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(":")) return !isPublicIp(h);
  return false;
}

function findRole(entities: unknown, role: string): string | null {
  if (!Array.isArray(entities)) return null;
  for (const entity of entities) {
    if (!entity || typeof entity !== "object") continue;
    const roles = "roles" in entity && Array.isArray(entity.roles) ? entity.roles.map(String) : [];
    if (!roles.includes(role)) continue;
    const vcard = "vcardArray" in entity ? entity.vcardArray : null;
    const org = vcardValue(vcard, "org") ?? vcardValue(vcard, "fn");
    if (org) return org.slice(0, 80);
  }
  return null;
}

function redactEntities(entities: unknown): string {
  if (!Array.isArray(entities) || entities.length === 0) {
    return "No entity block was published. Prex does not invent an owner.";
  }
  const org = findRole(entities, "registrant") ?? findRole(entities, "administrative");
  if (org && !org.includes("@")) {
    return `Public RDAP organization label: ${org}. This is registration metadata, not proof of who operates the service. Personal names and mailboxes were withheld.`;
  }
  return "RDAP included an entity, and Prex withheld personal names and mailboxes. Redaction is not the same as an unknown company.";
}

function vcardValue(vcard: unknown, key: string): string | null {
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
  for (const row of vcard[1]) {
    if (Array.isArray(row) && String(row[0]).toLowerCase() === key && typeof row[3] === "string") return row[3];
  }
  return null;
}

async function collectIp(ip: string) {
  const collectors: CollectorRun[] = [];
  const start = Date.now();
  const ptr = await doh(ptrName(ip), "PTR");
  const names = ptr.answers.filter((a) => a.type === 12).map((a) => a.data.replace(/\.$/, ""));
  collectors.push({
    id: "dns",
    title: "Reverse DNS",
    status: ptr.error ? "error" : names.length ? "ok" : "empty",
    detail: ptr.error ?? (names.length ? names.join(", ") : "No PTR. Reverse names would not be crawled anyway."),
    durationMs: Date.now() - start,
  });
  const rdapStart = Date.now();
  const rdap = await readRdap(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
  collectors.push({
    id: "rdap",
    title: "RDAP",
    status: rdap.error ? "error" : "ok",
    detail: rdap.error ?? rdap.asn ?? "IP registration metadata.",
    durationMs: Date.now() - rdapStart,
  });
  collectors.push({
    id: "http",
    title: "Homepage headers",
    status: "skipped",
    detail: "A bare IP is not fetched. Shared addresses would mix other tenants.",
    durationMs: 0,
  });
  collectors.push({ id: "ports", title: "Port scan", status: "denied", detail: "Not part of Prex.", durationMs: 0 });
  return { collectors, rdap, ptr: names };
}

function ptrName(ip: string): string {
  if (ip.includes(":")) return ip;
  return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
}

function brandObservations(display: string, now: string): Observations {
  const normalized = normalizeTarget(display);
  const stem = display.toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 24) || "brand";
  const lookalikes = [`${stem}-login.example`, `${stem.replace(/o/g, "0")}.example`, `${stem}s.example`].filter(
    (v, i, arr) => arr.indexOf(v) === i,
  );
  return {
    normalized,
    now,
    demo: false,
    mode: "public",
    verification: { verified: false, method: null, detail: "Brand labels cannot be verified with a DNS token." },
    collectors: [
      { id: "brand", title: "Brand-string indicators", status: "ok", detail: "Generated locally. Not resolved.", durationMs: 5 },
      { id: "dns", title: "DNS", status: "skipped", detail: "No host.", durationMs: 0 },
      { id: "http", title: "Homepage", status: "skipped", detail: "No host.", durationMs: 0 },
      { id: "ports", title: "Port scan", status: "denied", detail: "Not part of Prex.", durationMs: 0 },
    ],
    dynamicPolicy: [],
    dns: null,
    rdap: null,
    http: null,
    tls: null,
    ctNames: [],
    securityTxt: null,
    robotsFound: null,
    lookalikes,
    repository: null,
    scriptedChanges: [],
    safeRecheck: null,
  };
}

const DEMO_TOKEN = "northline-demo-proof";

export async function executeCheck(input: { host: string; method: ProofMethod; token: string }): Promise<CheckResult> {
  const norm = normalizeTarget(input.host);
  if (norm.kind !== "domain" || !norm.host) return { ok: false, error: "Proof checks apply to a public domain you control." };
  if (input.method === "demonstration") {
    if (norm.host !== "northline.example" || input.token !== DEMO_TOKEN) {
      return { ok: false, error: "The demonstration proof is only valid for northline.example." };
    }
    return { ok: true, host: norm.host, method: input.method, detail: "Demonstration proof recorded in this preview. No DNS record was written." };
  }
  if (!/^[a-z0-9_-]{8,80}$/i.test(input.token)) return { ok: false, error: "Token format was rejected." };
  const found = await proofPresent(norm.host, input.method, input.token);
  if (!found.ok) return found;
  return { ok: true, host: norm.host, method: input.method, detail: found.detail };
}

async function proofPresent(
  host: string,
  method: ProofMethod,
  token: string,
): Promise<{ ok: true; detail: string } | { ok: false; error: string }> {
  const resolved = await resolvePublic(host);
  if (resolved.blocked || !resolved.ips[0]) return { ok: false, error: "The host did not resolve to a stable public address." };
  const again = await resolvePublic(host);
  const ip = resolved.ips[0];
  if (again.blocked || !again.ips.includes(ip)) return { ok: false, error: "DNS changed before the proof check. Refused." };
  if (method === "dns") {
    const [dedicated, apex] = await Promise.all([doh(`_prex-verify.${host}`, "TXT"), doh(host, "TXT")]);
    const texts = [...txtJoin(dedicated.answers, 16), ...txtJoin(apex.answers, 16)];
    if (texts.some((t) => t.includes(`prex-verify=${token}`))) {
      return { ok: true, detail: "TXT record matched. Proof will be checked again on the next map." };
    }
    return { ok: false, error: "The TXT value was not found yet. Publish it and check again." };
  }
  if (method === "well-known") {
    try {
      const res = await pinRequest({
        protocol: "https",
        ip,
        hostname: host,
        path: "/.well-known/prex-verification",
        timeoutMs: 7000,
        maxBytes: 2000,
      });
      if (res.body.trim() === token) return { ok: true, detail: "Well-known file matched." };
      return { ok: false, error: "The well-known file did not contain only the token." };
    } catch {
      return { ok: false, error: "The well-known URL could not be read." };
    }
  }
  if (method === "meta") {
    try {
      const res = await pinRequest({
        protocol: "https",
        ip,
        hostname: host,
        path: "/",
        timeoutMs: 7000,
        maxBytes: 180_000,
      });
      const ok = res.body.includes('name="prex-verification"') && res.body.includes(`content="${token}"`);
      if (ok) return { ok: true, detail: "Meta tag matched. Page contents were not stored." };
      return { ok: false, error: "The homepage meta tag was not found." };
    } catch {
      return { ok: false, error: "The homepage could not be read for the meta tag." };
    }
  }
  return { ok: false, error: "Unknown proof method." };
}

export async function executeMap(input: { target?: unknown; proof?: Proof | null }): Promise<MapResult> {
  const target = typeof input.target === "string" ? input.target : "";
  const now = new Date().toISOString();
  const early = normalizeTarget(target);
  const demoHost = early.host === "northline.example" || early.host?.endsWith(".northline.example");
  if (isDemoQuery(target) || demoHost) {
    const proof = input.proof;
    const verified = proof?.method === "demonstration" && proof.token === DEMO_TOKEN;
    return { ok: true, scan: compileScan(northlineObservations(now, verified), newId("scn")) };
  }
  if (early.kind === "rejected") return { ok: false, error: early.rejectReason ?? "Target refused.", code: "rejected" };
  const norm = early;
  const limited = rateLimit(norm.host ?? norm.display.toLowerCase());
  if (limited) return { ok: false, error: limited, code: "rate_limit" };

  let mode: Observations["mode"] = "public";
  let verification: Observations["verification"] = {
    verified: false,
    method: null,
    detail: "No proof was attached. The map stayed passive.",
  };
  if (input.proof && norm.kind === "domain" && norm.host) {
    const check = await executeCheck({ host: norm.host, method: input.proof.method, token: input.proof.token });
    if (check.ok) {
      mode = "verified";
      verification = { verified: true, method: check.method, detail: check.detail };
    } else {
      verification = { verified: false, method: input.proof.method, detail: check.error };
    }
  }

  if (norm.kind === "brand") {
    return { ok: true, scan: compileScan(brandObservations(norm.display, now), newId("scn")) };
  }

  if (norm.kind === "ip" && norm.host) {
    const ipData = await collectIp(norm.host);
    const obs: Observations = {
      normalized: norm,
      now,
      demo: false,
      mode: "public",
      verification,
      collectors: ipData.collectors,
      dynamicPolicy: [],
      dns: {
        records: ipData.ptr.map((value) => ({ type: "PTR", name: norm.host ?? "", value, ttl: "" })),
        spf: null,
        dmarc: null,
        ad: null,
        dangling: [],
      },
      rdap: ipData.rdap.error ? { ...ipData.rdap, error: ipData.rdap.error } : ipData.rdap,
      http: null,
      tls: null,
      ctNames: [],
      securityTxt: null,
      robotsFound: null,
      lookalikes: [],
      repository: null,
      scriptedChanges: [],
      safeRecheck: null,
    };
    return { ok: true, scan: compileScan(obs, newId("scn")) };
  }

  if (norm.kind === "domain" && norm.host) {
    const collected = await collectDomain(norm.host, norm.registrable ?? norm.host, mode === "verified");
    const obs: Observations = {
      normalized: norm,
      now,
      demo: false,
      mode,
      verification,
      scriptedChanges: [],
      ...collected,
    };
    return { ok: true, scan: compileScan(obs, newId("scn")) };
  }

  return { ok: false, error: "Nothing was collected.", code: "empty" };
}
