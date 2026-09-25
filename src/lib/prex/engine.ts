import { buildLens } from "./dossier.ts";
import type {
  Asset,
  AssetStatus,
  ChangeEvent,
  Evidence,
  Factors,
  Finding,
  Markers,
  NormalizedTarget,
  Observations,
  PlanStep,
  PolicyDecision,
  Positive,
  Relation,
  ScanMode,
  ScanRecord,
  Severity,
  TargetKind,
} from "./types.ts";

const MULTI_PART = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.jp",
  "com.br",
  "com.mx",
  "co.za",
  "com.sg",
  "co.in",
  "com.tr",
  "co.kr",
  "com.hk",
  "co.nz",
]);

const DEMO_INPUTS = new Set([
  "northline",
  "northline freight",
  "northline demo",
  "prex demo",
  "demo",
  "northline.example",
  "www.northline.example",
]);

export function isDemoQuery(input: string): boolean {
  return DEMO_INPUTS.has(input.trim().toLowerCase().replace(/\s+/g, " "));
}

export function registrableDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length < 2) return parts.join(".");
  const last2 = parts.slice(-2).join(".");
  if (MULTI_PART.has(last2) && parts.length >= 3) return parts.slice(-3).join(".");
  return last2;
}

export function isPublicIp(ip: string): boolean {
  const raw = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (raw.startsWith("::ffff:")) return isPublicV4(raw.slice("::ffff:".length));
  if (raw.includes(":")) {
    if (raw === "::1" || raw === "::") return false;
    const first = (raw.split("::")[0] ?? "0").split(":")[0] || "0";
    const n = Number.parseInt(first, 16);
    if (Number.isNaN(n)) return false;
    if ((n & 0xfe00) === 0xfc00) return false;
    if ((n & 0xffc0) === 0xfe80) return false;
    if ((n & 0xff00) === 0xff00) return false;
    return true;
  }
  return isPublicV4(raw);
}

function isPublicV4(ip: string): boolean {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  const p = ip.split(".").map((n) => Number(n));
  if (p.some((n) => n > 255)) return false;
  const a = p[0] ?? 0;
  const b = p[1] ?? 0;
  if (a === 0 || a === 10 || a === 127 || a === 255) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a >= 224) return false;
  return true;
}

export function isIpLiteral(value: string): boolean {
  const v = value.replace(/^\[|\]$/g, "");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return v.split(".").every((n) => Number(n) <= 255);
  return v.includes(":") && /^[0-9a-f:]+$/i.test(v);
}

function blockedHost(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".localdomain") ||
    h === "metadata.google.internal" ||
    h === "metadata.goog"
  ) {
    return "That name is local or internal. Prex will not contact it.";
  }
  return null;
}

export function normalizeTarget(input: string): NormalizedTarget {
  const raw = input.trim();
  const notes: string[] = [];
  if (!raw || raw.length > 200) {
    return reject(raw, raw ? "That input is too long." : "Enter a domain, URL, IP, or brand.");
  }
  if (/[\u0000-\u001f\u007f]/.test(raw)) return reject(raw, "Control characters are not allowed.");

  if (!raw.includes("://") && !raw.startsWith("//") && /[^\s.]+(?:\s+[^\s.]+)+/.test(raw) && !raw.includes("/")) {
    return asBrand(raw, notes);
  }

  let url: URL;
  try {
    url = new URL(raw.includes("://") || raw.startsWith("//") ? raw : `https://${raw}`);
  } catch {
    if (!raw.includes(".") && !raw.includes(":")) return asBrand(raw, notes);
    return reject(raw, "That does not parse as a public host, IP, or brand.");
  }

  if (url.username || url.password) return reject(raw, "Userinfo in the URL was rejected.");
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return reject(raw, "Only http and https URLs are accepted. Other schemes are refused.");
  }
  if (url.port && url.port !== "443" && url.port !== "80") {
    return reject(raw, "Non-default ports are refused. Prex does not scan arbitrary ports.");
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return reject(raw, "Missing host.");
  if (raw.includes("://") && url.pathname && url.pathname !== "/") {
    notes.push("Path and query were stripped. Prex maps the host; it does not crawl.");
  } else if (url.search || url.hash) {
    notes.push("Query and fragment were stripped.");
  }
  if (url.protocol === "http:") notes.push("HTTP was noted. The map prefers HTTPS for the page request.");

  if (isIpLiteral(host)) {
    if (!isPublicIp(host)) return reject(raw, "Private, loopback, and link-local addresses are blocked.");
    return {
      input: raw,
      kind: "ip",
      display: host,
      host,
      registrable: null,
      notes,
      rejectReason: null,
    };
  }

  const blocked = blockedHost(host);
  if (blocked) return reject(raw, blocked);
  if (!host.includes(".") || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(host)) {
    return reject(raw, "That hostname is not a public DNS name Prex will query.");
  }
  if (host !== url.hostname.toLowerCase()) notes.push("The name was converted to ASCII (punycode) for lookup.");

  return {
    input: raw,
    kind: "domain",
    display: host,
    host,
    registrable: registrableDomain(host),
    notes,
    rejectReason: null,
  };
}

function asBrand(raw: string, notes: string[]): NormalizedTarget {
  const display = raw.replace(/\s+/g, " ").trim();
  if (display.length < 2 || display.length > 60 || !/^[\p{L}\p{N}][\p{L}\p{N}&' ._'-]*[\p{L}\p{N}]$/u.test(display)) {
    return reject(raw, "Brand names here are plain text, 2–60 characters, without a URL.");
  }
  notes.push("Treated as a brand label. Lookalike strings are generated and not resolved.");
  return {
    input: raw,
    kind: "brand",
    display,
    host: null,
    registrable: null,
    notes,
    rejectReason: null,
  };
}

function reject(input: string, reason: string): NormalizedTarget {
  return {
    input,
    kind: "rejected",
    display: input.trim().slice(0, 80),
    host: null,
    registrable: null,
    notes: [],
    rejectReason: reason,
  };
}

export function targetKey(norm: NormalizedTarget): string {
  if (norm.kind === "domain" && norm.host) return `domain:${norm.host}`;
  if (norm.kind === "ip" && norm.host) return `ip:${norm.host}`;
  if (norm.kind === "brand") return `brand:${norm.display.toLowerCase()}`;
  return "rejected";
}

export function bandFor(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

export function explainScore(f: Factors): { score: number; severity: Severity; formula: string } {
  const raw = f.exposure * f.impact * f.exploitability * f.confidence * f.criticality * 1.35;
  const score = Math.max(0, Math.min(100, Math.round(raw)));
  const formula = `${f.exposure} × ${f.impact} × ${f.exploitability} × ${f.confidence.toFixed(2)} × ${f.criticality.toFixed(2)} × 1.35 = ${raw.toFixed(1)} → ${score}`;
  return { score, severity: bandFor(score), formula };
}

export function policyFor(mode: ScanMode, kind: TargetKind): PolicyDecision[] {
  const decisions: PolicyDecision[] = [];
  const allow = (action: string, reason: string, when = true) => {
    decisions.push({ action, decision: when ? "allow" : "deny", reason });
  };

  allow(
    "Normalize target",
    "Input is canonicalized, and private or non-default-port targets are refused.",
  );
  allow(
    "Public DNS",
    kind === "brand" ? "Brand mode does not resolve lookalike names." : "Passive DNS metadata for the named host only.",
    kind === "domain" || kind === "ip",
  );
  allow(
    "RDAP registration",
    kind === "brand" ? "No host was given to look up." : "Public registration metadata. Personal contacts are withheld.",
    kind === "domain" || kind === "ip",
  );
  allow(
    "Homepage and TLS observe",
    kind === "domain"
      ? "One HTTPS page load and a TLS handshake on 443, plus a header-only check on port 80."
      : "HTTP is not fetched for a bare IP or a brand label in this preview.",
    kind === "domain",
  );
  allow(
    "Certificate log names",
    kind === "domain"
      ? "Public certificate-transparency names are labeled suspected, not owned."
      : "Certificate-name search is domain-scoped.",
    kind === "domain",
  );
  allow(
    "security.txt and robots.txt",
    kind === "domain" ? "Two well-known public URLs on the same host." : "No host to read.",
    kind === "domain",
  );
  allow(
    "Safe recheck",
    mode === "verified"
      ? "Control was proved for this pass, so a second homepage fetch is allowed. Nothing is submitted or mutated."
      : "A second validated fetch waits until this host proves control.",
    mode === "verified" && kind === "domain",
  );

  const denies: PolicyDecision[] = [
    { action: "Port scan", decision: "deny", reason: "Ports other than 80 and 443 are never probed." },
    { action: "Endpoint fuzzing", decision: "deny", reason: "Path brute force and content discovery wordlists are not run." },
    { action: "Credential attacks", decision: "deny", reason: "No login attempts, stuffing, or password spraying." },
    { action: "Exploit execution", decision: "deny", reason: "Prex does not generate or run payloads." },
    { action: "Private network", decision: "deny", reason: "Loopback, link-local, and RFC1918 targets are blocked, including after DNS resolution." },
    { action: "Secret display", decision: "deny", reason: "Secret values are never stored, logged, or rendered." },
    { action: "Person dossier", decision: "deny", reason: "Prex does not profile individuals or scrape social accounts." },
    {
      action: "Stolen credential contents",
      decision: "deny",
      reason: "Breach corpora are not queried for passwords or message bodies. Only a withheld aggregate signal is described.",
    },
  ];
  if (mode === "public") {
    denies.unshift({
      action: "Authenticated testing",
      decision: "deny",
      reason: "Logged-in application tests stay off without a verified scope.",
    });
  } else {
    denies.unshift({
      action: "Authenticated testing",
      decision: "deny",
      reason: "Even after domain proof, this preview does not log in, fuzz, or exploit. Those modules are not shipped.",
    });
  }
  return [...decisions, ...denies];
}

export function collectorPreview(norm: NormalizedTarget, mode: ScanMode): { title: string; expect: "run" | "skip" | "deny" }[] {
  if (norm.kind === "rejected") return [];
  if (norm.kind === "brand") {
    return [
      { title: "Brand-string indicators", expect: "run" },
      { title: "DNS, RDAP, HTTP, TLS", expect: "skip" },
      { title: "Port scan and exploits", expect: "deny" },
    ];
  }
  return [
    { title: "DNS and mail posture", expect: "run" },
    { title: "RDAP", expect: "run" },
    { title: norm.kind === "domain" ? "TLS and homepage headers" : "HTTP", expect: norm.kind === "domain" ? "run" : "skip" },
    { title: "Certificate log", expect: norm.kind === "domain" ? "run" : "skip" },
    { title: "Public description", expect: norm.kind === "domain" ? "run" : "skip" },
    { title: mode === "verified" ? "Safe recheck" : "Safe recheck (locked)", expect: mode === "verified" ? "run" : "deny" },
    { title: "Port scan, fuzzing, exploits", expect: "deny" },
  ];
}

const BASE_LIMITS = [
  "This is a public-exposure map, not a penetration test. A quiet rule set is not a clean bill of health.",
  "Only the named host was in scope. Cousin domains and certificate-log names were not treated as owned and were not crawled.",
  "Ports other than 80 and 443 were not contacted. No forms were submitted.",
  "Hosting, CDN, and certificate issuer are observations. They are not an identity of the operator.",
  "Personal data in registration records is withheld. Stolen credential contents are never retrieved.",
];

export function deriveChanges(prev: ScanRecord, next: ScanRecord): ChangeEvent[] {
  if (prev.targetKey !== next.targetKey) return [];
  const changes: ChangeEvent[] = [];
  const before = new Set(prev.markers.assetLabels);
  const after = new Set(next.markers.assetLabels);
  for (const label of next.markers.assetLabels) {
    if (!before.has(label)) {
      changes.push({
        id: `chg-add-${label}`,
        kind: "added",
        title: `New observed label: ${label}`,
        detail: "Present on this map and absent on the previous map stored in this browser.",
      });
    }
  }
  for (const label of prev.markers.assetLabels) {
    if (!after.has(label)) {
      changes.push({
        id: `chg-rm-${label}`,
        kind: "removed",
        title: `No longer observed: ${label}`,
        detail: "Present on the previous map and absent now. Removal is not proof the asset is gone everywhere.",
      });
    }
  }
  const flag = (
    id: string,
    was: boolean,
    now: boolean,
    lost: string,
    gained: string,
  ) => {
    if (was && !now) changes.push({ id, kind: "regressed", title: lost, detail: "Compared with the previous map in this browser." });
    if (!was && now) changes.push({ id, kind: "improved", title: gained, detail: "Compared with the previous map in this browser." });
  };
  flag("chg-hsts", prev.markers.hsts, next.markers.hsts, "HSTS header no longer observed", "HSTS header now observed");
  flag("chg-csp", prev.markers.csp, next.markers.csp, "Content-Security-Policy no longer observed", "Content-Security-Policy now observed");
  flag("chg-cdn", prev.markers.cdn, next.markers.cdn, "CDN response signal no longer observed", "CDN response signal now observed");
  if (prev.markers.dmarc !== next.markers.dmarc) {
    const weaker = rankDmarc(next.markers.dmarc) < rankDmarc(prev.markers.dmarc);
    changes.push({
      id: "chg-dmarc",
      kind: weaker ? "regressed" : "improved",
      title: `DMARC policy changed: ${prev.markers.dmarc ?? "absent"} → ${next.markers.dmarc ?? "absent"}`,
      detail: "Taken from the TXT record at _dmarc for each map.",
    });
  }
  if (prev.markers.spfTail !== next.markers.spfTail) {
    changes.push({
      id: "chg-spf",
      kind: "regressed",
      title: `SPF all-mechanism changed: ${prev.markers.spfTail ?? "absent"} → ${next.markers.spfTail ?? "absent"}`,
      detail: "A change is flagged for review. It is not automatically a vulnerability.",
    });
  }
  if (
    next.markers.certDays != null &&
    (prev.markers.certDays == null || prev.markers.certDays > 21) &&
    next.markers.certDays <= 21
  ) {
    changes.push({
      id: "chg-cert",
      kind: "regressed",
      title: `Certificate window is now ${next.markers.certDays} day(s)`,
      detail: "Crossed the 21-day watch line since the previous map.",
    });
  }
  const oldFindings = new Set(prev.markers.findingIds);
  for (const id of next.markers.findingIds) {
    if (!oldFindings.has(id)) {
      const finding = next.findings.find((f) => f.id === id);
      changes.push({
        id: `chg-f-${id}`,
        kind: "added",
        title: finding ? `New rule result: ${finding.title}` : "New rule result",
        detail: "This rule id was not on the previous map.",
      });
    }
  }
  return changes.slice(0, 12);
}

function rankDmarc(policy: string | null): number {
  if (policy === "reject") return 3;
  if (policy === "quarantine") return 2;
  if (policy === "none") return 1;
  return 0;
}

function headerValue(headers: { name: string; value: string }[], name: string): string | null {
  return headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? null;
}

export function compileScan(obs: Observations, id: string): ScanRecord {
  const evidence: Evidence[] = [];
  const assets: Asset[] = [];
  const relations: Relation[] = [];
  const findings: Finding[] = [];
  const positives: Positive[] = [];
  const method = obs.mode === "verified" ? "verified-safe-check" : "passive";

  const ev = (partial: Omit<Evidence, "id" | "collectedAt" | "method"> & { method?: Evidence["method"] }) => {
    const item: Evidence = {
      id: `ev-${evidence.length + 1}`,
      collectedAt: obs.now,
      method: partial.method ?? "passive",
      source: partial.source,
      summary: partial.summary,
      fields: partial.fields.slice(0, 24).map((f) => ({
        label: f.label.slice(0, 80),
        value: f.value.slice(0, 500),
      })),
    };
    evidence.push(item);
    return item.id;
  };

  const addAsset = (asset: Omit<Asset, "id"> & { id?: string }) => {
    const item: Asset = { ...asset, id: asset.id ?? `${asset.kind}:${asset.label.toLowerCase()}` };
    if (!assets.some((a) => a.id === item.id)) assets.push(item);
    return item.id;
  };

  const link = (from: string, to: string, type: string) => {
    relations.push({ id: `rel-${relations.length + 1}`, from, to, type });
  };

  const norm = obs.normalized;
  const rootStatus: AssetStatus = obs.demo
    ? "customer-confirmed"
    : obs.mode === "verified"
      ? "verified-owned"
      : "observed";

  let rootId = "";
  if (norm.kind === "domain" && norm.host) {
    rootId = addAsset({
      kind: "domain",
      label: norm.host,
      status: rootStatus,
      confidence: obs.mode === "verified" || obs.demo ? 0.95 : 0.7,
      summary: obs.demo
        ? "Demonstration tenant. Not a live host."
        : obs.mode === "verified"
          ? "Host matched a proof of control on this pass."
          : "Named by the operator of this map. Ownership is not otherwise proved.",
      evidenceIds: [],
    });
  } else if (norm.kind === "ip" && norm.host) {
    rootId = addAsset({
      kind: "ip",
      label: norm.host,
      status: "observed",
      confidence: 0.9,
      summary: "Public IP supplied as the target. Reverse names are not treated as ownership.",
      evidenceIds: [],
    });
  } else if (norm.kind === "brand") {
    rootId = addAsset({
      kind: "brand",
      label: norm.display,
      status: obs.demo ? "customer-confirmed" : "observed",
      confidence: 0.4,
      summary: "Label supplied by the person running the map. Not resolved to a company registry.",
      evidenceIds: [],
    });
  }

  if (obs.dns) {
    const dnsId = ev({
      source: obs.demo ? "demonstration dataset" : "DNS-over-HTTPS (Cloudflare)",
      summary: obs.dns.error
        ? `DNS lookup problem: ${obs.dns.error}`
        : `DNS answers for ${norm.host ?? norm.display}.`,
      fields: [
        ...obs.dns.records.slice(0, 40).map((r) => ({ label: r.type, value: `${r.name} ${r.value}` })),
        { label: "SPF", value: obs.dns.spf ?? "No SPF TXT observed" },
        { label: "DMARC", value: obs.dns.dmarc ?? "No DMARC TXT observed" },
        {
          label: "AD bit",
          value:
            obs.dns.ad == null
              ? "Not available"
              : obs.dns.ad
                ? "Set by the resolver. Prex did not validate the DNSSEC chain itself."
                : "Not set. This is not proof the zone is unsigned.",
        },
      ],
    });
    const root = assets.find((a) => a.id === rootId);
    if (root) root.evidenceIds = [...root.evidenceIds, dnsId];

    for (const rec of obs.dns.records.filter((r) => r.type === "A" || r.type === "AAAA")) {
      const ipId = addAsset({
        kind: "ip",
        label: rec.value,
        status: "observed",
        confidence: 0.9,
        summary: "Address returned for the queried name. Shared hosting is possible.",
        evidenceIds: [dnsId],
      });
      if (rootId) link(rootId, ipId, "resolves to");
    }
    const mx = obs.dns.records.filter((r) => r.type === "MX");
    if (mx.length && rootId) {
      const mailId = addAsset({
        kind: "mail",
        label: mx.map((r) => r.value).join(", "),
        status: "observed",
        confidence: 0.85,
        summary: "MX targets from public DNS. The mailbox provider is not the domain owner.",
        evidenceIds: [dnsId],
      });
      link(rootId, mailId, "mail via");
    }
    for (const dangle of obs.dns.dangling) {
      const subId = addAsset({
        kind: "subdomain",
        label: dangle.host,
        status: "suspected",
        confidence: 0.55,
        summary: "CNAME observed without a public address. Review required. This is not a confirmed takeover.",
        evidenceIds: [dnsId],
      });
      if (rootId) link(rootId, subId, "cname");
    }
  }

  if (obs.rdap) {
    const rdapId = ev({
      source: obs.demo ? "demonstration dataset" : "RDAP",
      summary: obs.rdap.error ? `RDAP problem: ${obs.rdap.error}` : "Public registration metadata.",
      fields: [
        { label: "Registrar", value: obs.rdap.registrar ?? "Not stated" },
        { label: "Network or ASN", value: [obs.rdap.asn, obs.rdap.networkName].filter(Boolean).join(" · ") || "Not stated" },
        { label: "Status", value: obs.rdap.statuses.join(", ") || "Not stated" },
        { label: "Nameservers", value: obs.rdap.nameservers.join(", ") || "Not stated" },
        ...obs.rdap.dates.map((d) => ({ label: d.label, value: d.value })),
        { label: "Entity", value: obs.rdap.entityNote },
      ],
    });
    const root = assets.find((a) => a.id === rootId);
    if (root) root.evidenceIds = [...root.evidenceIds, rdapId];
    if (obs.rdap.asn) {
      const asnId = addAsset({
        kind: "asn",
        label: obs.rdap.asn,
        status: "observed",
        confidence: 0.8,
        summary: obs.rdap.networkName
          ? `Network name on the RDAP response: ${obs.rdap.networkName}. An ASN does not identify a website operator by itself.`
          : "ASN from public IP registration data.",
        evidenceIds: [rdapId],
      });
      const ip = assets.find((a) => a.kind === "ip");
      if (ip) link(ip.id, asnId, "announced by");
      else if (rootId) link(rootId, asnId, "registration");
    }
  }

  let httpEv: string | null = null;
  if (obs.http) {
    httpEv = ev({
      source: obs.demo ? "demonstration dataset" : "HTTPS GET /",
      summary: obs.http.error
        ? `Homepage was not read: ${obs.http.error}`
        : `HTTP ${obs.http.status ?? "unknown"} from ${obs.http.url}.`,
      fields: [
        { label: "Status", value: obs.http.status == null ? "none" : String(obs.http.status) },
        { label: "Title", value: obs.http.title ?? "No title parsed" },
        ...obs.http.headers.map((h) => ({ label: h.name, value: h.value })),
        ...obs.http.cookies.map((c) => ({
          label: `Cookie ${c.name}`,
          value: `Secure=${c.secure} HttpOnly=${c.httpOnly} SameSite=${c.sameSite ?? "absent"} (value withheld)`,
        })),
        { label: "Redirect notes", value: obs.http.redirectNotes.join(" | ") || "None" },
        { label: "Scripts observed", value: obs.http.scripts.join(", ") || "None parsed" },
      ],
    });
    if (!obs.http.error && obs.http.status && rootId && norm.host) {
      const serviceId = addAsset({
        kind: "service",
        label: `https://${norm.host}/`,
        status: rootStatus === "customer-confirmed" ? "customer-confirmed" : "observed",
        confidence: 0.9,
        summary: "Single homepage response. Not a site crawl.",
        evidenceIds: [httpEv],
      });
      link(rootId, serviceId, "serves");
      for (const tech of obs.http.technologies) {
        const techId = addAsset({
          kind: "technology",
          label: tech.name,
          status: "observed",
          confidence: tech.confidence,
          summary: tech.evidence,
          evidenceIds: [httpEv],
        });
        link(serviceId, techId, "fingerprint");
      }
    }
  }

  let tlsEv: string | null = null;
  if (obs.tls) {
    tlsEv = ev({
      source: obs.demo ? "demonstration dataset" : "TLS handshake (observe only)",
      summary: obs.tls.error
        ? `TLS handshake did not complete: ${obs.tls.error}`
        : `Certificate presented by ${norm.host}.`,
      fields: [
        { label: "Subject", value: obs.tls.subject ?? "Unknown" },
        { label: "Issuer", value: obs.tls.issuer ?? "Unknown" },
        { label: "Valid from", value: obs.tls.validFrom ?? "Unknown" },
        { label: "Valid to", value: obs.tls.validTo ?? "Unknown" },
        { label: "Days remaining", value: obs.tls.daysRemaining == null ? "Unknown" : String(obs.tls.daysRemaining) },
        { label: "Protocol", value: obs.tls.protocol ?? "Unknown" },
        { label: "Hostname check", value: obs.tls.hostnameMismatch ? "Mismatch" : obs.tls.authorized ? "Matched" : (obs.tls.authError ?? "Not confirmed") },
        { label: "SANs", value: obs.tls.sans.slice(0, 12).join(", ") || "None parsed" },
      ],
    });
    if (!obs.tls.error && rootId) {
      const certId = addAsset({
        kind: "certificate",
        label: obs.tls.subject || norm.host || "certificate",
        status: "observed",
        confidence: 0.9,
        summary: `Issuer: ${obs.tls.issuer ?? "unstated"}. A certificate name is not proof of corporate ownership.`,
        evidenceIds: [tlsEv],
      });
      link(rootId, certId, "presents");
    }
  }

  if (obs.ctNames.length && rootId) {
    const ctId = ev({
      source: obs.demo ? "demonstration dataset" : "Certificate transparency (crt.sh)",
      summary: `${obs.ctNames.length} name(s) from public certificate logs. Discovered, not owned.`,
      fields: obs.ctNames.map((n) => ({ label: "Name", value: n })),
    });
    for (const name of obs.ctNames) {
      if (name === norm.host) continue;
      const id = addAsset({
        kind: "subdomain",
        label: name,
        status: "suspected",
        confidence: 0.46,
        summary: "Seen in a public certificate log. Prex did not resolve or request this name unless it was also in DNS for the target.",
        evidenceIds: [ctId],
      });
      link(rootId, id, "certificate log");
    }
  } else if (obs.ctError) {
    ev({
      source: "Certificate transparency (crt.sh)",
      summary: `Certificate log was not usable: ${obs.ctError}`,
      fields: [{ label: "Result", value: "No names added. Absence of a log result is not absence of names." }],
    });
  }

  if (obs.securityTxt) {
    const docIdEv = ev({
      source: obs.demo ? "demonstration dataset" : "GET /.well-known/security.txt",
      summary: obs.securityTxt.found ? "security.txt is published." : "security.txt was not found at the well-known path.",
      fields: [
        { label: "Contacts", value: obs.securityTxt.contacts.join(", ") || "None parsed" },
        { label: "Excerpt", value: obs.securityTxt.excerpt || "Empty" },
      ],
    });
    if (obs.securityTxt.found && rootId) {
      const docId = addAsset({
        kind: "document",
        label: "/.well-known/security.txt",
        status: "observed",
        confidence: 0.95,
        summary: "Published security contact. This is the disclosure channel the site chose to advertise.",
        evidenceIds: [docIdEv],
      });
      link(rootId, docId, "publishes");
    }
  }

  if (obs.lookalikes.length && rootId) {
    const lookEv = ev({
      source: obs.demo ? "demonstration dataset" : "local string generator",
      summary: "Lookalike strings were generated and not queried. They are indicators, not confirmed impersonation.",
      fields: obs.lookalikes.map((n) => ({ label: "String", value: n })),
    });
    for (const name of obs.lookalikes) {
      const id = addAsset({
        kind: "brand",
        label: name,
        status: "suspected",
        confidence: 0.2,
        summary: "Typo or homoglyph candidate. DNS and HTTP were intentionally not used.",
        evidenceIds: [lookEv],
      });
      link(rootId, id, "indicator");
    }
  }

  if (obs.repository && rootId) {
    const repoEv = ev({
      source: "demonstration dataset",
      summary: obs.repository.note,
      fields: [{ label: "Repository", value: obs.repository.label }],
    });
    const repoId = addAsset({
      kind: "repository",
      label: obs.repository.label,
      status: "customer-confirmed",
      confidence: 0.5,
      summary: obs.repository.note,
      evidenceIds: [repoEv],
    });
    link(rootId, repoId, "declared in demo");
  }

  if (obs.safeRecheck) {
    ev({
      source: "verified safe recheck",
      method: "verified-safe-check",
      summary: obs.safeRecheck.note,
      fields: [{ label: "Status", value: obs.safeRecheck.status == null ? "none" : String(obs.safeRecheck.status) }],
    });
  }

  const hsts = !!obs.http && headerValue(obs.http.headers, "strict-transport-security");
  const csp = !!obs.http && (headerValue(obs.http.headers, "content-security-policy") || headerValue(obs.http.headers, "content-security-policy-report-only"));
  const xfo = !!obs.http && headerValue(obs.http.headers, "x-frame-options");
  const xcto = !!obs.http && headerValue(obs.http.headers, "x-content-type-options");
  const referrer = !!obs.http && headerValue(obs.http.headers, "referrer-policy");
  const server = obs.http ? headerValue(obs.http.headers, "server") : null;
  const dmarcPolicy = dmarcTag(obs.dns?.dmarc ?? null);
  const spfTail = spfAll(obs.dns?.spf ?? null);
  const hasMx = !!obs.dns?.records.some((r) => r.type === "MX");
  const serviceAsset = assets.find((a) => a.kind === "service")?.id ?? rootId;
  const certAsset = assets.find((a) => a.kind === "certificate")?.id ?? rootId;
  const mailAsset = assets.find((a) => a.kind === "mail")?.id ?? rootId;

  const pushFinding = (draft: {
    ruleId: string;
    title: string;
    category: string;
    factors: Factors;
    factorNotes: { factor: string; note: string }[];
    rationale: string;
    whyItMatters: string;
    remediation: string;
    references: string[];
    assetId: string;
    evidenceIds: string[];
    observation?: Finding["observation"];
  }) => {
    if (!draft.assetId) return;
    const explained = explainScore(draft.factors);
    findings.push({
      id: `${draft.ruleId}:${draft.assetId}`,
      ruleId: draft.ruleId,
      title: draft.title,
      category: draft.category,
      severity: explained.severity,
      score: explained.score,
      formula: explained.formula,
      factors: draft.factors,
      factorNotes: draft.factorNotes,
      rationale: draft.rationale,
      whyItMatters: draft.whyItMatters,
      remediation: draft.remediation,
      references: draft.references,
      assetId: draft.assetId,
      evidenceIds: draft.evidenceIds,
      confidence: draft.factors.confidence,
      observation: draft.observation ?? method,
    });
  };

  if (obs.http && !obs.http.error && obs.http.status && obs.http.url.startsWith("https://") && !hsts) {
    pushFinding({
      ruleId: "hsts-missing",
      title: "HTTP Strict Transport Security was not observed",
      category: "Transport",
      factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.95, criticality: 0.7 },
      factorNotes: [
        { factor: "Exposure", note: "The homepage is on the public internet, so a first visit can still be intercepted before HTTPS sticks." },
        { factor: "Impact", note: "Limited to transport downgrade resistance. Not treated as site compromise." },
        { factor: "Exploitability", note: "Requires a network position. No exploit was attempted." },
        { factor: "Confidence", note: "The response headers were read directly." },
        { factor: "Criticality", note: "Default business weight. The customer has not labeled this host." },
      ],
      rationale: "The final HTTPS response did not include a Strict-Transport-Security header.",
      whyItMatters: "Browsers will not remember to force HTTPS for later visits. That matters most on networks you do not trust.",
      remediation: "Send Strict-Transport-Security with a max-age of at least 15552000 after you have confirmed HTTPS works. Add includeSubDomains and preload only when every subdomain is ready.",
      references: ["https://datatracker.ietf.org/doc/html/rfc6797"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  } else if (hsts) {
    positives.push({
      id: "pos-hsts",
      title: "HSTS is present",
      detail: hsts,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http && !obs.http.error && obs.http.status && !csp) {
    pushFinding({
      ruleId: "csp-missing",
      title: "No Content-Security-Policy was observed",
      category: "Browser controls",
      factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.9, criticality: 0.65 },
      factorNotes: [
        { factor: "Exposure", note: "The document is served to browsers." },
        { factor: "Impact", note: "CSP is defense in depth. Its absence is not an injection flaw." },
        { factor: "Exploitability", note: "Low until a content-injection bug exists. None was tested." },
        { factor: "Confidence", note: "Header absence was observed on this response only." },
        { factor: "Criticality", note: "Slightly reduced because a single document may not represent the app." },
      ],
      rationale: "Neither Content-Security-Policy nor a report-only policy was on the homepage response.",
      whyItMatters: "A policy would constrain script sources if a later bug injected markup. It does not, by itself, prove such a bug.",
      remediation: "Start with Content-Security-Policy-Report-Only, watch violations, then enforce a host allowlist. Avoid unsafe-inline on new applications.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  } else if (csp) {
    positives.push({
      id: "pos-csp",
      title: "A content security policy header is present",
      detail: "Prex did not judge whether the policy is strict.",
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http && !obs.http.error && obs.http.status && !xfo && !(csp && /frame-ancestors/i.test(csp))) {
    pushFinding({
      ruleId: "frame-control-missing",
      title: "No framing control was observed",
      category: "Browser controls",
      factors: { exposure: 3, impact: 2, exploitability: 2, confidence: 0.9, criticality: 0.6 },
      factorNotes: [
        { factor: "Exposure", note: "The page can be embedded if the application also has a state-changing action." },
        { factor: "Impact", note: "Clickjacking depends on the page. A static homepage is often low impact." },
        { factor: "Exploitability", note: "Not demonstrated." },
        { factor: "Confidence", note: "Headers of this one response." },
        { factor: "Criticality", note: "Unknown whether the document is sensitive." },
      ],
      rationale: "X-Frame-Options was absent and the CSP, if any, did not show frame-ancestors.",
      whyItMatters: "Framing controls matter on pages where a click performs an action. They matter less on a public brochure page.",
      remediation: "Set Content-Security-Policy: frame-ancestors 'none' or 'self', or X-Frame-Options: DENY, on documents that are not meant to be embedded.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http && !obs.http.error && obs.http.status && !xcto) {
    pushFinding({
      ruleId: "nosniff-missing",
      title: "X-Content-Type-Options was not observed",
      category: "Browser controls",
      factors: { exposure: 2, impact: 2, exploitability: 1, confidence: 0.9, criticality: 0.55 },
      factorNotes: [
        { factor: "Exposure", note: "Relevant when the origin also serves user-controlled files." },
        { factor: "Impact", note: "MIME sniffing is a narrow browser behavior." },
        { factor: "Exploitability", note: "Not demonstrated." },
        { factor: "Confidence", note: "Direct header observation." },
        { factor: "Criticality", note: "Low default weight." },
      ],
      rationale: "The homepage did not send X-Content-Type-Options: nosniff.",
      whyItMatters: "Some browsers may sniff content types. This is informational unless the origin hosts untrusted files.",
      remediation: "Send X-Content-Type-Options: nosniff on all responses.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http && !obs.http.error && obs.http.status && !referrer) {
    pushFinding({
      ruleId: "referrer-missing",
      title: "Referrer-Policy was not observed",
      category: "Browser controls",
      factors: { exposure: 2, impact: 2, exploitability: 1, confidence: 0.85, criticality: 0.5 },
      factorNotes: [
        { factor: "Exposure", note: "Only matters if URLs carry sensitive query values." },
        { factor: "Impact", note: "Informational on a typical marketing host." },
        { factor: "Exploitability", note: "No sensitive URL was assumed." },
        { factor: "Confidence", note: "Header absence on this response." },
        { factor: "Criticality", note: "Default low weight." },
      ],
      rationale: "No Referrer-Policy header was on the homepage.",
      whyItMatters: "Browsers may send the full URL as a referrer. That is a privacy leak only if the URL itself is sensitive.",
      remediation: "Set Referrer-Policy: strict-origin-when-cross-origin, or a stricter value if URLs contain secrets.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (server && /\d/.test(server)) {
    pushFinding({
      ruleId: "server-banner",
      title: "Server header includes a version",
      category: "Disclosure",
      factors: { exposure: 2, impact: 2, exploitability: 1, confidence: 0.9, criticality: 0.5 },
      factorNotes: [
        { factor: "Exposure", note: "The banner is visible to any client." },
        { factor: "Impact", note: "A version string is not a vulnerability." },
        { factor: "Exploitability", note: "No CVE was matched and no exploit was run." },
        { factor: "Confidence", note: "The header value was read. It can be a lie." },
        { factor: "Criticality", note: "Informational weight." },
      ],
      rationale: `The Server header was “${server}”.`,
      whyItMatters: "Version banners help inventory. They are informational unless a separate, evidenced vulnerability applies to a confirmed build.",
      remediation: "Prefer a generic server token if the banner is not needed for operations. Do not treat hiding it as a security control.",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http?.httpsToHttp) {
    pushFinding({
      ruleId: "https-to-http",
      title: "A redirect toward HTTP was observed",
      category: "Transport",
      factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.85, criticality: 0.75 },
      factorNotes: [
        { factor: "Exposure", note: "The browser was sent off HTTPS." },
        { factor: "Impact", note: "Session identifiers and forms can leak on the next hop. None were submitted." },
        { factor: "Exploitability", note: "A network attacker can read the HTTP hop. Not demonstrated here." },
        { factor: "Confidence", note: "The redirect chain was recorded. The chain was not fully followed off-domain." },
        { factor: "Criticality", note: "Raised slightly because transport downgrade is broadly serious." },
      ],
      rationale: "The redirect notes include a move from HTTPS to HTTP.",
      whyItMatters: "Downgrade redirects undo TLS for the next request.",
      remediation: "Redirect HTTP to HTTPS only. Remove any HTTPS-to-HTTP location.",
      references: ["https://datatracker.ietf.org/doc/html/rfc6797"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (obs.http?.httpServesContent) {
    pushFinding({
      ruleId: "http-open",
      title: "Port 80 responded without redirecting to HTTPS",
      category: "Transport",
      factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.8, criticality: 0.65 },
      factorNotes: [
        { factor: "Exposure", note: "Cleartext HTTP answered on the same host." },
        { factor: "Impact", note: "Depends whether anyone still uses the HTTP URL." },
        { factor: "Exploitability", note: "Network position required. Not tested." },
        { factor: "Confidence", note: "A single HEAD or header check. Body was not stored." },
        { factor: "Criticality", note: "Default weight." },
      ],
      rationale: "The port 80 check did not see a redirect to HTTPS.",
      whyItMatters: "Visitors who type the bare host, and old links, stay on cleartext.",
      remediation: "Answer port 80 with a 301 to the HTTPS URL, then keep HSTS on the HTTPS response.",
      references: ["https://datatracker.ietf.org/doc/html/rfc6797"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  } else if (obs.http?.httpRedirectsToHttps) {
    positives.push({
      id: "pos-http",
      title: "Port 80 redirects to HTTPS",
      detail: "A header check saw a redirect to an https URL. The body was not downloaded.",
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  for (const cookie of obs.http?.cookies ?? []) {
    if (!cookie.secure || !cookie.httpOnly || !cookie.sameSite) {
      pushFinding({
        ruleId: `cookie-${cookie.name}`,
        title: `Cookie “${cookie.name}” is missing a security flag`,
        category: "Session",
        factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.9, criticality: 0.7 },
        factorNotes: [
          { factor: "Exposure", note: "The cookie was set on a public response. Its value was discarded." },
          { factor: "Impact", note: "Impact depends whether the cookie is a session. The name alone does not prove that." },
          { factor: "Exploitability", note: "Flags were inspected. The cookie was not replayed." },
          { factor: "Confidence", note: "Set-Cookie attributes were parsed. The value was not stored." },
          { factor: "Criticality", note: "Default weight." },
        ],
        rationale: `Secure=${cookie.secure}, HttpOnly=${cookie.httpOnly}, SameSite=${cookie.sameSite ?? "absent"}.`,
        whyItMatters: "Missing Secure exposes the cookie on HTTP. Missing HttpOnly exposes it to script. Missing SameSite widens cross-site sending.",
        remediation: "Set Secure and HttpOnly on session cookies, and SameSite=Lax or Strict unless a cross-site flow truly needs None (which also requires Secure).",
        references: ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
        assetId: serviceAsset,
        evidenceIds: httpEv ? [httpEv] : [],
      });
    }
  }

  if (obs.http?.sourceMap) {
    pushFinding({
      ruleId: "source-map",
      title: "A source map reference was visible",
      category: "Disclosure",
      factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.8, criticality: 0.75 },
      factorNotes: [
        { factor: "Exposure", note: "The reference was on the public homepage or a script URL." },
        { factor: "Impact", note: "Maps can reveal original paths and source. The map file was not downloaded." },
        { factor: "Exploitability", note: "Contents were not fetched, so this stays short of a confirmed leak." },
        { factor: "Confidence", note: "A reference is not proof the map is still published." },
        { factor: "Criticality", note: "Default weight." },
      ],
      rationale: "HTML or a script URL mentioned a source map. Prex did not request the map.",
      whyItMatters: "Published maps can expose internal routes and unpublished logic. Treat the reference as a lead.",
      remediation: "Stop publishing production source maps, or restrict them at the edge. Confirm the .map URL returns 404.",
      references: ["https://developer.chrome.com/docs/devtools/javascript/source-maps"],
      assetId: serviceAsset,
      evidenceIds: httpEv ? [httpEv] : [],
    });
  }

  if (hasMx && !obs.dns?.spf) {
    pushFinding({
      ruleId: "spf-missing",
      title: "MX is published and SPF was not observed",
      category: "Mail",
      factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.85, criticality: 0.75 },
      factorNotes: [
        { factor: "Exposure", note: "Anyone can attempt to send mail as this domain." },
        { factor: "Impact", note: "Spoofing risk. Inbox placement also depends on receivers." },
        { factor: "Exploitability", note: "No message was sent." },
        { factor: "Confidence", note: "Based on TXT answers from one resolver." },
        { factor: "Criticality", note: "Mail-enabled domains get a higher default weight." },
      ],
      rationale: "An MX record was present and no v=spf1 TXT was observed on the host.",
      whyItMatters: "Receivers cannot tell which servers are allowed to send for the domain.",
      remediation: "Publish one SPF record that names your senders and ends in -all. Keep it under the DNS lookup limit.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7208"],
      assetId: mailAsset,
      evidenceIds: assets.find((a) => a.kind === "domain" || a.kind === "ip")?.evidenceIds.slice(0, 1) ?? [],
    });
  } else if (spfTail === "+all" || spfTail === "?all") {
    pushFinding({
      ruleId: "spf-permissive",
      title: `SPF ends in ${spfTail}`,
      category: "Mail",
      factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.95, criticality: 0.8 },
      factorNotes: [
        { factor: "Exposure", note: "The published policy authorizes or abstains on the rest of the internet." },
        { factor: "Impact", note: "Spoofed mail is easier for receivers to accept. No mail was sent." },
        { factor: "Exploitability", note: "The policy itself is the issue. It was not used to send mail." },
        { factor: "Confidence", note: "The TXT record was read." },
        { factor: "Criticality", note: "High default for a domain that publishes mail policy." },
      ],
      rationale: `The SPF record ends with ${spfTail}.`,
      whyItMatters: "+all allows any sender. ?all does not give receivers a fail signal.",
      remediation: "Replace the trailing mechanism with -all after every legitimate sender is included.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7208"],
      assetId: mailAsset,
      evidenceIds: [],
    });
  } else if (spfTail === "~all") {
    pushFinding({
      ruleId: "spf-softfail",
      title: "SPF ends in ~all (soft fail)",
      category: "Mail",
      factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.9, criticality: 0.7 },
      factorNotes: [
        { factor: "Exposure", note: "Unauthorized senders are marked, not rejected, by many receivers." },
        { factor: "Impact", note: "Weaker than -all. Often transitional." },
        { factor: "Exploitability", note: "No message was sent." },
        { factor: "Confidence", note: "Direct TXT observation." },
        { factor: "Criticality", note: "Default mail weight." },
      ],
      rationale: "SPF is present but uses soft fail.",
      whyItMatters: "Soft fail is a transition setting. Receivers may still deliver spoofed mail.",
      remediation: "Move to -all once forwarding and third-party senders are accounted for. Pair with DMARC.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7208"],
      assetId: mailAsset,
      evidenceIds: [],
    });
  } else if (spfTail === "-all") {
    positives.push({
      id: "pos-spf",
      title: "SPF ends in -all",
      detail: "The record tells receivers to fail non-listed senders. Prex did not test delivery.",
      evidenceIds: [],
    });
  }

  if (hasMx && !dmarcPolicy) {
    pushFinding({
      ruleId: "dmarc-missing",
      title: "MX is published and DMARC was not observed",
      category: "Mail",
      factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.9, criticality: 0.8 },
      factorNotes: [
        { factor: "Exposure", note: "Receivers have no domain policy for failed authentication." },
        { factor: "Impact", note: "Spoofing and reporting gaps. No mail was sent." },
        { factor: "Exploitability", note: "Policy absence only." },
        { factor: "Confidence", note: "TXT lookup at _dmarc." },
        { factor: "Criticality", note: "Mail-enabled default." },
      ],
      rationale: "No DMARC record was observed at _dmarc for this host.",
      whyItMatters: "Without DMARC, SPF and DKIM failures do not carry a domain-wide instruction.",
      remediation: "Publish a DMARC record. Start at p=none with a rua address you actually read, then move to quarantine or reject.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7489"],
      assetId: mailAsset,
      evidenceIds: [],
    });
  } else if (dmarcPolicy === "none") {
    pushFinding({
      ruleId: "dmarc-none",
      title: "DMARC policy is p=none",
      category: "Mail",
      factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 0.95, criticality: 0.75 },
      factorNotes: [
        { factor: "Exposure", note: "Monitoring only. Receivers are not asked to quarantine or reject." },
        { factor: "Impact", note: "Useful while deploying, weak as a final control." },
        { factor: "Exploitability", note: "No mail was sent." },
        { factor: "Confidence", note: "The tag was parsed from TXT." },
        { factor: "Criticality", note: "Default mail weight." },
      ],
      rationale: "A DMARC record exists and sets p=none.",
      whyItMatters: "p=none collects reports. It does not ask receivers to stop spoofed mail.",
      remediation: "Read aggregate reports, align SPF or DKIM, then move to p=quarantine and later p=reject.",
      references: ["https://datatracker.ietf.org/doc/html/rfc7489"],
      assetId: mailAsset,
      evidenceIds: [],
    });
  } else if (dmarcPolicy === "reject" || dmarcPolicy === "quarantine") {
    positives.push({
      id: "pos-dmarc",
      title: `DMARC policy is p=${dmarcPolicy}`,
      detail: "Prex did not confirm that mail actually aligns with SPF or DKIM.",
      evidenceIds: [],
    });
  }

  if (!hasMx && obs.dns && !obs.dns.error) {
    positives.push({
      id: "pos-nomx",
      title: "No MX was observed on this name",
      detail: "Mail-policy findings were not raised. A parent domain may still send mail.",
      evidenceIds: [],
    });
  }

  for (const dangle of obs.dns?.dangling ?? []) {
    pushFinding({
      ruleId: `dangling-${dangle.host}`,
      title: `Dangling CNAME needs review: ${dangle.host}`,
      category: "DNS",
      factors: { exposure: 4, impact: 4, exploitability: 2, confidence: 0.55, criticality: 0.7 },
      factorNotes: [
        { factor: "Exposure", note: "The alias is in public DNS." },
        { factor: "Impact", note: "A stale third-party alias can sometimes be reclaimed. That was not attempted." },
        { factor: "Exploitability", note: "Low on purpose. Takeover was not tested." },
        { factor: "Confidence", note: "Only a missing address was observed. Confidence stays modest." },
        { factor: "Criticality", note: "Default weight until an owner confirms the name." },
      ],
      rationale: `${dangle.host} CNAMEs to ${dangle.target}. ${dangle.reason}`,
      whyItMatters: "Stale aliases are a common way forgotten names become someone else's site. This record is a review item, not a confirmed takeover.",
      remediation: "If the name is unused, delete the CNAME. If it is used, restore the destination. Do not claim takeover without a separate, authorized proof.",
      references: ["https://datatracker.ietf.org/doc/html/rfc1912"],
      assetId: `subdomain:${dangle.host.toLowerCase()}`,
      evidenceIds: [],
    });
  }

  if (obs.tls && !obs.tls.error) {
    if (obs.tls.hostnameMismatch) {
      pushFinding({
        ruleId: "cert-mismatch",
        title: "Certificate name does not match the host",
        category: "Transport",
        factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.9, criticality: 0.8 },
        factorNotes: [
          { factor: "Exposure", note: "Clients that ignore errors would talk to the wrong name." },
          { factor: "Impact", note: "Breaks trust in the session. No traffic was intercepted by Prex." },
          { factor: "Exploitability", note: "The mismatch is directly observable. It was not abused." },
          { factor: "Confidence", note: "Compared the host with subject and SAN." },
          { factor: "Criticality", note: "Raised because users may click through errors." },
        ],
        rationale: "The certificate presented during the handshake did not cover the requested host.",
        whyItMatters: "Users and APIs either fail closed or, worse, get used to bypassing warnings.",
        remediation: "Issue a certificate whose SAN includes this exact host. Do not disable TLS verification in clients.",
        references: ["https://datatracker.ietf.org/doc/html/rfc5280"],
        assetId: certAsset,
        evidenceIds: tlsEv ? [tlsEv] : [],
      });
    }
    if (obs.tls.daysRemaining != null && obs.tls.daysRemaining < 0) {
      pushFinding({
        ruleId: "cert-expired",
        title: "Certificate is expired",
        category: "Transport",
        factors: { exposure: 4, impact: 4, exploitability: 2, confidence: 1, criticality: 0.75 },
        factorNotes: [
          { factor: "Exposure", note: "Clients will warn or refuse." },
          { factor: "Impact", note: "Availability and trust. Not treated as remote code execution." },
          { factor: "Exploitability", note: "Expiry is a fact, not an exploit." },
          { factor: "Confidence", note: "Dates came from the presented certificate." },
          { factor: "Criticality", note: "Operational weight, capped below critical." },
        ],
        rationale: `The not-after date is in the past (${obs.tls.daysRemaining} days).`,
        whyItMatters: "Expired certificates break clients and train people to ignore security warnings.",
        remediation: "Renew and deploy a certificate, and alert at 21 days rather than at expiry.",
        references: ["https://datatracker.ietf.org/doc/html/rfc5280"],
        assetId: certAsset,
        evidenceIds: tlsEv ? [tlsEv] : [],
      });
    } else if (obs.tls.daysRemaining != null && obs.tls.daysRemaining <= 21) {
      pushFinding({
        ruleId: "cert-soon",
        title: `Certificate expires in ${obs.tls.daysRemaining} day(s)`,
        category: "Transport",
        factors: { exposure: 4, impact: 3, exploitability: 2, confidence: 1, criticality: 0.7 },
        factorNotes: [
          { factor: "Exposure", note: "Public certificate." },
          { factor: "Impact", note: "Operational if renewal fails. Not a current break." },
          { factor: "Exploitability", note: "Not applicable. Score stays low." },
          { factor: "Confidence", note: "Date was on the certificate." },
          { factor: "Criticality", note: "Watch item." },
        ],
        rationale: `notAfter leaves ${obs.tls.daysRemaining} day(s).`,
        whyItMatters: "Short windows are how outages start. Expiry alone is not a critical vulnerability.",
        remediation: "Confirm automated renewal and alert before the 21-day mark.",
        references: ["https://datatracker.ietf.org/doc/html/rfc5280"],
        assetId: certAsset,
        evidenceIds: tlsEv ? [tlsEv] : [],
      });
    }
    if (obs.tls.protocol === "TLSv1" || obs.tls.protocol === "TLSv1.1") {
      pushFinding({
        ruleId: "tls-legacy",
        title: `Negotiated protocol was ${obs.tls.protocol}`,
        category: "Transport",
        factors: { exposure: 5, impact: 4, exploitability: 3, confidence: 0.85, criticality: 0.75 },
        factorNotes: [
          { factor: "Exposure", note: "The handshake accepted a legacy protocol." },
          { factor: "Impact", note: "Weaker cryptography. No ciphertext was attacked." },
          { factor: "Exploitability", note: "Protocol observation only." },
          { factor: "Confidence", note: "Taken from the handshake Prex made as a normal client." },
          { factor: "Criticality", note: "Default raised slightly for legacy TLS." },
        ],
        rationale: "The server negotiated a protocol older than TLS 1.2.",
        whyItMatters: "TLS 1.0 and 1.1 are obsolete and disabled in current browsers.",
        remediation: "Enable TLS 1.2 and 1.3 only.",
        references: ["https://datatracker.ietf.org/doc/html/rfc8996"],
        assetId: certAsset,
        evidenceIds: tlsEv ? [tlsEv] : [],
      });
    }
  }

  if (obs.securityTxt && !obs.securityTxt.found && norm.kind === "domain") {
    pushFinding({
      ruleId: "security-txt-missing",
      title: "security.txt was not published",
      category: "Disclosure",
      factors: { exposure: 2, impact: 2, exploitability: 1, confidence: 0.8, criticality: 0.5 },
      factorNotes: [
        { factor: "Exposure", note: "Researchers have no advertised contact." },
        { factor: "Impact", note: "Process gap, not a software flaw." },
        { factor: "Exploitability", note: "Not applicable." },
        { factor: "Confidence", note: "One well-known URL was requested." },
        { factor: "Criticality", note: "Informational." },
      ],
      rationale: "GET /.well-known/security.txt did not return a Contact field.",
      whyItMatters: "A published contact is how strangers report a problem without guessing inboxes.",
      remediation: "Publish /.well-known/security.txt with a Contact and a Policy, per RFC 9116.",
      references: ["https://datatracker.ietf.org/doc/html/rfc9116"],
      assetId: rootId,
      evidenceIds: [],
    });
  } else if (obs.securityTxt?.found) {
    positives.push({
      id: "pos-sectxt",
      title: "security.txt publishes a contact",
      detail: obs.securityTxt.contacts.join(", ") || "Contact field present.",
      evidenceIds: [],
    });
  }

  if (obs.lookalikes.length) {
    pushFinding({
      ruleId: "lookalikes",
      title: "Lookalike strings were generated, not resolved",
      category: "Brand",
      factors: { exposure: 2, impact: 2, exploitability: 1, confidence: 0.4, criticality: 0.45 },
      factorNotes: [
        { factor: "Exposure", note: "Strings only. They may not be registered." },
        { factor: "Impact", note: "Unknown until someone checks registration. Prex refused to query them." },
        { factor: "Exploitability", note: "Not applicable." },
        { factor: "Confidence", note: "Low. This is a generator, not an observation of abuse." },
        { factor: "Criticality", note: "Capped so it cannot outrank evidenced issues." },
      ],
      rationale: `${obs.lookalikes.length} candidate string(s) were produced from the label. No DNS or HTTP request was made for them.`,
      whyItMatters: "Typosquats are a watch item. A generated string is not evidence that a phishing site exists.",
      remediation: "Review the strings in your registrar or a defensive-registration program. Do not treat this list as confirmed abuse.",
      references: [],
      assetId: rootId,
      evidenceIds: [],
    });
  }

  if (obs.dns?.ad) {
    positives.push({
      id: "pos-ad",
      title: "Resolver AD bit was set",
      detail: "The recursive resolver marked the answer authenticated. Prex did not perform its own DNSSEC chain validation.",
      evidenceIds: [],
    });
  }

  const cdn = (obs.http?.technologies ?? []).some((t) => /cloudflare|fastly|akamai|cloudfront|vercel|cdn/i.test(t.name));

  const markers: Markers = {
    assetLabels: assets.map((a) => a.label).sort(),
    hsts: Boolean(hsts),
    csp: Boolean(csp),
    dmarc: dmarcPolicy,
    spfTail,
    certDays: obs.tls?.daysRemaining ?? null,
    cdn,
    findingIds: findings.map((f) => f.id).sort(),
  };

  const briefing = writeBriefing(obs, findings, assets);
  const limitations = [...BASE_LIMITS];
  if (obs.dns?.error) limitations.push("DNS did not fully succeed, so address and mail statements may be incomplete.");
  if (obs.ctError) limitations.push("The certificate log source did not return a usable list on this pass.");
  if (norm.kind === "brand") limitations.push("A brand label was not tied to a legal entity or a domain.");
  if (!obs.demo) limitations.push("Results are from one pass just now. They are not a continuous monitor unless you map again.");

  const plan: PlanStep[] = [
    { id: "normalize", title: "Normalize", detail: norm.notes.join(" ") || "Host canonicalized.", state: "done" },
    { id: "policy", title: "Policy", detail: obs.mode === "verified" ? "Verified mode. Destructive modules still denied." : "Public mode. Active modules denied.", state: "done" },
    {
      id: "collect",
      title: "Collect",
      detail: obs.collectors.map((c) => `${c.title}: ${c.status}`).join(" · ") || "No collectors.",
      state: "done",
    },
    { id: "correlate", title: "Correlate", detail: `${assets.length} entities, ${relations.length} links. Suspected names were not promoted to owned.`, state: "done" },
    { id: "score", title: "Score", detail: "Rules are fixed arithmetic. No model assigned severity.", state: "done" },
  ];

  return {
    id,
    createdAt: obs.now,
    targetKey: targetKey(norm),
    normalized: norm,
    mode: obs.mode,
    demo: obs.demo,
    plan,
    policy: [...policyFor(obs.mode, norm.kind), ...obs.dynamicPolicy],
    collectors: obs.collectors,
    assets,
    relations,
    findings: findings.sort((a, b) => b.score - a.score),
    positives,
    changes: obs.scriptedChanges,
    evidence,
    briefing,
    limitations,
    markers,
    breach: obs.demo
      ? {
          state: "demonstration-aggregate",
          statement:
            "Demonstration only: two corpus mentions are scripted for @northline.example. No mailbox, password, or breach record is stored. A real deployment would show an authorized admin a count, never the stolen material.",
        }
      : {
          state: "withheld",
          statement:
            "Credential contents are not queried or shown. An enterprise deployment can report an aggregate count for the company’s domains after a contract and an admin workflow. This preview does not call a breach corpus.",
        },
    verification: obs.verification,
    durationMs: obs.collectors.reduce((sum, c) => sum + c.durationMs, 0),
    ...buildLens(obs),
  };
}

function writeBriefing(obs: Observations, findings: Finding[], assets: Asset[]): string[] {
  const host = obs.normalized.display;
  const lines: string[] = [];
  lines.push(
    `${host} was mapped in ${obs.mode === "verified" ? "verified" : "public"} mode${obs.demo ? " from the Northline demonstration dataset" : ""}.`,
  );
  if (obs.dns?.error) lines.push(`DNS did not succeed (${obs.dns.error}). No address is claimed.`);
  else if (obs.dns) {
    const ips = obs.dns.records.filter((r) => r.type === "A" || r.type === "AAAA");
    lines.push(
      ips.length
        ? `Public DNS returned ${ips.length} address(es)${obs.rdap?.asn ? `, associated on RDAP with ${obs.rdap.asn}` : ""}. That association is registration data, not an operator’s name.`
        : "No public address was returned for this name.",
    );
  }
  if (obs.rdap?.entityNote) lines.push(obs.rdap.entityNote);
  if (obs.http?.error) lines.push(`The homepage was not collected (${obs.http.error}).`);
  else if (obs.http?.status) lines.push(`The homepage returned HTTP ${obs.http.status}${obs.http.title ? ` with title “${obs.http.title}”` : ""}.`);
  if (obs.tls && !obs.tls.error && obs.tls.daysRemaining != null) {
    lines.push(`The presented certificate has ${obs.tls.daysRemaining} day(s) remaining${obs.tls.issuer ? ` and issuer “${obs.tls.issuer}”` : ""}.`);
  }
  const suspected = assets.filter((a) => a.status === "suspected" && a.kind === "subdomain").length;
  if (suspected) lines.push(`${suspected} certificate-log name(s) are marked suspected. They were not declared owned.`);
  if (findings.length === 0) lines.push("No included rule fired. That covers only the checks that ran.");
  else {
    const top = findings[0];
    lines.push(`${findings.length} rule result(s). Highest explained score is ${top?.score ?? 0} (${top?.severity ?? "informational"}): ${top?.title ?? ""}.`);
  }
  lines.push("No exploit, credential attack, or port scan was run.");
  return lines.slice(0, 8);
}

function dmarcTag(record: string | null): string | null {
  if (!record) return null;
  const match = record.match(/p\s*=\s*(reject|quarantine|none)/i);
  return match?.[1]?.toLowerCase() ?? null;
}

function spfAll(record: string | null): string | null {
  if (!record) return null;
  const match = record.match(/([~+\-?])all\b/i);
  return match?.[0]?.toLowerCase() ?? null;
}

export function newId(prefix: string): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(8));
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${hex}`;
}

export function remediationDraft(finding: Finding, host: string): string {
  return [
    `Task: ${finding.title}`,
    `Host: ${host}`,
    `Rule: ${finding.ruleId}`,
    `Score: ${finding.score} (${finding.severity})`,
    `Why: ${finding.whyItMatters}`,
    `Do this: ${finding.remediation}`,
    "Done when: a new public map no longer produces this rule id, and the evidence still shows the fixed control.",
    "Do not attach exploit steps. This task is a configuration or process change.",
  ].join("\n");
}
