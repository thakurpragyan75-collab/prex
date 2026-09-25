import type { ChangeEvent, Observations } from "./types.ts";
import { normalizeTarget } from "./engine.ts";

const CHANGES: ChangeEvent[] = [
  {
    id: "demo-preview",
    kind: "added",
    title: "Certificate log now includes preview.northline.example",
    detail:
      "Compared with the demonstration’s prior week. The name is suspected, not owned, and was not requested.",
  },
  {
    id: "demo-dmarc",
    kind: "regressed",
    title: "DMARC moved from p=reject to p=none",
    detail: "Scripted prior snapshot for the demonstration tenant. Not a live history.",
  },
  {
    id: "demo-cdn",
    kind: "regressed",
    title: "CDN response signal absent; origin address still published",
    detail:
      "Prior snapshot showed a CDN header. This snapshot does not. 203.0.113.24 is a documentation address. This is a review item, not proof of compromise.",
  },
  {
    id: "demo-cert",
    kind: "regressed",
    title: "Certificate entered the 21-day window",
    detail: "12 days remain on the demonstration certificate.",
  },
];

export function northlineObservations(now: string, verified: boolean): Observations {
  const normalized = normalizeTarget("northline.example");
  return {
    normalized,
    now,
    demo: true,
    mode: verified ? "verified" : "public",
    verification: verified
      ? {
          verified: true,
          method: "demonstration",
          detail: "Demonstration proof accepted for northline.example only. No DNS change was made.",
        }
      : {
          verified: false,
          method: null,
          detail: "Public mode. The sample can be marked verified with the demonstration proof.",
        },
    collectors: [
      { id: "dns", title: "DNS and mail posture", status: "ok", detail: "Demonstration records. No resolver was queried.", durationMs: 40 },
      { id: "rdap", title: "RDAP", status: "ok", detail: "Demonstration registry. Not a real registrar.", durationMs: 30 },
      { id: "http", title: "Homepage headers", status: "ok", detail: "Scripted response. The host northline.example was not contacted.", durationMs: 50 },
      { id: "tls", title: "TLS observe", status: "ok", detail: "Scripted certificate.", durationMs: 20 },
      { id: "ct", title: "Certificate log", status: "ok", detail: "Scripted names, labeled suspected.", durationMs: 20 },
      { id: "docs", title: "security.txt", status: "ok", detail: "Scripted disclosure file.", durationMs: 10 },
      {
        id: "public",
        title: "Public description",
        status: "ok",
        detail: "Demonstration encyclopedia extract. Not a consumer review and not a live lookup.",
        durationMs: 5,
      },
      {
        id: "recheck",
        title: "Safe recheck",
        status: verified ? "ok" : "denied",
        detail: verified
          ? "Second scripted fetch recorded. Still no mutation and no exploit."
          : "Locked until demonstration proof is attached.",
        durationMs: verified ? 15 : 0,
      },
      { id: "ports", title: "Port scan", status: "denied", detail: "Not implemented.", durationMs: 0 },
    ],
    dynamicPolicy: [],
    dns: {
      records: [
        { type: "A", name: "northline.example", value: "203.0.113.24", ttl: "300" },
        { type: "NS", name: "northline.example", value: "ns1.northline.example", ttl: "86400" },
        { type: "NS", name: "northline.example", value: "ns2.northline.example", ttl: "86400" },
        { type: "MX", name: "northline.example", value: "10 mx.northline.example", ttl: "300" },
        { type: "TXT", name: "northline.example", value: "v=spf1 include:_spf.northline.example ~all", ttl: "300" },
        { type: "TXT", name: "_dmarc.northline.example", value: "v=DMARC1; p=none; rua=mailto:dmarc@northline.example", ttl: "300" },
        { type: "CAA", name: "northline.example", value: '0 issue "demo-ca.example"', ttl: "300" },
      ],
      spf: "v=spf1 include:_spf.northline.example ~all",
      dmarc: "v=DMARC1; p=none; rua=mailto:dmarc@northline.example",
      ad: true,
      dangling: [
        {
          host: "legacy.northline.example",
          target: "northline-legacy.herokuapp.com",
          reason: "No public address followed the alias. Third-party host pattern. Not a confirmed takeover.",
        },
      ],
    },
    rdap: {
      registrar: "Northline Demo Registry",
      statuses: ["client transfer prohibited"],
      nameservers: ["ns1.northline.example", "ns2.northline.example"],
      dates: [
        { label: "Registered", value: "2019-04-02" },
        { label: "Expiration", value: "2027-04-02" },
      ],
      entityNote:
        "Public RDAP organization label on this demonstration: Northline Freight. Personal contacts are withheld. The label is not identity proof, and the registry is fictional.",
      asn: "AS64500",
      networkName: "DOCUMENTATION-TEST-NET-3",
    },
    http: {
      url: "https://northline.example/",
      status: 200,
      title: "Northline Freight",
      headers: [
        { name: "server", value: "nginx/1.18.0" },
        { name: "content-type", value: "text/html; charset=utf-8" },
        { name: "set-cookie", value: "flags only; value withheld" },
      ],
      cookies: [{ name: "nl_session", secure: false, httpOnly: true, sameSite: null }],
      technologies: [{ name: "nginx", confidence: 0.7, evidence: "Server header included a version token." }],
      scripts: ["/assets/app.js", "/assets/app.js.map", "https://static.example/northline-widget.js"],
      sourceMap: true,
      redirectNotes: ["Port 80 returned a redirect to https://northline.example/."],
      httpsToHttp: false,
      httpServesContent: false,
      httpRedirectsToHttps: true,
    },
    tls: {
      subject: "northline.example",
      issuer: "Northline Demo CA",
      validFrom: "2025-09-20",
      validTo: "2026-10-07",
      daysRemaining: 12,
      sans: ["northline.example", "www.northline.example"],
      protocol: "TLSv1.2",
      authorized: true,
      authError: null,
      hostnameMismatch: false,
    },
    ctNames: [
      "www.northline.example",
      "app.northline.example",
      "api.northline.example",
      "preview.northline.example",
      "legacy.northline.example",
    ],
    ctEntries: [
      { name: "northline.example", notBefore: "2019-06-01", notAfter: "2019-09-01", issuer: "Northline Demo CA" },
      { name: "legacy.northline.example", notBefore: "2020-06-01", notAfter: "2020-09-01", issuer: "Northline Demo CA" },
      { name: "www.northline.example", notBefore: "2021-02-01", notAfter: "2021-05-01", issuer: "Northline Demo CA" },
      { name: "app.northline.example", notBefore: "2022-08-14", notAfter: "2022-11-14", issuer: "Northline Demo CA" },
      { name: "api.northline.example", notBefore: "2023-01-09", notAfter: "2023-04-09", issuer: "Northline Demo CA" },
      { name: "preview.northline.example", notBefore: "2024-11-02", notAfter: "2025-02-02", issuer: "Northline Demo CA" },
      { name: "northline.example", notBefore: "2025-09-20", notAfter: "2026-10-07", issuer: "Northline Demo CA" },
    ],
    publicNote: {
      source: "demonstration encyclopedia extract",
      title: "Northline Freight",
      extract:
        "Northline Freight is a fictional carrier used to show Prex. It is not a real company and this text is not a customer review.",
      found: true,
      url: null,
    },
    securityTxt: {
      found: true,
      contacts: ["security@northline.example"],
      excerpt: "Contact: security@northline.example. Policy: https://northline.example/security. Demonstration text.",
    },
    robotsFound: true,
    lookalikes: ["n0rthline.example", "north1ine.example", "northline-login.example"],
    repository: {
      label: "github.com/northline-demo/web",
      note: "Declared inside the demonstration dataset. Prex did not search a live code host and holds no secret material.",
    },
    scriptedChanges: CHANGES,
    safeRecheck: verified
      ? { status: 200, note: "Verified demonstration recheck returned the same scripted status. No payload was sent." }
      : null,
  };
}
