export type TargetKind = "domain" | "ip" | "brand" | "rejected";

export type NormalizedTarget = {
  input: string;
  kind: TargetKind;
  display: string;
  host: string | null;
  registrable: string | null;
  notes: string[];
  rejectReason: string | null;
};

export type AssetStatus =
  | "observed"
  | "suspected"
  | "verified-owned"
  | "customer-confirmed"
  | "out-of-scope";

export type Evidence = {
  id: string;
  source: string;
  collectedAt: string;
  method: "passive" | "verified-safe-check";
  summary: string;
  fields: { label: string; value: string }[];
};

export type Asset = {
  id: string;
  kind:
    | "brand"
    | "domain"
    | "subdomain"
    | "ip"
    | "asn"
    | "certificate"
    | "mail"
    | "service"
    | "technology"
    | "document"
    | "repository";
  label: string;
  status: AssetStatus;
  confidence: number;
  summary: string;
  evidenceIds: string[];
};

export type Relation = {
  id: string;
  from: string;
  to: string;
  type: string;
};

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export type Factors = {
  exposure: number;
  impact: number;
  exploitability: number;
  confidence: number;
  criticality: number;
};

export type Finding = {
  id: string;
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  score: number;
  formula: string;
  factors: Factors;
  factorNotes: { factor: string; note: string }[];
  rationale: string;
  whyItMatters: string;
  remediation: string;
  references: string[];
  assetId: string;
  evidenceIds: string[];
  confidence: number;
  observation: "passive" | "verified-safe-check";
};

export type Positive = {
  id: string;
  title: string;
  detail: string;
  evidenceIds: string[];
};

export type ChangeEvent = {
  id: string;
  kind: "added" | "removed" | "regressed" | "improved";
  title: string;
  detail: string;
};

export type CollectorRun = {
  id: string;
  title: string;
  status: "ok" | "empty" | "error" | "skipped" | "denied";
  detail: string;
  durationMs: number;
};

export type PolicyDecision = {
  action: string;
  decision: "allow" | "deny";
  reason: string;
};

export type PlanStep = {
  id: string;
  title: string;
  detail: string;
  state: "done" | "skipped" | "denied";
};

export type Markers = {
  assetLabels: string[];
  hsts: boolean;
  csp: boolean;
  dmarc: string | null;
  spfTail: string | null;
  certDays: number | null;
  cdn: boolean;
  findingIds: string[];
};

export type ScanMode = "public" | "verified";

export type ScanRecord = {
  id: string;
  createdAt: string;
  targetKey: string;
  normalized: NormalizedTarget;
  mode: ScanMode;
  demo: boolean;
  plan: PlanStep[];
  policy: PolicyDecision[];
  collectors: CollectorRun[];
  assets: Asset[];
  relations: Relation[];
  findings: Finding[];
  positives: Positive[];
  changes: ChangeEvent[];
  evidence: Evidence[];
  briefing: string[];
  limitations: string[];
  markers: Markers;
  breach: {
    state: "withheld" | "demonstration-aggregate";
    statement: string;
  };
  verification: { verified: boolean; method: string | null; detail: string };
  durationMs: number;
  shadow?: ShadowRow[];
  timeline?: TimeMark[];
  answers?: Answer[];
  scorecard?: Scorecard;
};

export type CtEntry = {
  name: string;
  notBefore: string | null;
  notAfter: string | null;
  issuer: string | null;
};

export type PublicNote = {
  source: string;
  title: string | null;
  extract: string | null;
  found: boolean;
  url: string | null;
};

export type ScoreAxis = {
  id: string;
  title: string;
  score: number | null;
  tone: "good" | "mixed" | "bad" | "unknown";
  note: string;
};

export type Scorecard = {
  overall: number;
  coverage: number;
  basis: string;
  review: string;
  axes: ScoreAxis[];
};

export type ShadowRow = {
  id: string;
  kind: "ghost" | "lookalike" | "third-party" | "mail" | "dangling";
  label: string;
  detail: string;
};

export type TimeMark = {
  id: string;
  at: string;
  label: string;
  detail: string;
};

export type Answer = {
  id: string;
  ask: string;
  answer: string;
};

export type DnsRecord = { type: string; name: string; value: string; ttl: string };

export type Observations = {
  normalized: NormalizedTarget;
  now: string;
  demo: boolean;
  mode: ScanMode;
  verification: { verified: boolean; method: string | null; detail: string };
  collectors: CollectorRun[];
  dynamicPolicy: PolicyDecision[];
  dns: null | {
    records: DnsRecord[];
    spf: string | null;
    dmarc: string | null;
    ad: boolean | null;
    dangling: { host: string; target: string; reason: string }[];
    error?: string;
  };
  rdap: null | {
    registrar: string | null;
    statuses: string[];
    nameservers: string[];
    dates: { label: string; value: string }[];
    entityNote: string;
    asn: string | null;
    networkName: string | null;
    error?: string;
  };
  http: null | {
    url: string;
    status: number | null;
    title: string | null;
    headers: { name: string; value: string }[];
    cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[];
    technologies: { name: string; confidence: number; evidence: string }[];
    scripts: string[];
    sourceMap: boolean;
    redirectNotes: string[];
    httpsToHttp: boolean;
    httpServesContent: boolean;
    httpRedirectsToHttps: boolean;
    error?: string;
  };
  tls: null | {
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
  };
  ctNames: string[];
  ctEntries: CtEntry[];
  ctError?: string;
  publicNote: PublicNote | null;
  securityTxt: null | { found: boolean; contacts: string[]; excerpt: string };
  robotsFound: boolean | null;
  lookalikes: string[];
  repository: null | { label: string; note: string };
  scriptedChanges: ChangeEvent[];
  safeRecheck: null | { status: number | null; note: string };
};

export type MapResult =
  | { ok: true; scan: ScanRecord }
  | { ok: false; error: string; code: string };

export type ProofMethod = "dns" | "well-known" | "meta" | "demonstration";

export type Proof = { method: ProofMethod; token: string };

export type CheckResult =
  | { ok: true; host: string; method: ProofMethod; detail: string }
  | { ok: false; error: string };
