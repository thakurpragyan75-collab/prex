import type { Answer, Observations, ScoreAxis, Scorecard, ShadowRow, TimeMark } from "./types.ts";

export type Lens = {
  shadow: ShadowRow[];
  timeline: TimeMark[];
  answers: Answer[];
  scorecard: Scorecard;
};

function round1(value: number): number {
  return Math.round(Math.max(0, Math.min(10, value)) * 10) / 10;
}

function toneFor(score: number | null): ScoreAxis["tone"] {
  if (score == null) return "unknown";
  if (score >= 7) return "good";
  if (score >= 5) return "mixed";
  return "bad";
}

function axis(id: string, title: string, score: number | null, note: string): ScoreAxis {
  return { id, title, score: score == null ? null : round1(score), tone: toneFor(score), note };
}

function header(obs: Observations, name: string): string | null {
  return obs.http?.headers.find((item) => item.name.toLowerCase() === name)?.value ?? null;
}

function scriptHosts(obs: Observations): string[] {
  const self = obs.normalized.registrable ?? obs.normalized.host ?? "";
  const found = new Set<string>();
  for (const raw of obs.http?.scripts ?? []) {
    if (!raw.startsWith("http://") && !raw.startsWith("https://")) continue;
    try {
      const host = new URL(raw).hostname.toLowerCase();
      if (!host || host === self || (self && host.endsWith(`.${self}`))) continue;
      found.add(host);
    } catch {
      /* skip a script URL that is not a URL */
    }
  }
  return [...found];
}

function ghosts(obs: Observations): string[] {
  const live = new Set((obs.dns?.records ?? []).map((record) => record.name.toLowerCase().replace(/\.$/, "")));
  const dangling = new Set((obs.dns?.dangling ?? []).map((item) => item.host.toLowerCase()));
  const host = obs.normalized.host?.toLowerCase() ?? "";
  return obs.ctNames.filter((name) => {
    const lower = name.toLowerCase();
    if (lower === host || lower === `www.${host}`) return false;
    if (dangling.has(lower)) return false;
    return !live.has(lower);
  });
}

function mxValues(obs: Observations): string[] {
  return (obs.dns?.records ?? []).filter((record) => record.type === "MX").map((record) => record.value);
}

export function buildLens(obs: Observations): Lens {
  const shadow = buildShadow(obs);
  const timeline = buildTimeline(obs);
  const scorecard = buildScorecard(obs, shadow);
  const answers = buildAnswers(obs, shadow, timeline, scorecard);
  return { shadow, timeline, answers, scorecard };
}

function buildShadow(obs: Observations): ShadowRow[] {
  const rows: ShadowRow[] = [];
  for (const name of ghosts(obs)) {
    rows.push({
      id: `ghost-${name}`,
      kind: "ghost",
      label: name,
      detail: "Named in a public certificate log. It was not in the DNS answers for this pass, and it was not requested.",
    });
  }
  for (const item of obs.dns?.dangling ?? []) {
    rows.push({
      id: `dangle-${item.host}`,
      kind: "dangling",
      label: item.host,
      detail: `${item.reason} Alias target: ${item.target}. Not a confirmed takeover.`,
    });
  }
  for (const host of scriptHosts(obs)) {
    rows.push({
      id: `script-${host}`,
      kind: "third-party",
      label: host,
      detail: "A script URL on the homepage named this host. The script body was not executed or stored.",
    });
  }
  const mx = mxValues(obs);
  if (mx.length) {
    rows.push({
      id: "mail",
      kind: "mail",
      label: mx.join(", "),
      detail: "Mail exchangers from public DNS. The mail host is not the website operator.",
    });
  }
  for (const name of obs.lookalikes) {
    rows.push({
      id: `like-${name}`,
      kind: "lookalike",
      label: name,
      detail: "Generated from the label. Not resolved, not registered by Prex, and not evidence of a copycat site.",
    });
  }
  return rows.slice(0, 16);
}

function buildTimeline(obs: Observations): TimeMark[] {
  const marks: TimeMark[] = [];
  const registered = obs.rdap?.dates.find((item) => /regist|creat/i.test(item.label));
  if (registered?.value) {
    marks.push({
      id: "rdap-registered",
      at: registered.value.slice(0, 10),
      label: "Registration date",
      detail: obs.demo
        ? "Demonstration registry date. Not a live registrar."
        : "Date published in RDAP. It is not proof of who operates the site today.",
    });
  }
  const seen = new Set<string>();
  for (const entry of obs.ctEntries) {
    if (!entry.notBefore) continue;
    const key = `${entry.name}|${entry.notBefore}`;
    if (seen.has(key)) continue;
    seen.add(key);
    marks.push({
      id: `ct-${key}`,
      at: entry.notBefore,
      label: entry.name,
      detail: `Certificate not-before ${entry.notBefore}${entry.notAfter ? `, not-after ${entry.notAfter}` : ""}${entry.issuer ? `. Issuer: ${entry.issuer}` : ""}. A logged name is not an owned host.`,
    });
  }
  if (obs.tls?.validFrom && !marks.some((mark) => mark.at.slice(0, 10) === obs.tls?.validFrom?.slice(0, 10) && mark.label === (obs.tls.subject ?? ""))) {
    marks.push({
      id: "tls-current",
      at: obs.tls.validFrom.slice(0, 10),
      label: obs.tls.subject ?? "Presented certificate",
      detail: `Certificate presented on this pass${obs.tls.daysRemaining != null ? `, ${obs.tls.daysRemaining} day(s) remaining` : ""}.`,
    });
  }
  return marks
    .filter((mark) => /^\d{4}-\d{2}-\d{2}/.test(mark.at))
    .sort((a, b) => a.at.localeCompare(b.at))
    .slice(-24);
}

function buildScorecard(obs: Observations, shadow: ShadowRow[]): Scorecard {
  const http = obs.http;
  const referrer = header(obs, "referrer-policy");
  const permissions = header(obs, "permissions-policy");
  const hsts = header(obs, "strict-transport-security");
  const csp = header(obs, "content-security-policy");
  const server = header(obs, "server");
  const cookies = http?.cookies ?? [];
  const parties = scriptHosts(obs);
  const ghostCount = shadow.filter((row) => row.kind === "ghost").length;
  const dangles = obs.dns?.dangling.length ?? 0;
  const spf = obs.dns?.spf ?? "";
  const dmarc = obs.dns?.dmarc ?? "";
  const mx = mxValues(obs).join(" ").toLowerCase();

  const axes: ScoreAxis[] = [
    axis(
      "privacy",
      "Privacy headers",
      http ? (referrer && permissions ? 9 : referrer || permissions ? 6 : 3) : null,
      http
        ? referrer || permissions
          ? `Referrer-Policy ${referrer ? "was present" : "was missing"}. Permissions-Policy ${permissions ? "was present" : "was missing"}.`
          : "The homepage did not send Referrer-Policy or Permissions-Policy."
        : "No homepage was collected, so privacy headers were not scored.",
    ),
    axis(
      "cookies",
      "Cookie discipline",
      http ? (cookies.length === 0 ? 7 : cookies.every((cookie) => cookie.secure && cookie.httpOnly && cookie.sameSite) ? 9 : cookies.some((cookie) => !cookie.secure) ? 3 : 5) : null,
      http
        ? cookies.length === 0
          ? "No Set-Cookie was kept. Values are never stored."
          : "Cookie values were discarded. The score uses Secure, HttpOnly, and SameSite flags only."
        : "No homepage was collected.",
    ),
    axis(
      "https",
      "HTTPS continuity",
      http ? (http.httpsToHttp ? 1 : http.httpRedirectsToHttps && !http.httpServesContent ? 9 : 7) : null,
      http
        ? http.httpsToHttp
          ? "HTTPS sent the browser back to HTTP."
          : http.httpRedirectsToHttps
            ? "Port 80 redirected to HTTPS and did not serve the page itself."
            : "The HTTPS homepage responded. A clean port-80 redirect was not confirmed."
        : "No homepage was collected.",
    ),
    axis(
      "cert-life",
      "Certificate lifetime",
      obs.tls?.daysRemaining == null ? null : obs.tls.daysRemaining > 30 ? 8 : obs.tls.daysRemaining > 7 ? 4 : 2,
      obs.tls?.daysRemaining == null ? "No certificate lifetime was observed." : `${obs.tls.daysRemaining} day(s) remaining on the presented certificate.`,
    ),
    axis(
      "cert-match",
      "Certificate name",
      obs.tls && !obs.tls.error ? (obs.tls.hostnameMismatch ? 2 : 8) : null,
      obs.tls?.hostnameMismatch ? "The presented certificate did not cover the host." : obs.tls && !obs.tls.error ? "The presented certificate covered the host that was asked." : "No certificate check.",
    ),
    axis(
      "tls",
      "TLS version",
      obs.tls?.protocol ? (/1\.3/.test(obs.tls.protocol) ? 9 : /1\.2/.test(obs.tls.protocol) ? 7 : 2) : null,
      obs.tls?.protocol ? `Negotiated ${obs.tls.protocol}.` : "No TLS protocol was observed.",
    ),
    axis("hsts", "HSTS", http ? (hsts ? 9 : 3) : null, http ? (hsts ? "Strict-Transport-Security was present." : "Strict-Transport-Security was absent.") : "No homepage was collected."),
    axis("csp", "Content security", http ? (csp ? 8 : 3) : null, http ? (csp ? "Content-Security-Policy was present." : "Content-Security-Policy was absent.") : "No homepage was collected."),
    axis(
      "spf",
      "SPF",
      obs.dns ? (/-all\b/i.test(spf) ? 9 : /~all\b/i.test(spf) ? 6 : spf ? 2 : 3) : null,
      obs.dns ? (spf ? `SPF tail observed: ${spf.slice(0, 120)}` : "No SPF TXT was observed.") : "DNS was not collected.",
    ),
    axis(
      "dmarc",
      "DMARC",
      obs.dns ? (/p\s*=\s*reject/i.test(dmarc) ? 9 : /p\s*=\s*quarantine/i.test(dmarc) ? 7 : /p\s*=\s*none/i.test(dmarc) ? 4 : 3) : null,
      obs.dns ? (dmarc ? `DMARC observed: ${dmarc.slice(0, 140)}` : "No DMARC TXT was observed.") : "DNS was not collected.",
    ),
    axis(
      "disclosure",
      "Disclosure contact",
      obs.securityTxt ? (obs.securityTxt.found ? 8 : 3) : null,
      obs.securityTxt?.found ? "security.txt published a contact." : obs.securityTxt ? "security.txt was requested and did not publish a contact." : "security.txt was not requested.",
    ),
    axis(
      "ghosts",
      "Forgotten names",
      obs.ctError ? null : obs.normalized.kind === "domain" || obs.ctNames.length ? (ghostCount === 0 ? 8 : ghostCount < 3 ? 5 : 3) : null,
      obs.ctError ? "The certificate log did not return a usable list." : `${ghostCount} certificate-log name(s) were not in this pass’s DNS answers.`,
    ),
    axis(
      "aliases",
      "Dangling aliases",
      obs.dns ? (dangles === 0 ? 8 : 3) : null,
      obs.dns ? (dangles === 0 ? "No dangling alias was observed." : `${dangles} alias(es) had no public address. Not a confirmed takeover.`) : "DNS was not collected.",
    ),
    axis(
      "scripts",
      "Third-party scripts",
      http ? (parties.length === 0 ? 8 : parties.length < 3 ? 6 : 4) : null,
      http ? (parties.length ? `Homepage script URLs named ${parties.join(", ")}.` : "No off-site script URL was named on the homepage.") : "No homepage was collected.",
    ),
    axis(
      "maps",
      "Source maps",
      http ? (http.sourceMap ? 3 : 8) : null,
      http ? (http.sourceMap ? "A source-map reference was visible. The map was not downloaded." : "No source-map reference was visible.") : "No homepage was collected.",
    ),
    axis(
      "version",
      "Version leakage",
      http ? (server && /\d/.test(server) ? 4 : server ? 7 : 8) : null,
      http ? (server ? `Server header: ${server.slice(0, 80)}` : "No Server header was observed.") : "No homepage was collected.",
    ),
    axis(
      "registration",
      "Registration record",
      obs.rdap ? (obs.rdap.registrar || obs.rdap.asn ? 8 : 4) : null,
      obs.rdap?.registrar ? `Registrar label: ${obs.rdap.registrar}. This is not an owner’s name.` : obs.rdap ? "RDAP returned little identity." : "RDAP was not collected.",
    ),
    axis(
      "mail-host",
      "Mail host",
      obs.dns ? (mx ? (/google|outlook|yahoo|proton/i.test(mx) ? 5 : 8) : 4) : null,
      obs.dns ? (mx ? "MX targets were published. A consumer mail host is a posture note, not proof of a problem." : "No MX was published.") : "DNS was not collected.",
    ),
    axis(
      "description",
      "Public description",
      obs.publicNote ? (obs.publicNote.found ? 7 : 5) : null,
      obs.publicNote?.found
        ? "An encyclopedia page matched the name. It is not a customer review."
        : obs.publicNote
          ? "No encyclopedia page matched. That absence is not scored as a defect beyond this note."
          : "No public-description lookup ran.",
    ),
    axis(
      "robots",
      "Crawl notice",
      obs.robotsFound == null ? null : obs.robotsFound ? 7 : 5,
      obs.robotsFound == null ? "robots.txt was not checked." : obs.robotsFound ? "robots.txt responded." : "robots.txt was not present at the well-known path.",
    ),
  ];

  const measured = axes.filter((item) => item.score != null);
  if (measured.length === 0) {
    const bare = nameOnly(obs);
    return {
      overall: bare.overall,
      coverage: 0,
      basis: bare.note,
      review: reviewText(obs),
      axes,
    };
  }
  const overall = round1(measured.reduce((sum, item) => sum + (item.score ?? 0), 0) / measured.length);
  return {
    overall,
    coverage: measured.length,
    basis:
      measured.length < 6
        ? `Thin public record. ${measured.length} of 20 signals had evidence. The missing ones were left blank, not filled with a guess.`
        : `${measured.length} of 20 signals had public evidence. Missing signals were left blank.`,
    review: reviewText(obs),
    axes,
  };
}

function nameOnly(obs: Observations): { overall: number; note: string } {
  const label = (obs.normalized.host ?? obs.normalized.display).toLowerCase();
  if (obs.normalized.kind === "brand") {
    return { overall: 4, note: "Only a name was supplied and nothing public came back with it. 4.0 is not a review of a website." };
  }
  if (/(login|verify|secure|wallet|support)/.test(label)) {
    return { overall: 3, note: "The name looks like an account prompt and almost no public data came back. 3.0 is a caution, not a measured review." };
  }
  return { overall: 5, note: "Almost no public data came back. 5.0 means unmeasured, not average quality." };
}

function reviewText(obs: Observations): string {
  if (obs.publicNote?.found && obs.publicNote.extract) {
    return `No consumer-review site was queried. This is a public encyclopedia extract, not a rating from customers. ${obs.publicNote.extract}`;
  }
  return "No consumer reviews were found or queried. The number is from the public signals that returned, or from the name alone when those signals are missing. It is not a star rating from users.";
}

function buildAnswers(obs: Observations, shadow: ShadowRow[], timeline: TimeMark[], scorecard: Scorecard): Answer[] {
  const host = obs.normalized.display;
  const mx = mxValues(obs);
  const parties = shadow.filter((row) => row.kind === "third-party").map((row) => row.label);
  const ghostsOnly = shadow.filter((row) => row.kind === "ghost").map((row) => row.label);
  const years = [...new Set(timeline.map((mark) => mark.at.slice(0, 4)))];
  return [
    {
      id: "mail",
      ask: "Who mails for this name?",
      answer: mx.length ? `Public DNS published ${mx.join(", ")}. That host delivers mail. It is not proof of who runs ${host}.` : "No MX record was observed on this pass.",
    },
    {
      id: "past",
      ask: "What names showed up over time?",
      answer: years.length
        ? `Dated public records span ${years[0]} to ${years[years.length - 1]}. ${ghostsOnly.length ? `Names in the certificate log that were not in this DNS pass: ${ghostsOnly.join(", ")}.` : "No extra certificate-log name was left unmatched."}`
        : "No dated certificate or registration marks were stored on this pass.",
    },
    {
      id: "parties",
      ask: "What third parties sit on the homepage?",
      answer: parties.length ? `Script URLs named ${parties.join(", ")}. Bodies were not fetched.` : "No off-site script host was named in the homepage HTML that was kept.",
    },
    {
      id: "expiry",
      ask: "What is about to expire?",
      answer:
        obs.tls?.daysRemaining == null
          ? "No certificate lifetime was observed."
          : obs.tls.daysRemaining <= 21
            ? `The presented certificate has ${obs.tls.daysRemaining} day(s) left.`
            : `The presented certificate has ${obs.tls.daysRemaining} day(s) left, outside the 21-day window.`,
    },
    {
      id: "who",
      ask: "Who operates it?",
      answer: obs.rdap?.entityNote
        ? `${obs.rdap.entityNote} Prex will not turn a registrar, CDN, or certificate issuer into a person’s name.`
        : "No registration entity was available. Prex does not invent an operator.",
    },
    {
      id: "description",
      ask: "Is there a public description?",
      answer: obs.publicNote?.found
        ? `${obs.publicNote.title ?? "A page"} matched on ${obs.publicNote.source}. ${obs.publicNote.extract ?? ""} This is not a customer review.`
        : "No encyclopedia page was attached. Prex did not invent a company biography.",
    },
    {
      id: "score",
      ask: "What is the rating and why?",
      answer: `${scorecard.overall.toFixed(1)} out of 10. ${scorecard.basis} ${scorecard.review}`,
    },
    {
      id: "other",
      ask: "What is the other site?",
      answer: shadow.length
        ? `${shadow.length} surrounding item(s): ${shadow
            .slice(0, 5)
            .map((row) => `${row.kind} ${row.label}`)
            .join("; ")}.`
        : "Nothing surrounding the front door was observed beyond the target itself.",
    },
    {
      id: "cert",
      ask: "What did the certificate say?",
      answer: obs.tls?.subject
        ? `Subject ${obs.tls.subject}${obs.tls.issuer ? `, issuer ${obs.tls.issuer}` : ""}${obs.tls.sans.length ? `, names ${obs.tls.sans.join(", ")}` : ""}.`
        : "No certificate was presented on this pass.",
    },
    {
      id: "refuse",
      ask: "What will you not claim?",
      answer: "No port scan, exploit, password, inbox, or private dossier. A quiet score is not a clean bill of health. A generated lookalike is not a phishing site.",
    },
  ];
}
