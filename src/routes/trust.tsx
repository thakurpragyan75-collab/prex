import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/prex/shell";

export const Route = createFileRoute("/trust")({ component: TrustPage });

const SECTIONS = [
  {
    title: "What a public map is allowed to do",
    body: "Resolve public DNS, read RDAP, observe a TLS handshake, request the homepage, request /.well-known/security.txt, and HEAD /robots.txt and port 80. Paths, queries, and non-default ports are stripped or refused. Redirects that leave the registrable domain are not followed.",
  },
  {
    title: "What it will not do",
    body: "Port scans, endpoint wordlists, login attempts, credential stuffing, exploit payloads, destructive tests, private-network access, and dossiers on people. If a name resolves to a loopback, link-local, or RFC1918 address, the connection is refused and the address is not shown.",
  },
  {
    title: "Ownership",
    body: "A host you typed is “observed”. A certificate-log name is “suspected”. “Verified-owned” appears only after a proof check succeeds on that pass. A CDN, an ASN, or a certificate issuer is never rewritten into a person’s name.",
  },
  {
    title: "Secrets and breaches",
    body: "Cookie values are discarded. Set-Cookie is reduced to flags. Secret material is not stored or rendered. Breach corpora are not queried. The product can describe an aggregate count in a contracted deployment. It will not show stolen passwords.",
  },
  {
    title: "Data in this preview",
    body: "Maps, proofs, tasks, and the audit log live in this browser. Clearing site data deletes them. There is no account. Do not map targets you are not willing to leave in local storage.",
  },
  {
    title: "Scoring",
    body: "Finding score = round(exposure × impact × exploitability × confidence × criticality × 1.35), clamped to 0–100. Each factor is stored with a sentence. A missing header cannot become critical by itself. The separate out-of-10 posture number is an average of up to 20 public signals and is not that formula.",
  },
  {
    title: "The other site, the time cut, and the score",
    body: "The other site lists certificate-log names, aliases, script hosts, and mail from the same pass. It does not crawl them. The time cut is dated certificate and registration rows, not a claim those names still resolve. The out-of-10 figure averages only the signals that returned, up to 20. Blank signals are not filled in. If almost nothing came back, the number is from the name alone and is labeled unmeasured. Wikipedia text, when a page matches the name, is an encyclopedia extract. It is not a customer review. No review site is queried.",
  },
  {
    title: "Disclosure",
    body: "If you find a flaw in Prex, describe the issue and the evidence, without exploit steps, through your own channel to the operator of this deployment. This preview does not publish a monitored mailbox. For a site you mapped, use the security.txt contact Prex observed, if one was published. Do not test systems you do not control.",
  },
  {
    title: "Safe harbor",
    body: "Good-faith research against assets you have verified, inside the allowed modules, is the only assessment Prex will deepen. Traffic that brute-forces, exploits, or leaves scope is out of policy even if a control check once succeeded.",
  },
];

function TrustPage() {
  return (
    <Shell>
      <p className="font-mono text-xs uppercase tracking-widest text-faint">Trust boundary</p>
      <h1 className="mt-2 max-w-xl font-display text-4xl leading-tight">Serious only if it can refuse.</h1>
      <div className="mt-8 max-w-3xl divide-y divide-line border-y border-line">
        {SECTIONS.map((section) => (
          <section key={section.title} className="py-5">
            <h2 className="text-base font-medium">{section.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-mist">{section.body}</p>
          </section>
        ))}
      </div>
    </Shell>
  );
}
