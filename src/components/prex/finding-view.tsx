import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { Band, Button } from "@/components/prex/primitives";
import { remediationDraft } from "@/lib/prex/engine";
import { addTicket, overlayFor, setOverlay, usePrex } from "@/lib/prex/store";
import type { Finding, ScanRecord } from "@/lib/prex/types";

export function FindingView({ scan, finding }: { scan: ScanRecord; finding: Finding }) {
  const state = usePrex();
  const status = overlayFor(state, scan.id, finding.id);
  const asset = scan.assets.find((item) => item.id === finding.assetId);
  const evidence = scan.evidence.filter((item) => finding.evidenceIds.includes(item.id));
  const [draft, setDraft] = useState<string | null>(null);
  const ticket = state.tickets.find((item) => item.scanId === scan.id && item.findingId === finding.id);

  return (
    <article className="grid gap-6 lg:grid-cols-2">
      <div>
        <p className="font-mono text-xs uppercase tracking-wide text-faint">
          {finding.category} · {finding.observation === "passive" ? "Passive observation" : "Verified safe check"} · {status}
        </p>
        <h2 className="mt-2 font-display text-3xl leading-tight">{finding.title}</h2>
        <p className="mt-4 text-sm leading-relaxed text-mist">{finding.rationale}</p>
        <p className="mt-3 text-sm leading-relaxed text-ink">{finding.whyItMatters}</p>
        <h3 className="mt-6 text-sm font-medium">Remediation</h3>
        <p className="mt-2 text-sm leading-relaxed text-mist">{finding.remediation}</p>
        {finding.references.length ? (
          <ul className="mt-3 space-y-1 text-sm">
            {finding.references.map((href) => (
              <li key={href}>
                <a href={href} className="text-mist underline decoration-line underline-offset-4" target="_blank" rel="noreferrer">
                  {href.replace(/^https:\/\//, "")}
                </a>
              </li>
            ))}
          </ul>
        ) : null}
        <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:flex-wrap">
          <Button tone="line" onClick={() => setOverlay(scan.id, finding.id, "acknowledged")}>
            Acknowledge
          </Button>
          <Button tone="line" onClick={() => setOverlay(scan.id, finding.id, "false_positive")}>
            Mark false positive
          </Button>
          <Button
            onClick={() => {
              const body = remediationDraft(finding, scan.normalized.display);
              setDraft(body);
              if (!ticket) {
                addTicket({ scanId: scan.id, findingId: finding.id, title: finding.title, body });
              }
            }}
          >
            {ticket ? "Show task" : "Draft remediation task"}
          </Button>
        </div>
        {draft || ticket ? (
          <pre className="mt-4 overflow-x-auto whitespace-pre-wrap rounded-md border border-line bg-inset p-4 font-mono text-xs leading-relaxed text-mist">
            {draft ?? ticket?.body}
          </pre>
        ) : null}
      </div>
      <div className="space-y-4">
        <section className="rounded-lg border border-line bg-panel p-4">
          <div className="flex items-baseline justify-between gap-3">
            <h3 className="text-sm font-medium">Explained score</h3>
            <Band severity={finding.severity} score={finding.score} />
          </div>
          <p className="mt-3 font-mono text-xs leading-relaxed text-mist">{finding.formula}</p>
          <ul className="mt-4 space-y-3">
            {finding.factorNotes.map((note) => {
              const value = factorValue(finding, note.factor);
              return (
                <li key={note.factor}>
                  <div className="flex items-baseline justify-between gap-3 text-xs">
                    <span>{note.factor}</span>
                    <span className="font-mono tabular-nums text-faint">{value}</span>
                  </div>
                  <div className="mt-1 h-1 rounded-sm bg-inset">
                    <div className="h-1 rounded-sm bg-paper" style={{ width: `${Math.min(100, value * 20)}%` }} />
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-faint">{note.note}</p>
                </li>
              );
            })}
          </ul>
          <p className="mt-4 text-xs leading-relaxed text-faint">
            Bands: 0–19 informational, 20–39 low, 40–59 medium, 60–79 high, 80–100 critical. Critical is not used for a single missing header.
          </p>
        </section>
        <section className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-sm font-medium">Asset</h3>
          <p className="mt-2 break-words text-sm text-mist">{asset?.label ?? finding.assetId}</p>
          <p className="mt-1 text-xs text-faint">{asset?.status}</p>
        </section>
        <section className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-sm font-medium">Evidence</h3>
          {evidence.length === 0 ? (
            <p className="mt-2 text-sm text-faint">This rule used the structured observation. No separate evidence card was attached.</p>
          ) : (
            evidence.map((item) => (
              <div key={item.id} className="mt-3 border-t border-line pt-3">
                <p className="font-mono text-xs text-faint">
                  {item.id} · {item.source} · {item.method}
                </p>
                <p className="mt-1 text-sm text-mist">{item.summary}</p>
                <dl className="mt-2 space-y-1">
                  {item.fields.slice(0, 8).map((field) => (
                    <div key={field.label + field.value} className="flex flex-col gap-1 text-xs sm:flex-row sm:gap-3">
                      <dt className="shrink-0 text-faint sm:w-24">{field.label}</dt>
                      <dd className="break-words text-mist">{field.value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            ))
          )}
        </section>
        <Link
          to="/footprint/$scanId"
          params={{ scanId: scan.id }}
          search={{ view: "findings" }}
          className="inline-flex h-11 items-center text-sm text-mist"
        >
          Back to findings
        </Link>
      </div>
    </article>
  );
}

function factorValue(finding: Finding, factor: string): number {
  const key = factor.toLowerCase();
  if (key.startsWith("exposure")) return finding.factors.exposure;
  if (key.startsWith("impact")) return finding.factors.impact;
  if (key.startsWith("exploit")) return finding.factors.exploitability;
  if (key.startsWith("confidence")) return Number((finding.factors.confidence * 5).toFixed(2));
  return Number((finding.factors.criticality * 5).toFixed(2));
}
