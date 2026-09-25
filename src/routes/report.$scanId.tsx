import { createFileRoute, Link } from "@tanstack/react-router";
import { Band, Button } from "@/components/prex/primitives";
import { Shell } from "@/components/prex/shell";
import { formatWhen, useHydrated, usePrex } from "@/lib/prex/store";

export const Route = createFileRoute("/report/$scanId")({
  component: ReportPage,
});

function ReportPage() {
  const { scanId } = Route.useParams();
  const hydrated = useHydrated();
  const scan = usePrex().scans.find((item) => item.id === scanId);
  if (!hydrated) {
    return (
      <Shell>
        <p className="text-sm text-mist">Opening the report.</p>
      </Shell>
    );
  }
  if (!scan) {
    return (
      <Shell>
        <p className="text-sm text-mist">This report is not stored in this browser.</p>
        <Link to="/" className="mt-4 inline-flex h-11 items-center text-sm">
          New map
        </Link>
      </Shell>
    );
  }

  return (
    <Shell>
      <div className="no-print flex flex-col gap-2 sm:flex-row">
        <Button tone="line" onClick={() => window.print()}>
          Print or save as PDF
        </Button>
        <Button
          tone="line"
          onClick={() => {
            const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = url;
            anchor.download = `prex-${scan.normalized.display.replace(/[^\w.-]+/g, "_")}.json`;
            anchor.click();
            URL.revokeObjectURL(url);
          }}
        >
          Download JSON
        </Button>
        <Link to="/footprint/$scanId" params={{ scanId }} search={{ view: "graph" }} className="inline-flex h-11 items-center px-3 text-sm text-mist">
          Back to map
        </Link>
      </div>
      <article className="mt-8 max-w-3xl">
        <p className="font-mono text-xs uppercase tracking-widest text-faint">Prex exposure report</p>
        <h1 className="mt-2 font-display text-4xl">{scan.normalized.display}</h1>
        <p className="mt-2 text-sm text-mist">
          {formatWhen(scan.createdAt)} · {scan.mode}
          {scan.demo ? " · demonstration dataset" : " · live observation"}
        </p>
        <h2 className="mt-8 font-display text-2xl">Briefing</h2>
        <div className="mt-3 space-y-3">
          {scan.briefing.map((line) => (
            <p key={line} className="text-sm leading-relaxed text-mist">
              {line}
            </p>
          ))}
        </div>
        <h2 className="mt-8 font-display text-2xl">What held</h2>
        <ul className="mt-3 space-y-2 text-sm text-mist">
          {scan.positives.map((item) => (
            <li key={item.id}>
              {item.title}. {item.detail}
            </li>
          ))}
          {scan.positives.length === 0 ? <li>No positive control was observed in this pass.</li> : null}
        </ul>
        <h2 className="mt-8 font-display text-2xl">Rule results</h2>
        <ul className="mt-3 divide-y divide-line border-y border-line">
          {scan.findings.map((finding) => (
            <li key={finding.id} className="py-4">
              <Band severity={finding.severity} score={finding.score} />
              <h3 className="mt-2 text-sm">{finding.title}</h3>
              <p className="mt-1 text-sm text-mist">{finding.whyItMatters}</p>
              <p className="mt-2 text-sm text-ink">{finding.remediation}</p>
              <p className="mt-2 font-mono text-xs text-faint">{finding.formula}</p>
            </li>
          ))}
        </ul>
        <h2 className="mt-8 font-display text-2xl">Changes</h2>
        {scan.changes.length === 0 ? (
          <p className="mt-3 text-sm text-mist">No comparison baseline.</p>
        ) : (
          <ul className="mt-3 space-y-3 text-sm text-mist">
            {scan.changes.map((change) => (
              <li key={change.id}>
                <span className="uppercase text-faint">{change.kind}. </span>
                {change.title} {change.detail}
              </li>
            ))}
          </ul>
        )}
        <h2 className="mt-8 font-display text-2xl">Limits</h2>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-mist">
          {scan.limitations.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <h2 className="mt-8 font-display text-2xl">Credential exposure</h2>
        <p className="mt-3 text-sm leading-relaxed text-mist">{scan.breach.statement}</p>
      </article>
    </Shell>
  );
}
