import { createFileRoute, Link } from "@tanstack/react-router";
import { Shell } from "@/components/prex/shell";
import { formatWhen, setAlerts, useHydrated, usePrex } from "@/lib/prex/store";
import type { ChangeEvent } from "@/lib/prex/types";

export const Route = createFileRoute("/monitor")({ component: MonitorPage });

function MonitorPage() {
  const hydrated = useHydrated();
  const state = usePrex();
  const changes = state.scans.flatMap((scan) =>
    scan.changes
      .filter((change) => armed(state.alerts, change))
      .map((change) => ({ ...change, scan })),
  );

  return (
    <Shell>
      <p className="font-mono text-xs uppercase tracking-widest text-faint">Watch</p>
      <h1 className="mt-2 max-w-xl font-display text-4xl leading-tight">What changed is the product.</h1>
      <p className="mt-4 max-w-2xl text-sm leading-relaxed text-mist">
        This preview does not run a scheduler. When you map a host again, Prex compares it with the previous copy in
        this browser and files the diff here. Enterprise scheduling would use the same comparison, inside a contract
        and a rate limit.
      </p>
      <fieldset className="mt-6 grid gap-2 sm:grid-cols-2" disabled={!hydrated}>
        <legend className="sr-only">Alert rules</legend>
        <Toggle label="New and removed labels" on={state.alerts.newAsset} set={(newAsset) => setAlerts({ ...state.alerts, newAsset })} />
        <Toggle label="Header, mail, and CDN regressions" on={state.alerts.regression} set={(regression) => setAlerts({ ...state.alerts, regression })} />
        <Toggle label="Certificate window" on={state.alerts.cert} set={(cert) => setAlerts({ ...state.alerts, cert })} />
        <Toggle label="New rule results" on={state.alerts.newFinding} set={(newFinding) => setAlerts({ ...state.alerts, newFinding })} />
      </fieldset>
      <section className="mt-8">
        <h2 className="font-mono text-xs uppercase tracking-widest text-faint">Changes</h2>
        {changes.length === 0 ? (
          <p className="mt-3 text-sm text-mist">Nothing armed has a diff yet. Open the Northline sample to see a scripted week-over-week change list.</p>
        ) : (
          <ul className="mt-3 divide-y divide-line border-y border-line">
            {changes.map((change) => (
              <li key={change.scan.id + change.id} className="py-4">
                <Link to="/footprint/$scanId" params={{ scanId: change.scan.id }} search={{ view: "changes" }} className="text-sm">
                  {change.title}
                </Link>
                <p className="mt-1 text-sm text-mist">{change.detail}</p>
                <p className="mt-1 font-mono text-xs text-faint">
                  {change.scan.normalized.display} · {formatWhen(change.scan.createdAt)}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="mt-8">
        <h2 className="font-mono text-xs uppercase tracking-widest text-faint">Remediation tasks</h2>
        {state.tickets.length === 0 ? (
          <p className="mt-3 text-sm text-mist">Draft one from a finding. The text is a template, not a model.</p>
        ) : (
          <ul className="mt-3 space-y-3">
            {state.tickets.map((ticket) => (
              <li key={ticket.id} className="rounded-lg border border-line bg-panel p-4">
                <p className="text-sm">{ticket.title}</p>
                <pre className="mt-2 whitespace-pre-wrap font-mono text-xs leading-relaxed text-mist">{ticket.body}</pre>
              </li>
            ))}
          </ul>
        )}
      </section>
    </Shell>
  );
}

function armed(alerts: { newAsset: boolean; regression: boolean; cert: boolean; newFinding: boolean }, change: ChangeEvent) {
  if (change.kind === "added" || change.kind === "removed") {
    if (change.title.startsWith("New rule")) return alerts.newFinding;
    return alerts.newAsset;
  }
  if (/certificate/i.test(change.title)) return alerts.cert;
  return alerts.regression;
}

function Toggle({ label, on, set }: { label: string; on: boolean; set: (value: boolean) => void }) {
  return (
    <label className="flex min-h-11 items-center justify-between gap-3 rounded-md border border-line px-3 text-sm">
      <span>{label}</span>
      <input type="checkbox" checked={on} onChange={(event) => set(event.target.checked)} />
    </label>
  );
}
