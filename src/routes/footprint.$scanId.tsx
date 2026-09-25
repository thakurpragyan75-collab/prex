import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Ask, OtherSite, Score, TimeCut } from "@/components/prex/lens";
import { ExposureGraph } from "@/components/prex/graph";
import { FindingView } from "@/components/prex/finding-view";
import { Band, Panel } from "@/components/prex/primitives";
import { Shell } from "@/components/prex/shell";
import { formatWhen, overlayFor, useHydrated, usePrex } from "@/lib/prex/store";
import type { Severity } from "@/lib/prex/types";

type View = "graph" | "other" | "time" | "ask" | "score" | "findings" | "assets" | "changes" | "collectors";

export const Route = createFileRoute("/footprint/$scanId")({
  validateSearch: (search: Record<string, unknown>): { view: View; fid?: string } => {
    const view = search.view;
    const allowed: View[] = ["graph", "other", "time", "ask", "score", "findings", "assets", "changes", "collectors"];
    const fid = typeof search.fid === "string" ? search.fid : undefined;
    return {
      view: allowed.includes(view as View) ? (view as View) : "graph",
      fid,
    };
  },
  component: FootprintPage,
});

function FootprintPage() {
  const { scanId } = Route.useParams();
  const { view, fid } = Route.useSearch();
  const hydrated = useHydrated();
  const state = usePrex();
  const scan = state.scans.find((item) => item.id === scanId);

  if (!hydrated) {
    return (
      <Shell>
        <p className="text-sm text-mist">Opening the map stored in this browser.</p>
      </Shell>
    );
  }
  if (!scan) {
    return (
      <Shell>
        <h1 className="font-display text-3xl">This map is not in this browser.</h1>
        <p className="mt-3 max-w-lg text-sm text-mist">Maps stay on this device. Run another pass from the start page.</p>
        <Link to="/" className="mt-6 inline-flex h-11 items-center text-sm text-ink">
          New map
        </Link>
      </Shell>
    );
  }

  const finding = fid ? scan.findings.find((item) => item.id === fid) : undefined;
  const highest = scan.findings[0];

  return (
    <Shell>
      <header className="flex flex-col gap-4 border-b border-line pb-5 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-widest text-faint">
            {scan.demo ? "Demonstration" : "Live observation"} · {scan.mode} · {formatWhen(scan.createdAt)}
          </p>
          <h1 className="mt-2 break-words font-display text-4xl leading-tight">{scan.normalized.display}</h1>
          <p className="mt-2 max-w-2xl text-sm text-mist">{scan.verification.detail}</p>
        </div>
        <div className="text-left md:text-right">
          {highest ? <Band severity={highest.severity} score={highest.score} /> : <span className="text-sm text-mist">No rule fired</span>}
          {scan.scorecard ? (
            <p className="mt-1 font-mono text-xs text-faint">
              {scan.scorecard.overall.toFixed(1)} / 10 public posture · {scan.scorecard.coverage}/20 signals
            </p>
          ) : (
            <p className="mt-1 font-mono text-xs text-faint">{scan.findings.length} results · {scan.assets.length} entities</p>
          )}
        </div>
      </header>

      {scan.demo ? (
        <p className="mt-4 rounded-md border border-line bg-panel px-3 py-3 text-sm leading-relaxed text-mist">
          Northline Freight is a fictional tenant on the reserved example domain. Collectors did not contact it. The
          change list is a scripted prior week, so you can see how a diff reads.
        </p>
      ) : null}

      <div className="mt-5 space-y-2">
        {scan.briefing.slice(0, 4).map((line) => (
          <p key={line} className="max-w-3xl text-sm leading-relaxed text-mist">
            {line}
          </p>
        ))}
      </div>

      <nav className="no-print mt-6 flex gap-2 overflow-x-auto" aria-label="Map sections">
        {(
          [
            ["graph", "Graph"],
            ["other", "Other site"],
            ["time", "Time"],
            ["ask", "Ask"],
            ["score", "Score"],
            ["findings", "Findings"],
            ["assets", "Assets"],
            ["changes", "Changes"],
            ["collectors", "Collectors"],
          ] as const
        ).map(([id, label]) => (
          <Link
            key={id}
            to="/footprint/$scanId"
            params={{ scanId }}
            search={{ view: id }}
            className={`inline-flex h-11 shrink-0 items-center rounded-sm px-3 text-sm ${view === id && !fid ? "bg-paper text-canvas" : "text-mist"}`}
          >
            {label}
          </Link>
        ))}
        <Link
          to="/report/$scanId"
          params={{ scanId }}
          className="inline-flex h-11 shrink-0 items-center rounded-sm px-3 text-sm text-mist"
        >
          Report
        </Link>
      </nav>

      <div className="mt-6">
        {finding ? (
          <FindingView scan={scan} finding={finding} />
        ) : view === "graph" ? (
          <ExposureGraph scan={scan} />
        ) : view === "other" ? (
          <OtherSite scan={scan} />
        ) : view === "time" ? (
          <TimeCut scan={scan} />
        ) : view === "ask" ? (
          <Ask scan={scan} />
        ) : view === "score" ? (
          <Score scan={scan} />
        ) : view === "findings" ? (
          <Findings scanId={scanId} />
        ) : view === "assets" ? (
          <AssetList scanId={scanId} />
        ) : view === "changes" ? (
          <Changes scanId={scanId} />
        ) : (
          <Collectors scanId={scanId} />
        )}
      </div>
    </Shell>
  );
}

function Findings({ scanId }: { scanId: string }) {
  const scan = usePrex().scans.find((item) => item.id === scanId);
  const state = usePrex();
  const [band, setBand] = useState<"all" | Severity>("all");
  const [query, setQuery] = useState("");
  if (!scan) return null;
  const rows = scan.findings.filter((finding) => {
    if (band !== "all" && finding.severity !== band) return false;
    const blob = `${finding.title} ${finding.category}`.toLowerCase();
    return blob.includes(query.trim().toLowerCase());
  });
  return (
    <div>
      <div className="flex flex-col gap-2 sm:flex-row">
        <label className="sr-only" htmlFor="finding-search">
          Filter findings
        </label>
        <input
          id="finding-search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter by title"
          className="h-11 w-full rounded-sm border border-line bg-inset px-3 text-sm text-ink outline-none placeholder:text-faint sm:max-w-xs"
        />
        <div className="flex gap-1 overflow-x-auto">
          {(["all", "high", "medium", "low", "informational"] as const).map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => setBand(item)}
              className={`h-11 shrink-0 rounded-sm px-3 text-xs uppercase ${band === item ? "bg-paper text-canvas" : "text-mist"}`}
            >
              {item}
            </button>
          ))}
        </div>
      </div>
      {scan.positives.length ? (
        <ul className="mt-4 divide-y divide-line border-y border-line">
          {scan.positives.map((item) => (
            <li key={item.id} className="py-3 text-sm">
              <span className="text-ok">{item.title}</span>
              <span className="text-faint"> — {item.detail}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {rows.length === 0 ? (
        <p className="mt-6 text-sm text-mist">No rule in this filter fired. Coverage is only the checks that ran.</p>
      ) : (
        <ul className="mt-4 divide-y divide-line">
          {rows.map((finding) => (
            <li key={finding.id}>
              <Link
                to="/footprint/$scanId"
                params={{ scanId }}
                search={{ view: "findings", fid: finding.id }}
                className="flex flex-col gap-1 py-4 md:flex-row md:items-center md:justify-between md:gap-4"
              >
                <Band severity={finding.severity} score={finding.score} />
                <span className="min-w-0">
                  <span className="block text-sm">{finding.title}</span>
                  <span className="mt-1 block text-xs text-faint">
                    {finding.category} · {overlayFor(state, scanId, finding.id)}
                  </span>
                </span>
                <span className="font-mono text-xs text-faint">{Math.round(finding.confidence * 100)}%</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AssetList({ scanId }: { scanId: string }) {
  const scan = usePrex().scans.find((item) => item.id === scanId);
  if (!scan) return null;
  return (
    <ul className="divide-y divide-line border-y border-line">
      {scan.assets.map((asset) => (
        <li key={asset.id} className="flex flex-col gap-1 py-4 md:flex-row md:gap-6">
          <span className="font-mono text-xs uppercase text-faint">{asset.kind}</span>
          <span>
            <span className="block break-words text-sm">{asset.label}</span>
            <span className="mt-1 block text-xs text-mist">
              {asset.status} · {Math.round(asset.confidence * 100)}% · {asset.summary}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}

function Changes({ scanId }: { scanId: string }) {
  const scan = usePrex().scans.find((item) => item.id === scanId);
  if (!scan) return null;
  if (scan.changes.length === 0) {
    return (
      <Panel>
        <h2 className="font-display text-2xl">No prior map to compare.</h2>
        <p className="mt-2 text-sm leading-relaxed text-mist">
          Map this host again later. Prex will diff addresses, headers, mail policy, certificate window, and new rule
          results against the copy stored in this browser.
        </p>
      </Panel>
    );
  }
  return (
    <ul className="divide-y divide-line border-y border-line">
      {scan.changes.map((change) => (
        <li key={change.id} className="py-4">
          <p className="font-mono text-xs uppercase text-faint">{change.kind}</p>
          <h3 className="mt-1 text-sm">{change.title}</h3>
          <p className="mt-1 text-sm text-mist">{change.detail}</p>
        </li>
      ))}
    </ul>
  );
}

function Collectors({ scanId }: { scanId: string }) {
  const scan = usePrex().scans.find((item) => item.id === scanId);
  if (!scan) return null;
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section>
        <h2 className="font-mono text-xs uppercase tracking-widest text-faint">Orchestrator</h2>
        <ol className="mt-3 space-y-3">
          {scan.plan.map((step, index) => (
            <li key={step.id} className="border-t border-line pt-3">
              <p className="text-sm">
                {index + 1}. {step.title}
              </p>
              <p className="mt-1 text-sm text-mist">{step.detail}</p>
            </li>
          ))}
        </ol>
        <ul className="mt-6 divide-y divide-line border-y border-line">
          {scan.collectors.map((collector) => (
            <li key={collector.id} className="flex items-start justify-between gap-3 py-3 text-sm">
              <span>
                {collector.title}
                <span className="mt-1 block text-xs text-faint">{collector.detail}</span>
              </span>
              <span className="shrink-0 font-mono text-xs uppercase text-mist">{collector.status}</span>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h2 className="font-mono text-xs uppercase tracking-widest text-faint">Policy decisions</h2>
        <ul className="mt-3 divide-y divide-line border-y border-line">
          {scan.policy.map((decision) => (
            <li key={decision.action + decision.reason} className="py-3">
              <p className="flex items-baseline justify-between gap-3 text-sm">
                <span>{decision.action}</span>
                <span className={`font-mono text-xs uppercase ${decision.decision === "deny" ? "text-danger" : "text-ok"}`}>
                  {decision.decision}
                </span>
              </p>
              <p className="mt-1 text-xs leading-relaxed text-faint">{decision.reason}</p>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
