import { useState } from "react";
import type { Asset, ScanRecord } from "@/lib/prex/types";

export function ExposureGraph({ scan }: { scan: ScanRecord }) {
  const root =
    scan.assets.find((asset) => asset.kind === "domain") ??
    scan.assets.find((asset) => asset.kind === "ip" && asset.label === scan.normalized.host) ??
    scan.assets[0];
  const [selectedId, setSelectedId] = useState(root?.id ?? "");
  const selected = scan.assets.find((asset) => asset.id === selectedId) ?? root;
  const links = root ? scan.relations.filter((rel) => rel.from === root.id) : [];

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="rounded-lg border border-line bg-inset p-4">
        {root ? (
          <AssetButton asset={root} selected={selected?.id === root.id} onSelect={setSelectedId} />
        ) : (
          <p className="text-sm text-mist">No entities were recorded.</p>
        )}
        <ul className="mt-4 border-l border-line">
          {links.map((rel) => {
            const asset = scan.assets.find((item) => item.id === rel.to);
            if (!asset) return null;
            return (
              <li key={rel.id} className="py-1 pl-4">
                <p className="font-mono text-xs uppercase tracking-wide text-faint">{rel.type}</p>
                <AssetButton asset={asset} selected={selected?.id === asset.id} onSelect={setSelectedId} />
              </li>
            );
          })}
        </ul>
      </div>
      {selected ? <AssetCard scan={scan} asset={selected} onSelect={setSelectedId} /> : null}
    </div>
  );
}

function AssetButton({
  asset,
  selected,
  onSelect,
}: {
  asset: Asset;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect(asset.id)}
      className={`flex min-h-11 w-full items-center justify-between gap-3 rounded-sm px-3 text-left ${selected ? "bg-panel" : ""}`}
    >
      <span className="min-w-0">
        <span className="block truncate text-sm">{asset.label}</span>
        <span className="font-mono text-xs uppercase text-faint">
          {asset.kind} · {asset.status}
        </span>
      </span>
      <span className="shrink-0 font-mono text-xs tabular-nums text-faint">{Math.round(asset.confidence * 100)}%</span>
    </button>
  );
}

function AssetCard({
  scan,
  asset,
  onSelect,
}: {
  scan: ScanRecord;
  asset: Asset;
  onSelect: (id: string) => void;
}) {
  const links = scan.relations.filter((rel) => rel.from === asset.id || rel.to === asset.id);
  const evidence = scan.evidence.filter((item) => asset.evidenceIds.includes(item.id));
  return (
    <aside className="rounded-lg border border-line bg-panel p-4">
      <p className="font-mono text-xs uppercase tracking-wide text-faint">
        {asset.kind} · {asset.status} · {Math.round(asset.confidence * 100)}% confidence
      </p>
      <h2 className="mt-2 break-words font-display text-2xl leading-tight">{asset.label}</h2>
      <p className="mt-3 text-sm leading-relaxed text-mist">{asset.summary}</p>
      {links.length ? (
        <ul className="mt-4 space-y-2">
          {links.slice(0, 8).map((rel) => {
            const otherId = rel.from === asset.id ? rel.to : rel.from;
            const other = scan.assets.find((item) => item.id === otherId);
            if (!other) return null;
            return (
              <li key={rel.id}>
                <button type="button" onClick={() => onSelect(other.id)} className="min-h-11 text-left text-sm text-mist">
                  <span className="text-faint">{rel.type} </span>
                  {other.label}
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
      {evidence.map((item) => (
        <div key={item.id} className="mt-4 border-t border-line pt-3">
          <p className="font-mono text-xs text-faint">
            {item.id} · {item.source}
          </p>
          <p className="mt-1 text-sm text-mist">{item.summary}</p>
        </div>
      ))}
    </aside>
  );
}
