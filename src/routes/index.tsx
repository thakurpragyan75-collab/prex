import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Shell } from "@/components/prex/shell";
import { Button, TextField } from "@/components/prex/primitives";
import { mapExposure } from "@/lib/prex/api";
import { collectorPreview, isDemoQuery, normalizeTarget } from "@/lib/prex/engine";
import { addScan, formatWhen, proofForHost, readPrex, useHydrated, usePrex } from "@/lib/prex/store";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const navigate = useNavigate();
  const hydrated = useHydrated();
  const state = usePrex();
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  const norm = useMemo(() => (value.trim() ? normalizeTarget(value) : null), [value]);
  const host = norm?.host ?? null;
  const proof = hydrated ? proofForHost(state, host) : null;
  const demo = value.trim() ? isDemoQuery(value) || host === "northline.example" : false;
  const mode = proof || demo ? "verified" : "public";

  async function run(target: string, withDemoProof = false) {
    setError("");
    setPending(true);
    const normalized = normalizeTarget(target);
    const attached = withDemoProof
        ? { method: "demonstration" as const, token: "northline-demo-proof" }
        : proofForHost(readPrex(), normalized.host);
    try {
      const result = await mapExposure({
        data: { target, proof: attached ? { method: attached.method, token: attached.token } : null },
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      const saved = addScan(result.scan);
      await navigate({ to: "/footprint/$scanId", params: { scanId: saved.id }, search: { view: "graph" } });
    } catch {
      setError("The map did not finish. Nothing was stored.");
    } finally {
      setPending(false);
    }
  }

  return (
    <Shell>
      <div className="grid gap-10 lg:grid-cols-2 lg:gap-16">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-faint">Public footprint first</p>
          <h1 className="mt-3 max-w-xl font-display text-4xl leading-tight text-ink md:text-5xl">
            The public record, with the receipt attached.
          </h1>
          <p className="mt-4 max-w-xl text-base leading-relaxed text-mist">
            Give Prex a domain, URL, IP, or brand. It maps the public footprint, the names around it, and a 20-signal posture score out of 10. It does not scan ports, guess passwords, invent reviews, or invent an owner.
          </p>
          <form
            className="mt-8 flex flex-col gap-2 sm:flex-row"
            onSubmit={(event) => {
              event.preventDefault();
              if (!value.trim() || pending) return;
              void run(value.trim());
            }}
          >
            <label className="sr-only" htmlFor="target">
              Domain, URL, IP, or brand
            </label>
            <TextField
              id="target"
              value={value}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="Domain, URL, IP, or brand"
              onChange={(event) => setValue(event.target.value)}
            />
            <Button type="submit" disabled={pending || !value.trim()} className="sm:w-auto">
              {pending ? "Mapping" : proof ? "Map and recheck" : "Map exposure"}
            </Button>
          </form>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <Button
              tone="line"
              disabled={pending}
              onClick={() => {
                setValue("northline.example");
                void run("northline.example");
              }}
            >
              Open the Northline sample
            </Button>
            <Button
              tone="ghost"
              disabled={pending}
              onClick={() => {
                setValue("example.com");
              }}
            >
              Use example.com
            </Button>
          </div>
          {error ? (
            <p className="mt-4 text-sm text-danger" role="alert">
              {error}
            </p>
          ) : null}
          {norm?.kind === "rejected" ? <p className="mt-4 text-sm text-mist">{norm.rejectReason}</p> : null}
          {norm && norm.kind !== "rejected" ? (
            <div className="mt-6 border-t border-line pt-4">
              <p className="font-mono text-xs uppercase tracking-wide text-faint">
                {demo ? "Demonstration dataset" : mode === "verified" ? "Proof on file for this host" : "Public mode"}
                {" · "}
                {norm.display}
              </p>
              <ul className="mt-3 space-y-2">
                {collectorPreview(norm, proof ? "verified" : "public").map((step) => (
                  <li key={step.title} className="flex items-baseline justify-between gap-4 text-sm">
                    <span>{step.title}</span>
                    <span className="font-mono text-xs uppercase text-faint">{step.expect}</span>
                  </li>
                ))}
              </ul>
              {norm.notes.map((note) => (
                <p key={note} className="mt-2 text-sm text-faint">
                  {note}
                </p>
              ))}
            </div>
          ) : null}
          {pending ? (
            <p className="prex-wait mt-6 text-sm text-mist">
              Collectors are running as one pass. Denied actions stay denied. Results replace this note.
            </p>
          ) : null}
        </div>
        <ModeTable />
      </div>
      <Recent hydrated={hydrated} scans={state.scans} />
    </Shell>
  );
}

function ModeTable() {
  const rows = [
    ["Public footprint", "Anyone", "DNS, RDAP, certificate names, homepage headers, mail policy.", "No brute force, port scans, or dossiers."],
    ["Authorized assessment", "Proved control", "The same map, plus a second safe fetch after DNS, file, or meta proof.", "No exploits, logins, or out-of-scope hosts."],
    ["Continuous watch", "You, in this browser", "The next map is compared with the last one stored here.", "No server-side scheduler in this preview."],
  ];
  return (
    <div className="border-t border-line pt-6 lg:border-l lg:border-t-0 lg:pt-0 lg:pl-8">
      <h2 className="font-display text-2xl">Three modes, not one scan button</h2>
      <div className="mt-5 divide-y divide-line">
        {rows.map((row) => (
          <article key={row[0]} className="py-4">
            <h3 className="text-sm font-medium">{row[0]}</h3>
            <p className="mt-1 font-mono text-xs uppercase tracking-wide text-faint">{row[1]}</p>
            <p className="mt-2 text-sm leading-relaxed text-mist">{row[2]}</p>
            <p className="mt-1 text-sm leading-relaxed text-faint">{row[3]}</p>
          </article>
        ))}
      </div>
      <p className="mt-2 text-sm text-faint">
        Severity is arithmetic you can read. Critical is reserved for compounded evidence, not a missing header.
      </p>
    </div>
  );
}

function Recent({ hydrated, scans }: { hydrated: boolean; scans: { id: string; normalized: { display: string }; mode: string; createdAt: string; demo: boolean }[] }) {
  if (!hydrated || scans.length === 0) return null;
  return (
    <section className="mt-12 border-t border-line pt-6">
      <h2 className="font-mono text-xs uppercase tracking-widest text-faint">Recent maps in this browser</h2>
      <ul className="mt-3 divide-y divide-line">
        {scans.map((scan) => (
          <li key={scan.id}>
            <Link
              to="/footprint/$scanId"
              params={{ scanId: scan.id }}
              search={{ view: "graph" }}
              className="flex min-h-11 flex-col justify-center gap-1 py-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <span className="text-sm">
                {scan.normalized.display}
                {scan.demo ? <span className="text-faint"> · sample</span> : null}
              </span>
              <span className="font-mono text-xs text-faint">
                {scan.mode} · {formatWhen(scan.createdAt)}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
