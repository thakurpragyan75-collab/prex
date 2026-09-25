import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/prex/shell";
import { formatWhen, useHydrated, usePrex } from "@/lib/prex/store";

export const Route = createFileRoute("/audit")({ component: AuditPage });

function AuditPage() {
  const hydrated = useHydrated();
  const audit = usePrex().audit;
  return (
    <Shell>
      <p className="font-mono text-xs uppercase tracking-widest text-faint">Audit</p>
      <h1 className="mt-2 font-display text-4xl">Who asked for what.</h1>
      <p className="mt-4 max-w-2xl text-sm leading-relaxed text-mist">
        This preview keeps the log in the browser, next to the maps. A deployment would append the same events to an
        immutable store: every map, policy denial, proof check, acknowledgement, and drafted task.
      </p>
      {!hydrated || audit.length === 0 ? (
        <p className="mt-8 text-sm text-mist">No events yet. A map or a proof check will write the first line.</p>
      ) : (
        <ul className="mt-8 divide-y divide-line border-y border-line">
          {audit.map((entry) => (
            <li key={entry.id} className="flex flex-col gap-1 py-4 md:flex-row md:gap-6">
              <time className="font-mono text-xs text-faint">{formatWhen(entry.at)}</time>
              <span>
                <span className="block text-sm">{entry.action}</span>
                <span className="mt-1 block text-sm text-mist">{entry.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Shell>
  );
}
