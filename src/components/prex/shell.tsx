import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

const LINKS = [
  { to: "/", label: "Map", exact: true },
  { to: "/monitor", label: "Watch" },
  { to: "/authorization", label: "Proof" },
  { to: "/audit", label: "Audit" },
  { to: "/trust", label: "Trust" },
] as const;

export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-dvh bg-canvas text-ink">
      <header className="no-print border-b border-line">
        <div className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between md:px-6">
          <Link to="/" className="flex items-baseline gap-3">
            <span className="font-display text-2xl italic tracking-tight">Prex</span>
            <span className="font-mono text-xs uppercase tracking-widest text-faint">Exposure graph</span>
          </Link>
          <nav className="flex gap-1 overflow-x-auto" aria-label="Primary">
            {LINKS.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                activeOptions={{ exact: "exact" in link && link.exact }}
                className="inline-flex h-11 shrink-0 items-center rounded-sm px-3 text-sm text-mist data-[status=active]:bg-panel data-[status=active]:text-ink"
              >
                {link.label}
              </Link>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl px-4 py-6 md:px-6 md:py-8">{children}</main>
    </div>
  );
}
