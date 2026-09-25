import { useSyncExternalStore } from "react";
import { deriveChanges, newId } from "./engine.ts";
import type { ProofMethod, ScanRecord } from "./types.ts";

export type Ticket = {
  id: string;
  scanId: string;
  findingId: string;
  title: string;
  body: string;
  createdAt: string;
};

export type Verification = {
  host: string;
  method: ProofMethod;
  token: string;
  checkedAt: string;
  ok: boolean;
  detail: string;
};

export type AuditEntry = { id: string; at: string; action: string; detail: string };

export type Alerts = {
  newAsset: boolean;
  regression: boolean;
  cert: boolean;
  newFinding: boolean;
};

type Overlay = "acknowledged" | "false_positive";

type State = {
  scans: ScanRecord[];
  verifications: Verification[];
  tickets: Ticket[];
  overlays: Record<string, Overlay>;
  audit: AuditEntry[];
  alerts: Alerts;
};

const DEFAULT_ALERTS: Alerts = { newAsset: true, regression: true, cert: true, newFinding: true };

const EMPTY: State = {
  scans: [],
  verifications: [],
  tickets: [],
  overlays: {},
  audit: [],
  alerts: DEFAULT_ALERTS,
};

const KEY = "prex.v1";
let memory: State = EMPTY;
let loaded = false;
const listeners = new Set<() => void>();

function sanitize(value: unknown): State {
  if (!value || typeof value !== "object") return EMPTY;
  const row = value as Partial<State>;
  return {
    scans: Array.isArray(row.scans) ? row.scans.slice(0, 8) : [],
    verifications: Array.isArray(row.verifications) ? row.verifications.slice(0, 20) : [],
    tickets: Array.isArray(row.tickets) ? row.tickets.slice(0, 40) : [],
    overlays: row.overlays && typeof row.overlays === "object" ? row.overlays : {},
    audit: Array.isArray(row.audit) ? row.audit.slice(0, 80) : [],
    alerts: { ...DEFAULT_ALERTS, ...(row.alerts ?? {}) },
  };
}

function ensure() {
  if (loaded || typeof window === "undefined") return;
  loaded = true;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (raw) memory = sanitize(JSON.parse(raw));
  } catch {
    memory = EMPTY;
  }
}

function emit() {
  if (typeof window !== "undefined") window.localStorage.setItem(KEY, JSON.stringify(memory));
  for (const listener of listeners) listener();
}

function commit(next: State) {
  memory = next;
  loaded = true;
  emit();
}

function snapshot(): State {
  ensure();
  return memory;
}

export function readPrex(): State {
  return snapshot();
}

export function usePrex(): State {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot,
    () => EMPTY,
  );
}

export function useHydrated(): boolean {
  return useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  );
}

export function logAudit(action: string, detail: string) {
  const entry: AuditEntry = { id: newId("aud"), at: new Date().toISOString(), action, detail };
  commit({ ...snapshot(), audit: [entry, ...snapshot().audit].slice(0, 80) });
}

export function addScan(scan: ScanRecord) {
  const current = snapshot();
  const prev = current.scans.find((item) => item.targetKey === scan.targetKey && !item.demo && !scan.demo);
  const record = prev ? { ...scan, changes: deriveChanges(prev, scan) } : scan;
  commit({
    ...current,
    scans: [record, ...current.scans.filter((item) => item.id !== record.id)].slice(0, 8),
    audit: [
      {
        id: newId("aud"),
        at: record.createdAt,
        action: "Map finished",
        detail: `${record.normalized.display} · ${record.mode} · ${record.findings.length} rule result(s)`,
      },
      ...current.audit,
    ].slice(0, 80),
  });
  return record;
}

export function setOverlay(scanId: string, findingId: string, overlay: Overlay) {
  const key = `${scanId}:${findingId}`;
  commit({ ...snapshot(), overlays: { ...snapshot().overlays, [key]: overlay } });
  logAudit(overlay === "acknowledged" ? "Finding acknowledged" : "Marked false positive", findingId);
}

export function overlayFor(state: State, scanId: string, findingId: string): Overlay | "open" {
  return state.overlays[`${scanId}:${findingId}`] ?? "open";
}

export function addTicket(ticket: Omit<Ticket, "id" | "createdAt">) {
  const item: Ticket = { ...ticket, id: newId("tkt"), createdAt: new Date().toISOString() };
  commit({ ...snapshot(), tickets: [item, ...snapshot().tickets].slice(0, 40) });
  logAudit("Remediation task drafted", ticket.title);
  return item;
}

export function saveVerification(entry: Verification) {
  const rest = snapshot().verifications.filter((item) => item.host !== entry.host);
  commit({ ...snapshot(), verifications: [entry, ...rest].slice(0, 20) });
  logAudit(entry.ok ? "Control proof accepted" : "Control proof failed", `${entry.host}: ${entry.detail}`);
}

export function proofForHost(state: State, host: string | null): Verification | null {
  if (!host) return null;
  const found = state.verifications.find((item) => item.host === host && item.ok);
  if (!found) return null;
  const age = Date.now() - new Date(found.checkedAt).getTime();
  if (Number.isNaN(age) || age > 7 * 86_400_000) return null;
  return found;
}

export function setAlerts(alerts: Alerts) {
  commit({ ...snapshot(), alerts });
}

export function formatWhen(iso: string): string {
  return iso.replace("T", " ").replace(/\.\d+Z$/, " UTC").replace("Z", " UTC");
}
