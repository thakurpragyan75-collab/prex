import assert from "node:assert/strict";
import test from "node:test";
import { compileScan, deriveChanges, explainScore, isDemoQuery, isPublicIp, normalizeTarget, policyFor, registrableDomain } from "./engine.ts";
import { northlineObservations } from "./demo-data.ts";

test("normalizer strips paths and refuses private targets", () => {
  const url = normalizeTarget("https://www.Example.com/admin?x=1#top");
  assert.equal(url.kind, "domain");
  assert.equal(url.host, "www.example.com");
  assert.equal(url.registrable, "example.com");
  assert.ok(url.notes.some((n) => n.includes("stripped")));

  assert.equal(normalizeTarget("10.1.1.1").kind, "rejected");
  assert.equal(normalizeTarget("http://169.254.169.254/").kind, "rejected");
  assert.equal(normalizeTarget("https://example.com:8443/").kind, "rejected");
  assert.equal(normalizeTarget("http://user:pass@example.com").kind, "rejected");
  assert.equal(normalizeTarget("localhost").kind, "rejected");
  assert.equal(normalizeTarget("javascript:alert(1)").kind, "rejected");
  assert.equal(normalizeTarget("Northline Freight").kind, "brand");
  assert.equal(normalizeTarget("8.8.8.8").kind, "ip");
  assert.equal(registrableDomain("a.b.co.uk"), "b.co.uk");
  assert.equal(isPublicIp("203.0.113.10"), true);
  assert.equal(isPublicIp("192.168.1.1"), false);
  assert.equal(isDemoQuery("northline freight"), true);
});

test("scores stay explainable and generic issues stay below critical", () => {
  const soft = explainScore({ exposure: 4, impact: 3, exploitability: 2, confidence: 0.95, criticality: 0.7 });
  assert.equal(soft.severity, "low");
  assert.ok(soft.formula.includes("→"));
  const extreme = explainScore({ exposure: 5, impact: 5, exploitability: 5, confidence: 1, criticality: 1 });
  assert.equal(extreme.score, 100);
  assert.equal(extreme.severity, "critical");
  const policy = policyFor("public", "domain");
  assert.ok(policy.some((d) => d.action === "Port scan" && d.decision === "deny"));
  assert.ok(policy.some((d) => d.action === "Exploit execution" && d.decision === "deny"));
});

test("northline demo never claims a confirmed takeover or a critical header gap", () => {
  const scan = compileScan(northlineObservations("2026-09-25T12:00:00.000Z", false), "scn_test");
  assert.equal(scan.demo, true);
  assert.ok(scan.findings.length > 0);
  assert.ok(scan.findings.every((f) => f.severity !== "critical"));
  const dangling = scan.findings.find((f) => f.ruleId.startsWith("dangling"));
  assert.ok(dangling);
  assert.match(dangling.title + dangling.rationale, /not a confirmed takeover/i);
  assert.equal(scan.breach.state, "demonstration-aggregate");
  assert.ok(scan.changes.some((c) => c.kind === "regressed"));
  assert.ok(scan.assets.some((a) => a.status === "suspected"));
  const second = compileScan(northlineObservations("2026-09-25T13:00:00.000Z", true), "scn_next");
  assert.equal(second.mode, "verified");
  const delta = deriveChanges(scan, {
    ...second,
    markers: { ...second.markers, hsts: true, assetLabels: [...second.markers.assetLabels, "new.northline.example"] },
  });
  assert.ok(delta.some((c) => c.title.includes("HSTS")));
  assert.ok(delta.some((c) => c.kind === "added"));
});
