import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Button, Panel, TextField } from "@/components/prex/primitives";
import { Shell } from "@/components/prex/shell";
import { checkControl } from "@/lib/prex/api";
import { newId } from "@/lib/prex/engine";
import { formatWhen, saveVerification, useHydrated, usePrex } from "@/lib/prex/store";
import type { ProofMethod } from "@/lib/prex/types";

export const Route = createFileRoute("/authorization")({ component: AuthorizationPage });

const DEMO_TOKEN = "northline-demo-proof";

function AuthorizationPage() {
  const hydrated = useHydrated();
  const state = usePrex();
  const [host, setHost] = useState("northline.example");
  const [method, setMethod] = useState<ProofMethod>("dns");
  const [token, setToken] = useState("");
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState(false);

  async function check(nextHost: string, nextMethod: ProofMethod, nextToken: string) {
    setPending(true);
    setMessage("");
    try {
      const result = await checkControl({ data: { host: nextHost, method: nextMethod, token: nextToken } });
      if (result.ok) {
        saveVerification({
          host: result.host,
          method: result.method,
          token: nextToken,
          checkedAt: new Date().toISOString(),
          ok: true,
          detail: result.detail,
        });
        setMessage(result.detail);
      } else {
        saveVerification({
          host: nextHost.trim().toLowerCase(),
          method: nextMethod,
          token: nextToken,
          checkedAt: new Date().toISOString(),
          ok: false,
          detail: result.error,
        });
        setMessage(result.error);
      }
    } catch {
      setMessage("The proof check did not finish.");
    } finally {
      setPending(false);
    }
  }

  return (
    <Shell>
      <p className="font-mono text-xs uppercase tracking-widest text-faint">Proof of control</p>
      <h1 className="mt-2 max-w-xl font-display text-4xl leading-tight">Active checks stay locked until the host answers.</h1>
      <p className="mt-4 max-w-2xl text-sm leading-relaxed text-mist">
        Public mode never needs this page. To label a map verified, publish a token you generate here, then ask Prex
        to read it back. The next map of that host rechecks the proof. Exploit modules are not unlocked, because they
        are not in the product.
      </p>

      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        <Panel>
          <label className="text-sm" htmlFor="proof-host">
            Host you control
          </label>
          <TextField id="proof-host" className="mt-2" value={host} onChange={(event) => setHost(event.target.value)} />
          <fieldset className="mt-4">
            <legend className="text-sm">Method</legend>
            <div className="mt-2 grid gap-2">
              {(
                [
                  ["dns", "DNS TXT"],
                  ["well-known", "Well-known file"],
                  ["meta", "Homepage meta tag"],
                ] as const
              ).map(([id, label]) => (
                <label key={id} className="flex min-h-11 items-center gap-3 text-sm">
                  <input type="radio" name="method" checked={method === id} onChange={() => setMethod(id)} />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>
          <Button
            tone="line"
            className="mt-4"
            onClick={() => setToken(newId("prex").replace("prex_", ""))}
          >
            {token ? "Generate another token" : "Generate token"}
          </Button>
          {token ? (
            <div className="mt-4 text-sm leading-relaxed text-mist">
              <p className="break-all font-mono text-xs text-ink">{token}</p>
              {method === "dns" ? (
                <p className="mt-3">
                  Publish a TXT record at <span className="text-ink">_prex-verify.{host || "your.host"}</span> with
                  value <span className="text-ink">prex-verify={token}</span>.
                </p>
              ) : null}
              {method === "well-known" ? (
                <p className="mt-3">
                  Place a file at <span className="text-ink">/.well-known/prex-verification</span> whose body is only
                  the token.
                </p>
              ) : null}
              {method === "meta" ? (
                <p className="mt-3">
                  Add <span className="text-ink">{`<meta name="prex-verification" content="${token}">`}</span> to the
                  homepage. Prex reads the tag and discards the page.
                </p>
              ) : null}
              <Button className="mt-4" disabled={pending || !token} onClick={() => void check(host, method, token)}>
                {pending ? "Checking" : "Check proof"}
              </Button>
            </div>
          ) : null}
          {message ? <p className="mt-4 text-sm text-mist">{message}</p> : null}
        </Panel>
        <Panel>
          <h2 className="font-display text-2xl">Demonstration proof</h2>
          <p className="mt-3 text-sm leading-relaxed text-mist">
            Northline is not a live domain. This button records a local proof the server accepts only for
            northline.example. It does not write DNS and it does not verify any other host.
          </p>
          <Button
            className="mt-4"
            tone="line"
            disabled={pending}
            onClick={() => void check("northline.example", "demonstration", DEMO_TOKEN)}
          >
            Record Northline demonstration proof
          </Button>
          <h3 className="mt-8 text-sm font-medium">Proofs in this browser</h3>
          {!hydrated || state.verifications.length === 0 ? (
            <p className="mt-2 text-sm text-faint">None yet.</p>
          ) : (
            <ul className="mt-3 divide-y divide-line">
              {state.verifications.map((item) => (
                <li key={item.host + item.checkedAt} className="py-3 text-sm">
                  <span className="text-ink">{item.host}</span>
                  <span className="text-faint">
                    {" "}
                    · {item.method} · {item.ok ? "accepted" : "failed"} · {formatWhen(item.checkedAt)}
                  </span>
                  <span className="mt-1 block text-mist">{item.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </Shell>
  );
}
