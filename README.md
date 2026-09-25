# Prex

Passive public-footprint mapper. Give it a domain, URL, IP, or brand. Prex builds an exposure graph from DNS, registration data, certificate names, and one homepage fetch, then adds four readings of the same evidence:

- **Other site** — names around the front door (certificate leftovers, aliases, script hosts, mail). They are not crawled.
- **Time** — dated certificate and registration rows you can step through.
- **Ask** — a fixed set of questions answered only from that map.
- **Score** — up to 20 public signals averaged out of 10. Missing signals stay blank. If almost nothing comes back, the number is from the name alone and is labeled unmeasured. An encyclopedia extract is not a customer review.

It does not scan ports, guess passwords, or invent an owner.

## Run it locally

Requires **Node.js 22**.

```bash
git clone https://github.com/thakurpragyan75-collab/prex.git
cd prex
npm install
npm run dev
```

Open [http://localhost:8080](http://localhost:8080).

Try `northline.example` for a fully local demonstration (no network lookups). Any other public domain runs a live passive map.

## What you can do

| Page | What it is |
| --- | --- |
| Map | Start a footprint from a domain, URL, IP, or brand |
| Other site, Time, Ask, Score | Open them on a finished map |
| Watch | Keep an eye on targets you have already mapped |
| Proof | Attach ownership proof before verified checks |
| Audit | Review what was collected and when |
| Trust | How scoring, sources, and limits work |

Scans are stored in the browser (`localStorage`). Nothing is written to a database. Sign-in is off (`.grok/app-env.json` sets `VITE_AUTH_ENABLED` to `false`).

Live maps are rate-limited: 8 per minute, and 8 seconds between repeats of the same host. DNS uses Cloudflare’s public resolver. The homepage request is pinned to the resolved public address.

## Scripts

```bash
npm run dev        # local server on port 8080
npm run build      # production build
npm run typecheck
npm test
```
