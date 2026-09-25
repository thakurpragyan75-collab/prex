import { useMemo, useState } from "react";
import type { ScanRecord, ScoreAxis } from "@/lib/prex/types";

export function OtherSite({ scan }: { scan: ScanRecord }) {
  const rows = scan.shadow ?? [];
  if (!scan.shadow) return <Stale />;
  if (rows.length === 0) {
    return <p className="text-sm text-mist">Nothing surrounding the front door was observed. The other site is empty on this pass.</p>;
  }
  return (
    <div>
      <p className="max-w-2xl text-sm leading-relaxed text-mist">
        The homepage is the door. These are names and hosts around it: certificate-log leftovers, aliases, script hosts, and mail. None of them were crawled.
      </p>
      <ul className="mt-4 divide-y divide-line border-y border-line">
        {rows.map((row) => (
          <li key={row.id} className="grid gap-1 py-4 md:grid-cols-2 md:gap-6">
            <div className="min-w-0">
              <p className="font-mono text-xs uppercase tracking-wide text-faint">{row.kind}</p>
              <p className="mt-1 break-words text-sm">{row.label}</p>
            </div>
            <p className="text-sm leading-relaxed text-mist">{row.detail}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TimeCut({ scan }: { scan: ScanRecord }) {
  const marks = scan.timeline ?? [];
  const [index, setIndex] = useState(Math.max(0, marks.length - 1));
  if (!scan.timeline) return <Stale />;
  if (marks.length === 0) {
    return <p className="text-sm text-mist">No dated certificate or registration marks were stored. The cut needs a not-before date.</p>;
  }
  const mark = marks[Math.min(index, marks.length - 1)] ?? marks[0];
  return (
    <div>
      <p className="max-w-2xl text-sm leading-relaxed text-mist">
        Drag through public dates. Each mark is a certificate log row or a registration date, not a claim that the name is still live.
      </p>
      <p className="mt-6 font-mono text-xs uppercase tracking-widest text-faint">{mark?.at}</p>
      <h2 className="mt-2 break-words font-display text-3xl">{mark?.label}</h2>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-mist">{mark?.detail}</p>
      <label className="mt-6 block text-sm text-faint" htmlFor="time-cut">
        Position in the public record
      </label>
      <input
        id="time-cut"
        type="range"
        min={0}
        max={marks.length - 1}
        value={Math.min(index, marks.length - 1)}
        onChange={(event) => setIndex(Number(event.target.value))}
        className="mt-2 h-11 w-full accent-paper"
      />
      <ol className="mt-4 divide-y divide-line border-y border-line">
        {marks.map((item, itemIndex) => (
          <li key={item.id}>
            <button
              type="button"
              onClick={() => setIndex(itemIndex)}
              className={`flex w-full flex-col items-start gap-1 py-3 text-left md:flex-row md:gap-6 ${itemIndex === index ? "text-ink" : "text-mist"}`}
            >
              <span className="font-mono text-xs">{item.at}</span>
              <span className="min-w-0 break-words text-sm">{item.label}</span>
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function Ask({ scan }: { scan: ScanRecord }) {
  const answers = scan.answers ?? [];
  const [query, setQuery] = useState("");
  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return answers;
    return answers.filter((item) => `${item.ask} ${item.answer}`.toLowerCase().includes(needle));
  }, [answers, query]);
  if (!scan.answers) return <Stale />;
  return (
    <div>
      <p className="max-w-2xl text-sm leading-relaxed text-mist">
        Questions are fixed. Answers are only sentences already supported by this map. If a question is not in the set, Prex will not invent one.
      </p>
      <label className="sr-only" htmlFor="ask">
        Filter questions
      </label>
      <input
        id="ask"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Mail, expiry, rating, operator"
        className="mt-4 h-11 w-full rounded-sm border border-line bg-inset px-3 text-sm text-ink outline-none placeholder:text-faint sm:max-w-md"
      />
      {shown.length === 0 ? (
        <p className="mt-6 text-sm text-mist">That question is not in the fixed set. Nothing was guessed.</p>
      ) : (
        <ul className="mt-4 divide-y divide-line border-y border-line">
          {shown.map((item) => (
            <li key={item.id} className="py-4">
              <h2 className="text-sm font-medium">{item.ask}</h2>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-mist">{item.answer}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function Score({ scan }: { scan: ScanRecord }) {
  const card = scan.scorecard;
  if (!card) return <Stale />;
  return (
    <div>
      <p className="font-mono text-xs uppercase tracking-widest text-faint">Public posture, not a user review</p>
      <p className="mt-2 font-display text-5xl">{card.overall.toFixed(1)}<span className="text-2xl text-faint"> / 10</span></p>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-mist">{card.basis}</p>
      <p className="mt-2 max-w-2xl text-sm leading-relaxed text-faint">{card.review}</p>
      <ul className="mt-6 divide-y divide-line border-y border-line">
        {card.axes.map((item) => (
          <Axis key={item.id} axis={item} />
        ))}
      </ul>
    </div>
  );
}

function Axis({ axis: item }: { axis: ScoreAxis }) {
  const width = item.score == null ? 0 : item.score * 10;
  const tone = item.tone === "good" ? "bg-ok" : item.tone === "bad" ? "bg-danger" : item.tone === "mixed" ? "bg-warn" : "bg-line";
  return (
    <li className="grid gap-2 py-4 md:grid-cols-2 md:gap-6">
      <div>
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="text-sm">{item.title}</h2>
          <span className="font-mono text-xs text-faint">{item.score == null ? "—" : item.score.toFixed(1)}</span>
        </div>
        <div className="mt-2 h-1.5 w-full bg-inset">
          <div className={`h-1.5 ${tone}`} style={{ width: `${width}%` }} />
        </div>
      </div>
      <p className="text-sm leading-relaxed text-mist">{item.note}</p>
    </li>
  );
}

function Stale() {
  return <p className="text-sm text-mist">This map was saved before these sections existed. Run it again from the start page.</p>;
}
