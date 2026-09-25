import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import type { Severity } from "@/lib/prex/types";

const tones = {
  solid: "bg-paper text-canvas hover:opacity-90",
  line: "border border-line text-ink hover:border-line-strong",
  ghost: "text-ink hover:bg-panel",
} as const;

export function Button({
  tone = "solid",
  className = "",
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: keyof typeof tones }) {
  return (
    <button
      type={type}
      className={`press inline-flex h-11 items-center justify-center gap-2 rounded-sm px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${tones[tone]} ${className}`}
      {...props}
    />
  );
}

export function TextField(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`h-11 w-full rounded-sm border border-line bg-inset px-3 text-base text-ink outline-none placeholder:text-faint focus-visible:border-line-strong ${props.className ?? ""}`}
    />
  );
}

const bandClass: Record<Severity, string> = {
  critical: "text-danger",
  high: "text-warn",
  medium: "text-ink",
  low: "text-info",
  informational: "text-mist",
};

export function Band({ severity, score }: { severity: Severity; score?: number }) {
  return (
    <span className={`font-mono text-xs uppercase tracking-wide ${bandClass[severity]}`}>
      {score != null ? <span className="tabular-nums">{score} </span> : null}
      {severity}
    </span>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`rounded-lg border border-line bg-panel p-4 md:p-5 ${className}`}>{children}</section>;
}
