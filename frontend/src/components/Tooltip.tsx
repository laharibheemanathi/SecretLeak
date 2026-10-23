export function Tooltip({ text, children }: { text: string; children: React.ReactNode }) {
  return (
    <span className="group relative inline-flex">
      {children}
      <span className="pointer-events-none absolute left-1/2 top-full z-20 mt-2 hidden w-64 -translate-x-1/2 rounded-lg border border-white/10 bg-ink-950 px-3 py-2 text-xs text-slate-300 shadow-card group-hover:block group-focus-within:block">
        {text}
      </span>
    </span>
  );
}
