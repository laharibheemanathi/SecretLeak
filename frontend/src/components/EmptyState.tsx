export function EmptyState({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="card flex flex-col items-start gap-3 p-8">
      <h2 className="text-xl font-semibold">{title}</h2>
      <p className="max-w-xl text-sm leading-6 text-slate-400">{body}</p>
      {action}
    </div>
  );
}
