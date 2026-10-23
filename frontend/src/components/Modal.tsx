export function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true">
      <div className="card w-full max-w-md p-6">
        <h2 className="text-lg font-semibold">{title}</h2>
        <div className="mt-3 text-sm text-slate-300">{children}</div>
        <button className="btn-ghost mt-4" onClick={onClose} type="button">
          Close
        </button>
      </div>
    </div>
  );
}
