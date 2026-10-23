import { NavLink, Outlet } from "react-router-dom";
import { Fingerprint, History, LayoutDashboard, ScanSearch, Settings, Shield, FileWarning, FileText } from "lucide-react";

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan", label: "New Scan", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: FileWarning },
  { to: "/history", label: "Scan History", icon: History },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/about", label: "About & Security", icon: Shield },
];

export function Layout() {
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
      <aside className="border-b border-white/10 bg-ink-900/80 p-5 lg:border-b-0 lg:border-r">
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-violet/20 text-accent-glow shadow-glow">
            <Fingerprint size={20} />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-wide">SecretLeak</p>
            <p className="text-xs text-slate-400">Forgotten credentials hunter</p>
          </div>
        </div>
        <nav className="grid grid-cols-2 gap-1 lg:grid-cols-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded-xl px-3 py-2 text-sm transition ${
                  isActive ? "bg-white/10 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <p className="mt-8 hidden text-xs leading-5 text-slate-500 lg:block">
          Local-first scanning. No telemetry. Pattern matches are not proof a credential is valid.
        </p>
      </aside>
      <main className="p-4 sm:p-8">
        <Outlet />
      </main>
    </div>
  );
}
