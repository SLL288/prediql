import { Link, Outlet, useLocation } from "react-router-dom";

function BrandMark() {
  // A source→sink glyph: nodes wired through a center.
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
      <circle cx="4" cy="11" r="2.4" className="fill-accent" />
      <line x1="6" y1="11" x2="16" y2="6.5" className="stroke-accent" strokeWidth="1.4" />
      <line x1="6" y1="11" x2="16" y2="15.5" className="stroke-accent" strokeWidth="1.4" />
      <circle cx="11" cy="11" r="1.5" className="fill-high" />
      <circle cx="18" cy="6" r="2.4" className="fill-none stroke-accent" strokeWidth="1.4" />
      <circle cx="18" cy="16" r="2.4" className="fill-crit" />
    </svg>
  );
}

export function App() {
  const loc = useLocation();
  const tab = (path: string, label: string) => {
    const active = path === "/" ? loc.pathname === "/" : loc.pathname.startsWith(path);
    return (
      <Link
        to={path}
        className={`focusable rounded-md px-3 py-1.5 text-sm transition-colors ${
          active ? "bg-elevated font-medium text-txt" : "text-dim hover:text-txt"
        }`}
      >
        {label}
      </Link>
    );
  };
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-hairline bg-ink/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-5 px-6">
          <Link to="/" className="focusable flex items-center gap-2.5">
            <BrandMark />
            <span className="font-bold tracking-tight">
              PrediQL<span className="text-faint"> Lab</span>
            </span>
          </Link>
          <nav className="flex items-center gap-1">
            {tab("/", "Experiments")}
            {tab("/live", "Live")}
            {tab("/coverage", "Coverage")}
            {tab("/compare", "Compare")}
            {tab("/security", "Security")}
            {tab("/baselines", "Baselines")}
            {tab("/fuzz4all", "Fuzz4All")}
            {tab("/reliability", "Reliability")}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
