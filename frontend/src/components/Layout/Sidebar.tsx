import { Link, useLocation } from "react-router-dom";

const LOGO_URL = "https://lh3.googleusercontent.com/aida-public/AB6AXuB93YHTxcKojn5JfsMz6oUwC01XC1m_2qClCdskiuQof_DIapwxXsjlbted6XmRnLmdznHo2vhdRANP6dzRwernHz8-peO6aSHdwf2A44PR5ZBNVV9qh0YJFBZwRPMhvBRJUdcR7JUk6mGCkwZB_HXxAElPv3hPefiH8YQX5g0hSU5CrmCq8WEyziBxWKBburwmpJrw-mpB2R8SK6ll34060JtObvyJio7iXuRYw9yAaueKcS6Nm-Ca9g";

export default function Sidebar() {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === "/" || path === "/dashboard") {
      return location.pathname === "/" || location.pathname === "/dashboard";
    }
    return location.pathname.startsWith(path);
  };

  const navLinkClass = (path: string) =>
    `flex items-center px-md py-sm transition-all ${
      isActive(path)
        ? "bg-primary-container text-on-primary-container font-bold"
        : "text-body-sm text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface"
    }`;

  return (
    <aside className="fixed left-0 top-0 h-full w-60 bg-surface-container-low border-r border-outline-variant z-50 flex flex-col">
      {/* Brand Header */}
      <div className="p-lg flex items-center gap-sm border-b border-outline-variant bg-surface-container-lowest">
        <img
          src={LOGO_URL}
          alt="Sentinel AI Firewall Logo"
          className="h-8 w-auto object-contain"
          onError={(e) => {
            // Fallback shield icon if image URL is unreachable
            (e.target as HTMLElement).style.display = 'none';
          }}
        />
        <span className="font-headline-sm text-on-surface tracking-tight truncate flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-[24px]">shield</span>
          Sentinel AI
        </span>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 py-md overflow-y-auto">
        <div className="px-md pb-xs mb-xs font-label-caps text-outline uppercase">
          System
        </div>
        <Link to="/dashboard" className={navLinkClass("/dashboard")}>
          <span className="material-symbols-outlined mr-md text-[20px]">dashboard</span>
          Dashboard
        </Link>
        <Link to="/firewall" className={navLinkClass("/firewall")}>
          <span className="material-symbols-outlined mr-md text-[20px]">security</span>
          Firewall
        </Link>
        <Link to="/alerts" className={navLinkClass("/alerts")}>
          <span className="material-symbols-outlined mr-md text-[20px]">warning</span>
          Alerts
        </Link>

        <div className="px-md pb-xs mt-md mb-xs font-label-caps text-outline uppercase">
          Network
        </div>
        <Link to="/devices" className={navLinkClass("/devices")}>
          <span className="material-symbols-outlined mr-md text-[20px]">devices</span>
          Devices
        </Link>

        <div className="px-md pb-xs mt-md mb-xs font-label-caps text-outline uppercase">
          Analysis
        </div>
        <div className="mt-auto border-t border-outline-variant pt-sm">
          <Link
            to="/ai-assistant"
            className={`flex items-center px-md py-sm text-body-sm transition-all ${
              isActive("/ai-assistant")
                ? "bg-primary-container text-on-primary-container font-bold"
                : "text-secondary hover:bg-secondary-container/10"
            }`}
          >
            <span className="material-symbols-outlined mr-md text-[20px]">smart_toy</span>
            AI Assistant
          </Link>
        </div>
      </nav>
    </aside>
  );
}