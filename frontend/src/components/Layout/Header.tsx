import { useState, useEffect } from "react";
import { fetchHealth } from "../../services/api";

export default function Header() {
  const [isHealthy, setIsHealthy] = useState<boolean>(true);

  useEffect(() => {
    fetchHealth()
      .then(() => setIsHealthy(true))
      .catch(() => setIsHealthy(false));
  }, []);

  return (
    <header className="fixed top-0 left-60 right-0 h-14 bg-surface/90 backdrop-blur-md border-b border-outline-variant z-40 flex items-center justify-between px-lg shadow-[0_1px_8px_rgba(0,0,0,0.1)]">
      {/* Search & Protection Status */}
      <div className="flex items-center gap-md flex-1">
        <div className="relative max-w-md w-full flex items-center">
          <span className="material-symbols-outlined absolute left-3 text-[20px] text-outline">
            search
          </span>
          <input
            type="text"
            placeholder="Search network, IPs, processes..."
            className="w-full bg-surface-container-low border border-outline-variant rounded px-10 py-1 text-body-sm text-on-surface focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        <div className={`flex items-center gap-xs px-sm py-[2px] border rounded-full ${
          isHealthy
            ? "bg-secondary-container/10 border-secondary/20 text-secondary"
            : "bg-error-container/20 border-error/30 text-error"
        }`}>
          <div className={`w-2 h-2 rounded-full ${isHealthy ? "bg-secondary animate-pulse" : "bg-error"}`} />
          <span className="font-label-caps">
            {isHealthy ? "PROTECTION ACTIVE" : "BACKEND OFFLINE"}
          </span>
        </div>
      </div>

      {/* Right User & Device Context */}
      <div className="flex items-center gap-lg">
        <div className="flex flex-col items-end">
          <span className="font-label-caps text-outline">CURRENT DEVICE</span>
          <span className="font-headline-sm text-[13px] text-on-surface">
            SENTINEL-X1-MAIN
          </span>
        </div>

        <div className="flex items-center gap-md border-l border-outline-variant pl-lg">
          <button className="text-on-surface-variant hover:text-primary transition-colors flex items-center p-1 rounded-full hover:bg-surface-container-high">
            <span className="material-symbols-outlined text-[22px]">notifications</span>
          </button>

          <div className="flex items-center gap-sm group cursor-pointer">
            <div className="w-8 h-8 rounded-full bg-primary flex items-center justify-center">
              <span className="material-symbols-outlined text-on-primary text-[18px]">
                admin_panel_settings
              </span>
            </div>
            <span className="material-symbols-outlined text-on-surface-variant group-hover:text-on-surface">
              expand_more
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}