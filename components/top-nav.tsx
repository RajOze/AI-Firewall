"use client";

import { Search, Bell, Settings } from "lucide-react";

export function TopNav() {
  return (
    <div className="h-16 bg-card border-b border-border px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Search Bar */}
      <div className="flex-1 max-w-sm">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-text-secondary" />
          <input
            type="text"
            placeholder="Search processes, connections..."
            className="w-full bg-card-dark border border-border rounded-lg pl-10 pr-4 py-2 text-sm text-foreground placeholder-text-secondary focus:outline-none focus:border-primary"
          />
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center gap-4 ml-6">
        {/* Status Indicator */}
        <div className="flex items-center gap-2 px-4 py-2 bg-card-dark rounded-lg border border-border">
          <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
          <span className="text-xs text-text-secondary">Protected</span>
        </div>

        {/* System Info */}
        <div className="text-right">
          <div className="text-xs text-foreground font-medium">DESKTOP-JDK</div>
          <div className="text-xs text-text-secondary">Administrator</div>
        </div>

        {/* Notification */}
        <button className="relative p-2 hover:bg-border rounded-lg transition-colors">
          <Bell className="w-5 h-5 text-text-secondary hover:text-foreground" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-warning rounded-full"></span>
        </button>

        {/* Settings */}
        <button className="p-2 hover:bg-border rounded-lg transition-colors">
          <Settings className="w-5 h-5 text-text-secondary hover:text-foreground" />
        </button>
      </div>
    </div>
  );
}
