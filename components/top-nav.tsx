"use client";

import { Search, Bell, Settings } from "lucide-react";

export function TopNav() {
  return (
    <div className="h-16 bg-[rgba(11,17,32,0.8)] backdrop-blur-xl border-b border-[rgba(79,124,255,0.1)] px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Search Bar */}
      <div className="flex-1 max-w-sm">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#94a3b8]" />
          <input
            type="text"
            placeholder="Search processes, connections..."
            className="w-full bg-[rgba(5,8,22,0.6)] border border-[rgba(79,124,255,0.2)] rounded-xl pl-10 pr-4 py-2 text-sm text-[#f1f5f9] placeholder-[#94a3b8] focus:outline-none focus:border-[#4f7cff] focus:shadow-lg focus:shadow-[rgba(79,124,255,0.2)] transition-all duration-200 group-hover:border-[rgba(79,124,255,0.3)]"
          />
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center gap-4 ml-6">
        {/* Status Indicator */}
        <div className="glass-card px-4 py-2 border-[rgba(34,197,94,0.3)]">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-[#22c55e] rounded-full animate-pulse"></div>
            <span className="text-xs text-[#94a3b8]">Protected</span>
          </div>
        </div>

        {/* System Info */}
        <div className="text-right">
          <div className="text-xs text-[#f1f5f9] font-medium">DESKTOP-JDK</div>
          <div className="text-xs text-[#94a3b8]">Administrator</div>
        </div>

        {/* Notification */}
        <button className="relative p-2 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-all duration-200 group">
          <Bell className="w-5 h-5 text-[#94a3b8] group-hover:text-[#4f7cff]" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-[#f59e0b] rounded-full animate-pulse"></span>
        </button>

        {/* Settings */}
        <button className="p-2 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-all duration-200 group">
          <Settings className="w-5 h-5 text-[#94a3b8] group-hover:text-[#4f7cff]" />
        </button>
      </div>
    </div>
  );
}
