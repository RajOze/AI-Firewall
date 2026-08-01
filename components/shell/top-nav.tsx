'use client';

import { useState, useEffect } from 'react';
import {
  Search,
  Bell,
  Moon,
  Sun,
  User,
  LogOut,
  Settings,
  Monitor,
} from 'lucide-react';

export function TopNavShell() {
  const [theme, setTheme] = useState('dark');
  const [dropdownOpen, setDropdownOpen] = useState(false);

  // Mock system info
  const systemInfo = {
    hostname: 'DESKTOP-FIREWALL-01',
    windowsVersion: 'Windows 11 Pro',
    user: 'Administrator',
    notifications: 3,
  };

  return (
    <div className="fixed top-0 left-0 right-0 h-20 bg-[rgba(11,17,32,0.8)] border-b border-[rgba(79,124,255,0.08)] backdrop-blur-xl flex items-center px-6 gap-4 z-40">
      {/* Left Section - System Info */}
      <div className="flex items-center gap-8">
        <div className="hidden sm:flex items-center gap-2">
          <Monitor className="w-4 h-4 text-[#4F7CFF]" />
          <span className="text-xs font-mono text-[#F1F5F9]">{systemInfo.hostname}</span>
        </div>
        <div className="hidden md:flex items-center gap-2 text-xs text-[#94A3B8]">
          <span>{systemInfo.windowsVersion}</span>
          <span className="text-[#4F7CFF]">•</span>
          <span>{systemInfo.user}</span>
        </div>
      </div>

      {/* Center - Search */}
      <div className="flex-1 max-w-2xl">
        <div className="relative group">
          <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#94A3B8]" />
          <input
            type="text"
            placeholder="Search processes, connections, threats..."
            className="w-full bg-[rgba(5,8,22,0.6)] border border-[rgba(79,124,255,0.15)] rounded-xl pl-12 pr-4 py-2.5 text-sm text-[#F1F5F9] placeholder-[#94A3B8] focus:outline-none focus:border-[#4F7CFF] focus:shadow-lg focus:shadow-[rgba(79,124,255,0.2)] transition-all duration-200"
          />
        </div>
      </div>

      {/* Right Section - Actions */}
      <div className="flex items-center gap-2">
        {/* Notifications */}
        <button className="relative p-2.5 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-all duration-200 group">
          <Bell className="w-5 h-5 text-[#94A3B8] group-hover:text-[#4F7CFF]" />
          {systemInfo.notifications > 0 && (
            <span className="absolute top-1 right-1 w-5 h-5 bg-gradient-to-r from-[#EF4444] to-[#F59E0B] rounded-full text-white text-xs font-bold flex items-center justify-center">
              {systemInfo.notifications}
            </span>
          )}
        </button>

        {/* Theme Toggle */}
        <button
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className="p-2.5 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-all duration-200 group"
        >
          {theme === 'dark' ? (
            <Moon className="w-5 h-5 text-[#94A3B8] group-hover:text-[#4F7CFF]" />
          ) : (
            <Sun className="w-5 h-5 text-[#94A3B8] group-hover:text-[#4F7CFF]" />
          )}
        </button>

        {/* User Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2 px-3 py-2 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-all duration-200 ml-2"
          >
            <div className="w-8 h-8 bg-gradient-to-br from-[#4F7CFF] to-[#7C3AED] rounded-lg flex items-center justify-center">
              <User className="w-4 h-4 text-white" />
            </div>
            <span className="text-xs font-semibold text-[#F1F5F9] hidden sm:block">
              {systemInfo.user}
            </span>
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-48 glass-card rounded-xl shadow-xl border border-[rgba(79,124,255,0.15)] overflow-hidden">
              <div className="p-3 border-b border-[rgba(79,124,255,0.08)]">
                <div className="text-xs text-[#94A3B8]">Logged in as</div>
                <div className="text-sm font-semibold text-[#F1F5F9]">{systemInfo.user}</div>
              </div>
              <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-[#F1F5F9] hover:bg-[rgba(79,124,255,0.1)] transition-colors">
                <Settings className="w-4 h-4" />
                Profile Settings
              </button>
              <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-[#94A3B8] hover:text-[#EF4444] hover:bg-[rgba(239,68,68,0.1)] transition-colors">
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
