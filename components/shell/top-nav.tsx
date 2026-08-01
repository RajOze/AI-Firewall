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
    <div 
      className="fixed top-0 left-0 right-0 h-20 flex items-center px-6 gap-6 z-40"
      style={{
        background: 'linear-gradient(135deg, rgba(3, 7, 18, 0.7) 0%, rgba(10, 14, 26, 0.5) 100%)',
        borderBottom: '1px solid rgba(148, 163, 184, 0.08)',
        backdropFilter: 'blur(30px)',
        WebkitBackdropFilter: 'blur(30px)',
      }}
    >
      {/* Left Section - System Info */}
      <div className="flex items-center gap-8">
        <div className="hidden sm:flex items-center gap-2 group">
          <Monitor className="w-4 h-4 text-[#3d61ff] group-hover:text-[#00d9ff] transition-colors" />
          <span className="text-xs font-mono text-[#f8fafc] font-medium">{systemInfo.hostname}</span>
        </div>
        <div className="hidden md:flex items-center gap-2 text-xs text-[#94a3b8] font-medium">
          <span>{systemInfo.windowsVersion}</span>
          <span className="text-[#3d61ff] opacity-50">•</span>
          <span>{systemInfo.user}</span>
        </div>
      </div>

      {/* Center - Premium Search */}
      <div className="flex-1 max-w-2xl">
        <div className="relative group">
          <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#94a3b8] group-focus-within:text-[#3d61ff] transition-colors" />
          <input
            type="text"
            placeholder="Search processes, connections, threats..."
            className="input-field pl-12 pr-4 py-3"
            style={{
              background: 'linear-gradient(135deg, rgba(10, 14, 26, 0.4) 0%, rgba(20, 24, 41, 0.2) 100%)',
              fontSize: '0.875rem',
            }}
          />
        </div>
      </div>

      {/* Right Section - Premium Actions */}
      <div className="flex items-center gap-1">
        {/* Notifications */}
        <button 
          className="nav-item p-3 relative group transition-all duration-300"
          style={{
            color: '#94a3b8',
          }}
        >
          <Bell className="w-5 h-5 group-hover:text-[#3d61ff] transition-colors" />
          {systemInfo.notifications > 0 && (
            <span 
              className="absolute top-2 right-2 w-5 h-5 text-white text-xs font-bold flex items-center justify-center rounded-full pulse-glow"
              style={{
                background: 'linear-gradient(135deg, #ef4444, #f97316)',
                boxShadow: '0 0 12px rgba(239, 68, 68, 0.5)',
              }}
            >
              {systemInfo.notifications}
            </span>
          )}
        </button>

        {/* Theme Toggle */}
        <button
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className="nav-item p-3 group transition-all duration-300"
        >
          {theme === 'dark' ? (
            <Moon className="w-5 h-5 group-hover:text-[#3d61ff] transition-colors" />
          ) : (
            <Sun className="w-5 h-5 group-hover:text-[#3d61ff] transition-colors" />
          )}
        </button>

        {/* User Dropdown */}
        <div className="relative ml-2">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2.5 px-4 py-2.5 group transition-all duration-300"
            style={{
              background: 'rgba(61, 97, 255, 0.08)',
              border: '1px solid rgba(61, 97, 255, 0.15)',
              borderRadius: '12px',
            }}
          >
            <div 
              className="w-8 h-8 rounded-[10px] flex items-center justify-center flex-shrink-0 relative overflow-hidden group-hover:shadow-glow transition-all duration-300"
              style={{
                background: 'linear-gradient(135deg, #3d61ff 0%, #7c3aed 100%)',
              }}
            >
              <User className="w-4 h-4 text-white" />
            </div>
            <span className="text-xs font-bold text-[#f8fafc] hidden sm:block">
              {systemInfo.user}
            </span>
          </button>

          {dropdownOpen && (
            <div 
              className="absolute right-0 mt-3 w-56 rounded-[14px] shadow-lg overflow-hidden border border-l border-b border-r border-t animate-fade-in"
              style={{
                background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(20, 24, 41, 0.6) 100%)',
                borderColor: 'rgba(148, 163, 184, 0.12)',
                backdropFilter: 'blur(24px)',
                WebkitBackdropFilter: 'blur(24px)',
                boxShadow: '0 16px 48px rgba(0, 0, 0, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.1)',
              }}
            >
              <div 
                className="p-4 border-b"
                style={{ borderBottomColor: 'rgba(148, 163, 184, 0.08)' }}
              >
                <div className="text-xs text-[#94a3b8] font-medium">LOGGED IN AS</div>
                <div className="text-sm font-bold text-[#f8fafc] mt-1">{systemInfo.user}</div>
              </div>
              <button className="w-full flex items-center gap-3 px-4 py-3 text-sm text-[#f8fafc] hover:bg-[rgba(61,97,255,0.1)] transition-colors font-medium group">
                <Settings className="w-4 h-4 group-hover:text-[#3d61ff] transition-colors" />
                Profile Settings
              </button>
              <button className="w-full flex items-center gap-3 px-4 py-3 text-sm text-[#94a3b8] hover:text-[#ef4444] hover:bg-[rgba(239,68,68,0.1)] transition-colors font-medium group">
                <LogOut className="w-4 h-4 group-hover:scale-110 transition-transform" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
