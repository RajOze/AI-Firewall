'use client';

import { useState } from 'react';
import {
  LayoutDashboard,
  Wifi,
  AlertTriangle,
  Shield,
  Zap,
  BarChart3,
  Cog,
  FileText,
  Activity,
  ChevronDown,
  GripVertical,
  Brain,
  Sparkles,
} from 'lucide-react';

const menuItems = [
  { icon: LayoutDashboard, label: 'Dashboard', id: 'dashboard' },
  { icon: Wifi, label: 'Live Connections', id: 'connections' },
  { icon: AlertTriangle, label: 'Threat Intelligence', id: 'threats' },
  { icon: Shield, label: 'Firewall Rules', id: 'rules' },
  { icon: Zap, label: 'AI Decisions', id: 'decisions' },
  { icon: BarChart3, label: 'Traffic Analytics', id: 'analytics' },
  { icon: Activity, label: 'Processes', id: 'processes' },
  { icon: FileText, label: 'Reports', id: 'reports' },
  { icon: Cog, label: 'Settings', id: 'settings' },
];

export function SidebarShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [activeItem, setActiveItem] = useState('dashboard');

  return (
    <div
      className={`relative h-screen bg-[#0B1120] border-r border-[rgba(79,124,255,0.08)] transition-all duration-300 flex flex-col ${
        collapsed ? 'w-20' : 'w-72'
      } backdrop-blur-xl`}
    >
      {/* Logo Section */}
      <div className="h-20 border-b border-[rgba(79,124,255,0.08)] flex items-center justify-between px-4">
        {!collapsed && (
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-[#4F7CFF] to-[#7C3AED] rounded-2xl flex items-center justify-center shadow-lg">
              <Brain className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="font-bold text-sm text-[#F1F5F9]">SentinelAI</div>
              <div className="text-xs text-[#94A3B8]">Firewall</div>
            </div>
          </div>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-2 hover:bg-[rgba(79,124,255,0.1)] rounded-xl transition-colors"
        >
          <GripVertical className="w-4 h-4 text-[#94A3B8]" />
        </button>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-1">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveItem(item.id)}
            className={`w-full flex items-center gap-3 px-4 py-3.5 rounded-xl transition-all duration-200 group ${
              activeItem === item.id
                ? 'bg-gradient-to-r from-[#4F7CFF] to-[#7C3AED] text-white shadow-lg shadow-[rgba(79,124,255,0.3)]'
                : 'text-[#94A3B8] hover:bg-[rgba(79,124,255,0.06)] hover:text-[#F1F5F9]'
            }`}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {!collapsed && (
              <span className="text-sm font-medium group-hover:translate-x-0.5 transition-transform">
                {item.label}
              </span>
            )}
          </button>
        ))}
      </nav>

      {/* AI Assistant Card */}
      <div className="p-3 border-t border-[rgba(79,124,255,0.08)]">
        <div className="glass-card p-4 relative overflow-hidden">
          {/* Animated glow orb */}
          <div className="absolute -top-8 -right-8 w-24 h-24 bg-gradient-to-br from-[#00E5FF] to-[#4F7CFF] rounded-full opacity-20 blur-3xl animate-pulse" />

          {collapsed ? (
            <button className="w-full flex items-center justify-center p-2 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#4F7CFF] text-white hover:shadow-lg transition-all">
              <Sparkles className="w-4 h-4" />
            </button>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-2 h-2 bg-[#00E5FF] rounded-full animate-pulse" />
                <span className="text-xs font-semibold text-[#F1F5F9]">AI Assistant</span>
              </div>
              <div className="text-xs text-[#94A3B8] mb-3">
                <div className="mb-1 flex items-center gap-1">
                  <span>Status:</span>
                  <span className="text-[#22C55E] font-semibold">Protected</span>
                </div>
              </div>
              <button className="w-full bg-gradient-to-r from-[#4F7CFF] to-[#00E5FF] text-white text-xs font-semibold py-2.5 rounded-xl hover:shadow-lg hover:shadow-[rgba(79,124,255,0.4)] transition-all">
                Quick Scan
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
