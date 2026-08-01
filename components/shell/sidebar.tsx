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
      className={`relative h-screen flex flex-col transition-all duration-400 ease-out ${
        collapsed ? 'w-20' : 'w-72'
      }`}
      style={{
        background: 'linear-gradient(135deg, rgba(3, 7, 18, 0.8) 0%, rgba(10, 14, 26, 0.6) 100%)',
        borderRight: '1px solid rgba(148, 163, 184, 0.08)',
        backdropFilter: 'blur(30px)',
        WebkitBackdropFilter: 'blur(30px)',
      }}
    >
      {/* Logo Section - Premium */}
      <div 
        className="h-24 flex items-center justify-between px-4 border-b"
        style={{
          borderBottomColor: 'rgba(148, 163, 184, 0.08)',
        }}
      >
        {!collapsed && (
          <div className="flex items-center gap-3 group">
            <div 
              className="w-11 h-11 rounded-[14px] flex items-center justify-center flex-shrink-0 relative overflow-hidden shadow-lg group-hover:shadow-glow transition-all duration-300"
              style={{
                background: 'linear-gradient(135deg, #3d61ff 0%, #7c3aed 100%)',
              }}
            >
              <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent" />
              <Brain className="w-6 h-6 text-white relative z-10" />
            </div>
            <div>
              <div className="text-sm font-bold text-[#f8fafc] tracking-tight">SentinelAI</div>
              <div className="text-xs text-[#94a3b8]">Enterprise</div>
            </div>
          </div>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="nav-item p-2.5 relative group"
        >
          <GripVertical className="w-4 h-4 text-[#94a3b8] group-hover:text-[#3d61ff] transition-colors" />
        </button>
      </div>

      {/* Navigation Menu - Premium */}
      <nav className="flex-1 overflow-y-auto px-3 pt-6 pb-3 space-y-1.5">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveItem(item.id)}
            className={`nav-item w-full flex items-center gap-3 px-4 py-3 relative group transition-all duration-300 overflow-hidden ${
              activeItem === item.id
                ? 'active'
                : ''
            }`}
            style={activeItem === item.id ? {
              background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.2) 0%, rgba(124, 58, 237, 0.1) 100%)',
              boxShadow: 'inset 0 1px 3px rgba(61, 97, 255, 0.2), 0 0 20px rgba(61, 97, 255, 0.15)',
            } : {}}
          >
            <div className="relative flex-shrink-0">
              <item.icon className="w-5 h-5 relative z-10 transition-all duration-300" />
              {activeItem === item.id && (
                <div 
                  className="absolute inset-0 rounded-lg blur-lg animate-pulse"
                  style={{
                    background: 'linear-gradient(135deg, #3d61ff, #00d9ff)',
                    opacity: 0.3,
                  }}
                />
              )}
            </div>
            {!collapsed && (
              <span className="text-sm font-medium transition-all duration-300 group-hover:translate-x-0.5">
                {item.label}
              </span>
            )}
          </button>
        ))}
      </nav>

      {/* AI Assistant Card - Premium */}
      <div className="px-3 pb-4 border-t" style={{ borderTopColor: 'rgba(148, 163, 184, 0.08)' }}>
        <div 
          className="card-compact relative group mt-4 overflow-hidden"
          style={{
            background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.15) 0%, rgba(0, 217, 255, 0.08) 100%)',
            border: '1px solid rgba(61, 97, 255, 0.25)',
          }}
        >
          {/* Animated glow orb */}
          <div 
            className="absolute -top-12 -right-12 w-32 h-32 rounded-full blur-3xl animate-pulse opacity-40"
            style={{
              background: 'linear-gradient(135deg, #00d9ff 0%, #3d61ff 100%)',
            }}
          />

          {collapsed ? (
            <button 
              className="w-full flex items-center justify-center p-3 rounded-[12px] group-hover:shadow-glow transition-all duration-300 relative"
              style={{
                background: 'linear-gradient(135deg, #3d61ff 0%, #00d9ff 100%)',
                boxShadow: '0 8px 24px rgba(61, 97, 255, 0.3)',
              }}
            >
              <Sparkles className="w-4 h-4 text-white group-hover:scale-110 transition-transform" />
            </button>
          ) : (
            <>
              <div className="flex items-center gap-2.5 mb-3 relative z-10">
                <div className="w-2 h-2 bg-[#00d9ff] rounded-full animate-pulse" />
                <span className="text-xs font-bold text-[#f8fafc] tracking-tight">AI ASSISTANT</span>
              </div>
              <div className="text-xs text-[#94a3b8] mb-4 relative z-10">
                <div className="mb-2 flex items-center justify-between">
                  <span>Status:</span>
                  <span className="text-[#10b981] font-bold">Protected</span>
                </div>
              </div>
              <button 
                className="w-full text-white text-xs font-bold py-3 rounded-[12px] transition-all duration-300 group-hover:shadow-glow relative z-10"
                style={{
                  background: 'linear-gradient(135deg, #3d61ff 0%, #7c3aed 100%)',
                  boxShadow: '0 8px 24px rgba(61, 97, 255, 0.3)',
                }}
              >
                Quick Scan
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
