from pathlib import Path

# 1. Update App.tsx to ensure root `/` routes directly to `/dashboard`
app_tsx = '''import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import FirewallPage from './pages/FirewallPage';
import { Shield, LayoutDashboard, Sliders, Bell, Laptop, Bot } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Firewall', path: '/firewall', icon: Sliders },
  ];

  return (
    <div className="flex min-h-screen bg-[#0d1117] text-slate-100 font-sans antialiased">
      {/* Left Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-[#161b22] flex flex-col justify-between p-4 shrink-0">
        <div>
          {/* Logo & Brand */}
          <div className="flex items-center gap-3 px-3 py-4 mb-6">
            <div className="p-2 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-base tracking-wide text-white">Sentinel AI</h1>
              <p className="text-[10px] text-slate-400 font-mono">Autonomous Firewall</p>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="space-y-1">
            <span className="px-3 text-[10px] font-mono uppercase text-slate-500 font-semibold tracking-wider">
              System
            </span>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold font-mono transition-colors ${
                    active
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.name}
                </Link>
              );
            })}
          </div>
        </div>

        {/* Footer Status */}
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl text-xs font-mono text-slate-400">
          <div className="flex items-center justify-between text-[11px]">
            <span>ENGINE</span>
            <span className="text-emerald-400 font-bold">ACTIVE</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1 truncate">SENTINEL-X1-MAIN</p>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-x-hidden">
        {children}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
'''

Path("frontend/src/App.tsx").write_text(app_tsx, encoding="utf-8")
print("Successfully patched App.tsx with default router redirect")
