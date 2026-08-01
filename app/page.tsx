export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-[#050816] via-[#0B1120] to-[#050816] p-6">
      {/* Welcome Section */}
      <div className="mb-8 animate-fade-in">
        <h1 className="text-4xl font-bold text-[#F1F5F9] mb-2">Welcome to SentinelAI</h1>
        <p className="text-[#94A3B8]">Real-time enterprise cybersecurity monitoring and AI-powered threat detection</p>
      </div>

      {/* Dashboard Grid - Shell Showcase */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Status Cards */}
        <div className="glass-card p-6 rounded-2xl hover:shadow-lg transition-all duration-300 hover:border-[rgba(79,124,255,0.3)]">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-[#94A3B8] text-xs font-semibold uppercase tracking-wider mb-1">
                Protection Status
              </p>
              <p className="text-3xl font-bold text-[#22C55E]">Protected</p>
            </div>
            <div className="w-12 h-12 bg-gradient-to-br from-[#22C55E] to-[#00E5FF] rounded-2xl flex items-center justify-center opacity-70" />
          </div>
          <p className="text-xs text-[#94A3B8]">All systems operational and monitored</p>
        </div>

        <div className="glass-card p-6 rounded-2xl hover:shadow-lg transition-all duration-300 hover:border-[rgba(79,124,255,0.3)]">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-[#94A3B8] text-xs font-semibold uppercase tracking-wider mb-1">
                Active Threats
              </p>
              <p className="text-3xl font-bold text-[#4F7CFF]">0</p>
            </div>
            <div className="w-12 h-12 bg-gradient-to-br from-[#4F7CFF] to-[#7C3AED] rounded-2xl flex items-center justify-center opacity-70" />
          </div>
          <p className="text-xs text-[#94A3B8]">No active threats detected</p>
        </div>

        <div className="glass-card p-6 rounded-2xl hover:shadow-lg transition-all duration-300 hover:border-[rgba(79,124,255,0.3)]">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-[#94A3B8] text-xs font-semibold uppercase tracking-wider mb-1">
                AI Engine
              </p>
              <p className="text-3xl font-bold text-[#00E5FF]">Running</p>
            </div>
            <div className="w-12 h-12 bg-gradient-to-br from-[#00E5FF] to-[#4F7CFF] rounded-2xl flex items-center justify-center opacity-70 animate-pulse" />
          </div>
          <p className="text-xs text-[#94A3B8]">Confidence: 99.8%</p>
        </div>

        {/* Large Info Section */}
        <div className="md:col-span-2 lg:col-span-3 glass-card p-8 rounded-2xl border border-[rgba(79,124,255,0.15)]">
          <h2 className="text-2xl font-bold text-[#F1F5F9] mb-6">Application Shell</h2>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-sm font-semibold text-[#4F7CFF] uppercase tracking-wider mb-3">
                Navigation Features
              </h3>
              <ul className="space-y-2 text-sm text-[#94A3B8]">
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#22C55E] rounded-full" />
                  Collapsible sidebar with 9 main menu items
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#22C55E] rounded-full" />
                  Floating top navigation with system info
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#22C55E] rounded-full" />
                  Real-time search across all systems
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#22C55E] rounded-full" />
                  Notification center with badge counter
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#22C55E] rounded-full" />
                  Theme toggle and user profile dropdown
                </li>
              </ul>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#4F7CFF] uppercase tracking-wider mb-3">
                Design Elements
              </h3>
              <ul className="space-y-2 text-sm text-[#94A3B8]">
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] rounded-full" />
                  Glassmorphism with backdrop blur effects
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] rounded-full" />
                  Animated AI orb in sidebar assistant card
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] rounded-full" />
                  Gradient borders and neon highlights
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] rounded-full" />
                  Smooth hover animations and transitions
                </li>
                <li className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] rounded-full" />
                  Large rounded corners (18px+) with layered depth
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="glass-card p-6 rounded-2xl border border-[rgba(79,124,255,0.15)]">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-2 h-2 bg-[#4F7CFF] rounded-full animate-pulse" />
            <h3 className="text-sm font-semibold text-[#F1F5F9]">Sidebar Menu</h3>
          </div>
          <p className="text-xs text-[#94A3B8] leading-relaxed">
            Dashboard, Live Connections, Threat Intelligence, Firewall Rules, AI Decisions, Traffic Analytics, Processes, Reports, and Settings
          </p>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-[rgba(79,124,255,0.15)]">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-2 h-2 bg-[#00E5FF] rounded-full animate-pulse" />
            <h3 className="text-sm font-semibold text-[#F1F5F9]">AI Assistant</h3>
          </div>
          <p className="text-xs text-[#94A3B8] leading-relaxed">
            Bottom sidebar card with animated glowing orb, protection state indicator, and Quick Scan button
          </p>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-[rgba(79,124,255,0.15)]">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-2 h-2 bg-[#7C3AED] rounded-full animate-pulse" />
            <h3 className="text-sm font-semibold text-[#F1F5F9]">Top Navigation</h3>
          </div>
          <p className="text-xs text-[#94A3B8] leading-relaxed">
            System info, search, notifications, theme toggle, and user profile with dropdown menu
          </p>
        </div>
      </div>

      {/* Footer Note */}
      <div className="mt-8 glass-card p-4 rounded-2xl border border-[rgba(79,124,255,0.15)] text-center">
        <p className="text-xs text-[#94A3B8]">
          Premium application shell ready for dashboard widgets. Use the sidebar to navigate between sections.
        </p>
      </div>
    </div>
  );
}
