export default function DashboardPage() {
  return (
    <div className="min-h-screen p-8" style={{ background: 'linear-gradient(135deg, rgba(3, 7, 18, 0.5) 0%, rgba(10, 14, 26, 0.3) 100%)' }}>
      {/* Welcome Section - Premium */}
      <div className="mb-12 space-y-3">
        <h1 className="text-5xl font-bold tracking-tight text-gradient">
          Security Dashboard
        </h1>
        <p className="text-[#94a3b8] text-lg">Real-time enterprise cybersecurity monitoring powered by advanced AI threat detection</p>
      </div>

      {/* Dashboard Grid - Premium Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {/* Status Cards - Premium */}
        <div className="card-premium group" style={{ background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.02) 100%)', borderColor: 'rgba(16, 185, 129, 0.15)' }}>
          <div className="flex items-start justify-between mb-6">
            <div>
              <p className="text-xs font-bold text-[#94a3b8] uppercase tracking-widest mb-2">
                Protection Status
              </p>
              <p className="text-4xl font-bold text-[#10b981]">Protected</p>
            </div>
            <div className="w-14 h-14 rounded-[14px] flex items-center justify-center flex-shrink-0 group-hover:shadow-glow transition-all duration-300 relative overflow-hidden" style={{ background: 'linear-gradient(135deg, #10b981, #06b6d4)' }}>
              <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent" />
            </div>
          </div>
          <p className="text-sm text-[#94a3b8]">All systems operational and monitored</p>
        </div>

        <div className="card-premium group" style={{ background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.08) 0%, rgba(61, 97, 255, 0.02) 100%)', borderColor: 'rgba(61, 97, 255, 0.15)' }}>
          <div className="flex items-start justify-between mb-6">
            <div>
              <p className="text-xs font-bold text-[#94a3b8] uppercase tracking-widest mb-2">
                Active Threats
              </p>
              <p className="text-4xl font-bold text-[#3d61ff]">0</p>
            </div>
            <div className="w-14 h-14 rounded-[14px] flex items-center justify-center flex-shrink-0 group-hover:shadow-glow transition-all duration-300 relative overflow-hidden" style={{ background: 'linear-gradient(135deg, #3d61ff, #7c3aed)' }}>
              <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent" />
            </div>
          </div>
          <p className="text-sm text-[#94a3b8]">No active threats detected</p>
        </div>

        <div className="card-premium group pulse-glow" style={{ background: 'linear-gradient(135deg, rgba(0, 217, 255, 0.08) 0%, rgba(0, 217, 255, 0.02) 100%)', borderColor: 'rgba(0, 217, 255, 0.15)' }}>
          <div className="flex items-start justify-between mb-6">
            <div>
              <p className="text-xs font-bold text-[#94a3b8] uppercase tracking-widest mb-2">
                AI Engine
              </p>
              <p className="text-4xl font-bold text-[#00d9ff]">Running</p>
            </div>
            <div className="w-14 h-14 rounded-[14px] flex items-center justify-center flex-shrink-0 group-hover:shadow-glow transition-all duration-300 relative overflow-hidden animate-pulse" style={{ background: 'linear-gradient(135deg, #00d9ff, #3d61ff)' }}>
              <div className="absolute inset-0 bg-gradient-to-br from-white/30 to-transparent" />
            </div>
          </div>
          <p className="text-sm text-[#94a3b8]">Confidence: 99.8%</p>
        </div>

        {/* Large Feature Section */}
        <div className="md:col-span-2 lg:col-span-3 card-premium" style={{ background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.06) 0%, rgba(0, 217, 255, 0.03) 100%)', borderColor: 'rgba(61, 97, 255, 0.15)' }}>
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-[#f8fafc] mb-2">Enterprise-Grade Application Shell</h2>
            <p className="text-[#94a3b8]">Purpose-built for modern cybersecurity operations with AI-driven insights</p>
          </div>
          
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <h3 className="text-xs font-bold text-[#3d61ff] uppercase tracking-widest mb-4">
                Core Navigation
              </h3>
              <ul className="space-y-3">
                {[
                  'Collapsible sidebar with smart icon-only mode',
                  'Floating premium top navigation with glassmorphism',
                  'Unified search with AI-powered results',
                  'Real-time notification system with badge counter',
                  'Theme toggle and user profile management',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-sm text-[#94a3b8]">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: 'linear-gradient(135deg, #10b981, #06b6d4)' }} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="text-xs font-bold text-[#3d61ff] uppercase tracking-widest mb-4">
                Design System
              </h3>
              <ul className="space-y-3">
                {[
                  'Premium glassmorphism with 30px backdrop blur',
                  'Gradient borders and animated highlights',
                  'Layered depth with soft shadows',
                  'Large 14-16px rounded corners throughout',
                  'Smooth cubic-bezier transitions and micro-interactions',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-sm text-[#94a3b8]">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: 'linear-gradient(135deg, #00d9ff, #3d61ff)' }} />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Feature Cards */}
        {[
          { title: 'Sidebar', desc: 'Dashboard, Connections, Threats, Rules, Decisions, Analytics, Processes, Reports, Settings', icon: '📊' },
          { title: 'AI Assistant', desc: 'Animated orb, protection indicators, Quick Scan, real-time status updates', icon: '🤖' },
          { title: 'Premium UI', desc: 'Gradients, glassmorphism, smooth animations, professional typography', icon: '✨' },
        ].map((item, i) => (
          <div key={i} className="card-premium" style={{ background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.08) 0%, rgba(0, 217, 255, 0.04) 100%)', borderColor: 'rgba(61, 97, 255, 0.2)' }}>
            <div className="flex items-start gap-4 mb-4">
              <div className="text-2xl">{item.icon}</div>
              <div>
                <h3 className="text-sm font-bold text-[#f8fafc]">{item.title}</h3>
              </div>
            </div>
            <p className="text-sm text-[#94a3b8] leading-relaxed">{item.desc}</p>
          </div>
        ))}
      </div>

      {/* Footer Section */}
      <div className="card-compact text-center mt-12" style={{ background: 'linear-gradient(135deg, rgba(61, 97, 255, 0.05) 0%, rgba(0, 217, 255, 0.03) 100%)', borderColor: 'rgba(148, 163, 184, 0.1)' }}>
        <p className="text-sm text-[#94a3b8] font-medium">
          Enterprise-grade dashboard ready for advanced threat monitoring and security operations
        </p>
      </div>
    </div>
  );
}
