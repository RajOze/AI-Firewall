import { Sidebar } from "@/components/sidebar";
import { TopNav } from "@/components/top-nav";
import { SummaryCards } from "@/components/summary-cards";
import { TrafficCharts } from "@/components/traffic-charts";
import { NetworkTable } from "@/components/network-table";
import { ThreatPanel } from "@/components/threat-panel";
import { RulesTable } from "@/components/rules-table";
import { DecisionTimeline } from "@/components/decision-timeline";
import { SystemHealth } from "@/components/system-health";
import { EventLog } from "@/components/event-log";
import { RightSidebar } from "@/components/right-sidebar";
import { StatusBar } from "@/components/status-bar";

export default function Home() {
  return (
    <div className="flex h-screen bg-background">
      {/* Left Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Navigation */}
        <TopNav />

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6">
            {/* Summary Cards */}
            <SummaryCards />

            {/* Traffic Charts */}
            <TrafficCharts />

            {/* Network and Threats Row */}
            <div className="grid grid-cols-3 gap-4 mb-6">
              {/* Live Network */}
              <div className="col-span-2">
                <NetworkTable />
              </div>

              {/* Threat Panel */}
              <div>
                <ThreatPanel />
              </div>
            </div>

            {/* Rules and Timeline Row */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <RulesTable />
              <DecisionTimeline />
            </div>

            {/* System Health */}
            <div className="mb-6">
              <SystemHealth />
            </div>

            {/* Events Log */}
            <div className="mb-6">
              <EventLog />
            </div>
          </div>
        </div>

        {/* Status Bar */}
        <StatusBar />
      </div>

      {/* Right Sidebar */}
      <RightSidebar />
    </div>
  );
}
