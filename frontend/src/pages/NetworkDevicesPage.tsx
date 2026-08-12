import { useState } from "react";

interface Device {
  id: string;
  name: string;
  ip: string;
  mac: string;
  type: "Server" | "Workstation" | "Mobile" | "IoT Probes";
  status: "Protected" | "Warning" | "Isolated";
  bandwidth: string;
  os: string;
}

const mockDevices: Device[] = [
  {
    id: "DEV-01",
    name: "SENTINEL-X1-MAIN",
    ip: "192.168.1.100",
    mac: "00:1A:2B:3C:4D:5E",
    type: "Workstation",
    status: "Protected",
    bandwidth: "42.8 Mbps",
    os: "Windows 11 Pro Enterprise",
  },
  {
    id: "DEV-02",
    name: "DB-CLUSTER-ALPHA",
    ip: "10.0.4.52",
    mac: "A1:B2:C3:D4:E5:F6",
    type: "Server",
    status: "Protected",
    bandwidth: "128.4 Mbps",
    os: "Ubuntu 24.04 LTS",
  },
  {
    id: "DEV-03",
    name: "CORP-SEC-GATEWAY",
    ip: "192.168.1.1",
    mac: "34:90:9E:11:22:33",
    type: "Server",
    status: "Protected",
    bandwidth: "450.0 Mbps",
    os: "Sentinel Hardened OS",
  },
  {
    id: "DEV-04",
    name: "UNKNOWN-PROBE-99",
    ip: "192.168.1.189",
    mac: "BC:D1:E2:F3:A4:B5",
    type: "IoT Probes",
    status: "Warning",
    bandwidth: "1.2 Mbps",
    os: "Embedded Linux",
  },
  {
    id: "DEV-05",
    name: "EXECUTIVE-LAPTOP",
    ip: "192.168.1.142",
    mac: "70:85:C2:DE:F0:11",
    type: "Mobile",
    status: "Protected",
    bandwidth: "15.4 Mbps",
    os: "macOS Sequoia",
  },
  {
    id: "DEV-06",
    name: "ROGUE-NODE-SUSPECT",
    ip: "10.0.9.111",
    mac: "EE:FF:00:11:22:33",
    type: "Workstation",
    status: "Isolated",
    bandwidth: "0.0 Mbps",
    os: "Unknown OS",
  },
];

export default function NetworkDevicesPage() {
  const [filterType, setFilterType] = useState<string>("All");

  const filteredDevices = mockDevices.filter(
    (dev) => filterType === "All" || dev.type === filterType
  );

  return (
    <div className="flex flex-col w-full gap-gutter">
      {/* Header Banner */}
      <div className="bg-surface-container p-lg rounded border border-outline-variant/30 flex items-center justify-between">
        <div>
          <h1 className="font-headline-lg text-on-surface">Network & Connected Devices</h1>
          <p className="font-body-sm text-outline mt-1">
            Real-time topology, MAC authorization, and bandwidth inspection across subnets.
          </p>
        </div>
        <div className="flex items-center gap-md">
          <button className="px-md py-sm bg-primary text-on-primary font-body-sm rounded hover:bg-primary-container transition-colors flex items-center gap-xs">
            <span className="material-symbols-outlined text-[18px]">radar</span>
            Scan Subnet
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-sm border-b border-outline-variant/30 pb-sm">
        {["All", "Server", "Workstation", "Mobile", "IoT Probes"].map((tab) => (
          <button
            key={tab}
            onClick={() => setFilterType(tab)}
            className={`px-md py-xs font-label-caps rounded transition-colors ${
              filterType === tab
                ? "bg-primary text-on-primary"
                : "bg-surface-container-high text-on-surface-variant hover:text-on-surface"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Devices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-gutter">
        {filteredDevices.map((dev) => (
          <div
            key={dev.id}
            className="bg-surface-container p-lg rounded border border-outline-variant/30 flex flex-col justify-between hover:border-primary/50 transition-all group"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-sm">
                <span className="material-symbols-outlined text-primary text-[28px]">
                  {dev.type === "Server"
                    ? "dns"
                    : dev.type === "Workstation"
                    ? "desktop_windows"
                    : dev.type === "Mobile"
                    ? "smartphone"
                    : "sensors"}
                </span>
                <div>
                  <h3 className="font-headline-sm text-on-surface group-hover:text-primary transition-colors">
                    {dev.name}
                  </h3>
                  <span className="font-code-sm text-outline text-[12px]">{dev.ip}</span>
                </div>
              </div>
              <span
                className={`px-xs py-[2px] rounded uppercase font-bold text-[10px] border ${
                  dev.status === "Protected"
                    ? "bg-secondary/10 text-secondary border-secondary/20"
                    : dev.status === "Warning"
                    ? "bg-tertiary/10 text-tertiary border-tertiary/20"
                    : "bg-error/10 text-error border-error/20"
                }`}
              >
                {dev.status}
              </span>
            </div>

            <div className="my-md py-sm border-y border-outline-variant/20 space-y-xs font-code-sm text-[12px]">
              <div className="flex justify-between">
                <span className="text-outline">MAC Address:</span>
                <span className="text-on-surface-variant">{dev.mac}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-outline">Bandwidth:</span>
                <span className="text-secondary">{dev.bandwidth}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-outline">Operating System:</span>
                <span className="text-on-surface-variant truncate max-w-[150px]">{dev.os}</span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-xs">
              <button className="text-body-sm text-outline hover:text-on-surface flex items-center gap-xs">
                <span className="material-symbols-outlined text-[16px]">info</span> Details
              </button>
              <button
                className={`text-body-sm font-medium px-sm py-xs rounded ${
                  dev.status === "Isolated"
                    ? "bg-secondary/10 text-secondary hover:bg-secondary/20"
                    : "bg-error/10 text-error hover:bg-error/20"
                }`}
              >
                {dev.status === "Isolated" ? "Re-Authorize" : "Isolate Device"}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
