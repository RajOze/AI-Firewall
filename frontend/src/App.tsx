import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import AppLayout from "./components/Layout/AppLayout";
import DashboardPage from "./pages/DashboardPage";
import NetworkDevicesPage from "./pages/NetworkDevicesPage";
import FirewallPage from "./pages/FirewallPage";
import AlertsPage from "./pages/AlertsPage";
import AIAssistantPage from "./pages/AIAssistantPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/devices" element={<NetworkDevicesPage />} />
          <Route path="/firewall" element={<FirewallPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/ai-assistant" element={<AIAssistantPage />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}