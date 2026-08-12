import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";

export default function AppLayout() {
  return (
    <div className="min-h-screen bg-surface text-on-surface font-body-md">
      <Sidebar />
      <Header />
      <main className="pl-60 pt-14 min-h-screen bg-surface w-full">
        <div className="flex flex-col w-full p-lg gap-gutter">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
