import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { SidebarShell } from "@/components/shell/sidebar";
import { TopNavShell } from "@/components/shell/top-nav";
import "./globals.css";

const geistSans = Geist({ subsets: ["latin"] });
const geistMono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SentinelAI Firewall",
  description: "Enterprise cybersecurity desktop application",
  viewport: {
    width: "device-width",
    initialScale: 1,
    maximumScale: 1,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="bg-[#050816]">
      <body className={`${geistSans.className} bg-[#050816] text-[#F1F5F9] overflow-hidden`}>
        <div className="flex h-screen bg-[#050816]">
          <SidebarShell />
          <div className="flex-1 flex flex-col overflow-hidden">
            <TopNavShell />
            <main className="flex-1 overflow-auto pt-20">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
