import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "../components/Sidebar";

export const metadata: Metadata = {
  title: "AegisAI - Advanced Threat Detection",
  description: "Multi-agent AI security analysis for URLs, emails, and files.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="flex h-screen overflow-hidden bg-[var(--color-bg-base)] text-slate-200">
          <Sidebar />
          {children}
        </div>
      </body>
    </html>
  );
}
