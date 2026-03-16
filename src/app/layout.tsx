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
        <div className="flex h-screen overflow-hidden bg-[var(--color-bg-base)] text-slate-900 p-4 md:p-5 gap-5">
          <Sidebar />
          <main className="flex-1 h-full overflow-hidden relative z-10 transition-all rounded-[2.5rem] bg-transparent">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
