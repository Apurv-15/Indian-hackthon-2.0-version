import type { Metadata } from "next";
import "./globals.css";

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
      <body>{children}</body>
    </html>
  );
}
