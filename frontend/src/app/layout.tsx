import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ReconIQ — AI Security Scanner",
  description: "Autonomous multi-agent web security scanner powered by AWS Bedrock",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-[#0a0f1a]`}>{children}</body>
    </html>
  );
}
