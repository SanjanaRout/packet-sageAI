import type { Metadata } from "next";
import "./globals.css";
import { TooltipProvider } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { figtree, geistMono, geistSans } from "./fonts";

export const metadata: Metadata = {
  title: "PacketSage AI - Network Flow & Incident Investigation",
  description:
    "Evidence-grounded network flow analysis and incident correlation assistant",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={cn(
        "h-full",
        "antialiased",
        geistSans.variable,
        geistMono.variable,
        figtree.variable,
      )}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground font-sans">
        <TooltipProvider>{children}</TooltipProvider>
      </body>
    </html>
  );
}
