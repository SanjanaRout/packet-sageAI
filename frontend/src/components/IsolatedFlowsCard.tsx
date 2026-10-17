"use client";

import { ChevronDown, ChevronRight, Filter, Info } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { getIsolatedFlows } from "@/lib/api";
import type { IsolatedFlowsResponse } from "@/types/api";

interface IsolatedFlowsCardProps {
  uploadId: string;
}

export function IsolatedFlowsCard({ uploadId }: IsolatedFlowsCardProps) {
  const [data, setData] = useState<IsolatedFlowsResponse | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [_loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;
    if (!uploadId) return;

    setLoading(true);
    getIsolatedFlows(uploadId)
      .then((res) => {
        if (mounted) setData(res);
      })
      .catch(() => {
        // Silently handle if no isolated flows endpoint or empty
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [uploadId]);

  if (!data || data.total_count === 0) {
    return null;
  }

  return (
    <Card className="border-border">
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CardHeader className="py-3 px-4 sm:px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              <div>
                <CardTitle className="text-sm font-semibold">
                  Isolated Flagged Flows (1–2 Flow Bursts)
                </CardTitle>
                <CardDescription className="text-xs">
                  Separated from full incidents by{" "}
                  <code className="text-[11px]">ISOLATED_FLOW_MAX=2</code> to
                  prevent incident clutter
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className="text-xs font-mono bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-300"
              >
                {data.total_count} isolated flow(s)
              </Badge>
              <CollapsibleTrigger className="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted cursor-pointer">
                {isOpen ? (
                  <ChevronDown className="h-4 w-4" />
                ) : (
                  <ChevronRight className="h-4 w-4" />
                )}
              </CollapsibleTrigger>
            </div>
          </div>
        </CardHeader>
        <CollapsibleContent>
          <CardContent className="px-4 pb-4 sm:px-6 pt-0 space-y-3">
            <div className="rounded-md border bg-muted/30 p-2.5 text-xs text-muted-foreground flex items-start gap-2">
              <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
              <span>
                These flows exceeded supervised anomaly thresholds but occurred
                in bursts of ≤2 flows. Rather than creating low-confidence
                single-flow incidents, they are tracked here for forensic
                review.
              </span>
            </div>

            <div>
              <div className="text-[11px] font-medium text-muted-foreground mb-1.5">
                Sample Flagged Flow IDs (showing {data.flow_ids.length} of{" "}
                {data.total_count}):
              </div>
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-1.5 border rounded-md bg-background">
                {data.flow_ids.map((id) => (
                  <Badge
                    key={id}
                    variant="secondary"
                    className="font-mono text-[10px] py-0 px-1.5"
                  >
                    flow #{id}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
