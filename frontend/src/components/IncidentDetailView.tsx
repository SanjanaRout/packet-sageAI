"use client";

import { ArrowLeft, Clock, Loader2, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { AnalystFeedbackSection } from "@/components/AnalystFeedbackSection";
import { AskIncidentSheet } from "@/components/AskIncidentSheet";
import { IncidentFlowsTable } from "@/components/IncidentFlowsTable";
import { IncidentReportDialog } from "@/components/IncidentReportDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getIncidentDetail } from "@/lib/api";
import type { IncidentDetailResponse } from "@/types/api";

interface IncidentDetailViewProps {
  incidentId: string;
  onBack: () => void;
}

export function IncidentDetailView({
  incidentId,
  onBack,
}: IncidentDetailViewProps) {
  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getIncidentDetail(incidentId);
      setDetail(data);
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Failed to load incident details",
      );
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    fetchDetail();
  }, [fetchDetail]);

  if (loading && !detail) {
    return (
      <Card className="border-border p-12 text-center">
        <div className="flex flex-col items-center justify-center gap-2 text-muted-foreground text-xs">
          <Loader2 className="h-6 w-6 animate-spin" />
          <span>Loading incident {incidentId} telemetry...</span>
        </div>
      </Card>
    );
  }

  if (error || !detail) {
    return (
      <Card className="border-rose-200 bg-rose-50/50 p-6">
        <div className="text-xs text-rose-800 space-y-2">
          <p className="font-semibold">
            Error loading incident: {error || "Not found"}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            className="text-xs"
          >
            Return to Incidents List
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Top action / back bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <Button
          variant="ghost"
          size="sm"
          onClick={onBack}
          className="text-xs h-8 gap-1.5 self-start"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Incident List
        </Button>
        <div className="flex items-center gap-2">
          <AskIncidentSheet incidentId={incidentId} />
          <IncidentReportDialog incidentId={incidentId} />
        </div>
      </div>

      {/* Incident summary header */}
      <Card className="border-border">
        <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-rose-600" />
                <CardTitle className="text-base font-semibold">
                  Incident: {detail.incident_id}
                </CardTitle>
              </div>
              <CardDescription className="text-xs mt-0.5">
                Observed from {detail.start} to {detail.end}
              </CardDescription>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              {detail.kinds.map((k) => (
                <Badge
                  key={k}
                  variant="destructive"
                  className="uppercase font-mono text-[10px]"
                >
                  {k}
                </Badge>
              ))}
              {detail.time_shift_applied && (
                <Badge
                  variant="outline"
                  className="text-[10px] bg-blue-50 text-blue-700 border-blue-200 gap-1"
                >
                  <Clock className="h-3 w-3" />
                  12h Shifted
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="px-4 pb-4 sm:px-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center mb-3">
            <div className="rounded-lg border bg-card p-2.5">
              <div className="text-[11px] text-muted-foreground">
                Flagged Flows
              </div>
              <div className="mt-0.5 text-base font-bold">
                {detail.flow_count.toLocaleString()}
              </div>
            </div>
            <div className="rounded-lg border bg-card p-2.5">
              <div className="text-[11px] text-muted-foreground">
                Max Anomaly Score
              </div>
              <div className="mt-0.5 text-base font-bold text-rose-600">
                {detail.max_score.toFixed(4)}
              </div>
            </div>
            <div className="rounded-lg border bg-card p-2.5">
              <div className="text-[11px] text-muted-foreground">
                Source Hosts
              </div>
              <div className="mt-0.5 text-xs font-mono font-semibold truncate">
                {detail.src_ips.join(", ") || "—"}
              </div>
            </div>
            <div className="rounded-lg border bg-card p-2.5">
              <div className="text-[11px] text-muted-foreground">
                Target Hosts
              </div>
              <div className="mt-0.5 text-xs font-mono font-semibold truncate">
                {detail.dst_ips.join(", ") || "—"}
              </div>
            </div>
          </div>

          <div className="rounded-md border bg-muted/20 p-2.5 text-xs text-muted-foreground">
            <strong>Correlation Reasons:</strong> {detail.reasons.join("; ")}
          </div>
        </CardContent>
      </Card>

      {/* Evidence Flows Table with Deviations */}
      <IncidentFlowsTable
        flows={detail.flows}
        totalFlows={detail.total_flows}
      />

      {/* Analyst Feedback Section */}
      <AnalystFeedbackSection
        incidentId={detail.incident_id}
        currentStatus={detail.status}
        feedbackHistory={detail.feedback}
        onFeedbackSaved={fetchDetail}
      />
    </div>
  );
}
