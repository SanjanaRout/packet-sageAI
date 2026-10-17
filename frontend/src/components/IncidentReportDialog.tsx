"use client";

import { Download, FileText, Loader2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchMarkdownReportText, getIncidentReport } from "@/lib/api";
import type { IncidentReportResponse } from "@/types/api";

interface IncidentReportDialogProps {
  incidentId: string;
}

export function IncidentReportDialog({
  incidentId,
}: IncidentReportDialogProps) {
  const [open, setOpen] = useState(false);
  const [report, setReport] = useState<IncidentReportResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getIncidentReport(incidentId);
      setReport(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load report");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    if (open) {
      loadReport();
    }
  }, [open, loadReport]);

  const handleDownloadMarkdown = async () => {
    setDownloading(true);
    try {
      let mdContent = report?.markdown_report;
      if (!mdContent) {
        mdContent = await fetchMarkdownReportText(incidentId);
      }
      const blob = new Blob([mdContent], {
        type: "text/markdown;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `incident-report-${incidentId}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to download markdown report",
      );
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger className="inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded-md border border-input bg-background hover:bg-muted text-xs font-medium cursor-pointer">
        <FileText className="h-3.5 w-3.5" />
        View / Export Report
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col p-0">
        <DialogHeader className="p-4 sm:p-6 pb-2 border-b">
          <div className="flex items-center justify-between pr-6">
            <div>
              <DialogTitle className="text-base font-semibold">
                Structured Incident Report
              </DialogTitle>
              <DialogDescription className="text-xs">
                Incident: <span className="font-mono">{incidentId}</span>
              </DialogDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleDownloadMarkdown}
                disabled={loading || !report || downloading}
                className="h-8 text-xs gap-1.5"
              >
                <Download className="h-3.5 w-3.5" />
                {downloading ? "Downloading..." : "Download Markdown (.md)"}
              </Button>
            </div>
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-5 text-xs">
          {loading && (
            <div className="py-12 flex flex-col items-center justify-center text-muted-foreground gap-2">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span>Generating structured incident report...</span>
            </div>
          )}

          {error && (
            <Alert variant="destructive" className="py-2.5">
              <AlertTitle className="text-xs">Error</AlertTitle>
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}

          {report && !loading && (
            <>
              {/* Meta header */}
              <div className="flex flex-wrap items-center gap-2 pb-2 border-b">
                <Badge variant="outline" className="font-mono text-[11px]">
                  Status: {report.analyst_feedback_history.current_status}
                </Badge>
                {report.observed_facts.time_shift_applied && (
                  <Badge
                    variant="outline"
                    className="bg-blue-50 text-blue-700 border-blue-200 text-[11px]"
                  >
                    12h Clock Shift Applied
                  </Badge>
                )}
                <span className="text-muted-foreground text-[11px] ml-auto">
                  Generated: {new Date(report.generated_at).toUTCString()}
                </span>
              </div>

              {/* 1. Executive Summary */}
              <div className="space-y-1.5">
                <h4 className="font-semibold text-sm text-foreground">
                  1. Executive Summary
                </h4>
                <div className="rounded-md border bg-muted/20 p-3 leading-relaxed text-muted-foreground">
                  {report.executive_summary}
                </div>
              </div>

              {/* 2. Observed Facts */}
              <div className="space-y-2">
                <h4 className="font-semibold text-sm text-foreground">
                  2. Observed Facts
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div className="rounded border p-2 space-y-0.5">
                    <span className="text-[10px] text-muted-foreground uppercase font-semibold">
                      Time Window
                    </span>
                    <div className="font-mono text-[11px]">
                      {report.observed_facts.time_window}
                    </div>
                  </div>
                  <div className="rounded border p-2 space-y-0.5">
                    <span className="text-[10px] text-muted-foreground uppercase font-semibold">
                      Rules Triggered
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {report.observed_facts.rules_triggered.map((r) => (
                        <Badge
                          key={r}
                          variant="secondary"
                          className="text-[10px] py-0"
                        >
                          {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="rounded border p-2 space-y-0.5">
                    <span className="text-[10px] text-muted-foreground uppercase font-semibold">
                      Source IPs
                    </span>
                    <div className="font-mono text-[11px]">
                      {report.observed_facts.src_ips.join(", ") || "N/A"}
                    </div>
                  </div>
                  <div className="rounded border p-2 space-y-0.5">
                    <span className="text-[10px] text-muted-foreground uppercase font-semibold">
                      Target Destination IPs
                    </span>
                    <div className="font-mono text-[11px]">
                      {report.observed_facts.dst_ips.join(", ") || "N/A"}
                    </div>
                  </div>
                </div>

                <div className="text-[11px] text-muted-foreground">
                  <strong>Trigger Reasons:</strong>{" "}
                  {report.observed_facts.reasons.join("; ")}
                </div>

                {report.observed_facts.top_feature_deviations &&
                  report.observed_facts.top_feature_deviations.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      <div className="text-[11px] font-semibold text-muted-foreground">
                        Top Statistical Feature Deviations vs. Benign Baseline:
                      </div>
                      <div className="rounded-md border overflow-x-auto">
                        <Table>
                          <TableHeader>
                            <TableRow className="bg-muted/40">
                              <TableHead className="text-[11px] h-7">
                                Feature
                              </TableHead>
                              <TableHead className="text-[11px] h-7 text-right">
                                Observed Value
                              </TableHead>
                              <TableHead className="text-[11px] h-7 text-right">
                                Benign Median
                              </TableHead>
                              <TableHead className="text-[11px] h-7">
                                Percentile Bracket
                              </TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {report.observed_facts.top_feature_deviations.map(
                              (d) => (
                                <TableRow key={`${d.feature}-${d.value}`}>
                                  <TableCell className="font-mono text-[11px] font-medium">
                                    {d.feature}
                                  </TableCell>
                                  <TableCell className="text-right font-mono text-[11px] font-bold text-rose-600">
                                    {d.value}
                                  </TableCell>
                                  <TableCell className="text-right font-mono text-[11px] text-muted-foreground">
                                    {d.benign_median}
                                  </TableCell>
                                  <TableCell className="text-[11px] text-muted-foreground">
                                    {d.bracket}
                                  </TableCell>
                                </TableRow>
                              ),
                            )}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                  )}
              </div>

              {/* 3. Hypotheses & Uncertainties */}
              <div className="space-y-1.5">
                <h4 className="font-semibold text-sm text-foreground">
                  3. Hypotheses & Uncertainties
                </h4>
                <div className="space-y-1 rounded-md border p-3 bg-muted/10">
                  {report.hypotheses_and_uncertainties.map((h) => (
                    <div
                      key={h}
                      className="text-[11px] leading-relaxed text-muted-foreground"
                    >
                      • {h}
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. Recommended Next Steps */}
              <div className="space-y-1.5">
                <h4 className="font-semibold text-sm text-foreground">
                  4. Recommended Next Steps
                </h4>
                <div className="space-y-1.5 rounded-md border p-3 bg-muted/10">
                  <p className="text-[10px] text-amber-700 dark:text-amber-400 font-medium pb-0.5">
                    Advisory triage recommendations for security analyst review.
                    Autonomous blocking is not performed.
                  </p>
                  {report.recommended_next_steps.map((step, idx) => (
                    <div
                      key={step}
                      className="text-[11px] leading-relaxed text-foreground flex items-start gap-1.5"
                    >
                      <span className="font-semibold">{idx + 1}.</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* 5. Analyst Feedback History */}
              <div className="space-y-1.5">
                <h4 className="font-semibold text-sm text-foreground">
                  5. Analyst Decision Audit History
                </h4>
                {report.analyst_feedback_history.feedback_entries.length ===
                0 ? (
                  <p className="text-muted-foreground italic text-[11px]">
                    No feedback recorded yet.
                  </p>
                ) : (
                  <div className="space-y-1">
                    {report.analyst_feedback_history.feedback_entries.map(
                      (fb, idx) => (
                        <div
                          key={`${fb.timestamp}-${fb.decision}-${idx}`}
                          className="rounded border p-2 text-[11px] bg-muted/20"
                        >
                          <div className="flex items-center justify-between text-muted-foreground text-[10px] mb-0.5">
                            <span className="font-medium text-foreground">
                              {fb.analyst_name || fb.analyst_id || "Anonymous"}
                            </span>
                            <span>{new Date(fb.timestamp).toUTCString()}</span>
                          </div>
                          <div className="font-semibold text-rose-600 mb-0.5 uppercase text-[10px]">
                            {fb.decision}
                          </div>
                          <div className="text-foreground leading-relaxed">
                            {fb.note}
                          </div>
                        </div>
                      ),
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
