"use client";

import { AlertTriangle, Clock, FileSpreadsheet } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { UploadResponse } from "@/types/api";

interface IngestionSummaryCardProps {
  upload: UploadResponse;
}

export function IngestionSummaryCard({ upload }: IngestionSummaryCardProps) {
  const malformed = upload.malformed_rows ?? upload.invalid_rows ?? 0;
  const incomplete = upload.incomplete_rows ?? 0;
  const nanInfSanitized = upload.nan_inf_sanitized_records ?? 0;
  const timeShiftApplied =
    upload.time_shift_applied ??
    upload.warnings?.some((w) => w.includes("shifted"));

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-5 w-5 text-primary" />
            <div>
              <CardTitle className="text-base font-semibold">
                Ingestion & Sanitation Summary
              </CardTitle>
              <CardDescription className="text-xs">
                Upload Session:{" "}
                <span className="font-mono">{upload.upload_id}</span>
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {timeShiftApplied ? (
              <Badge
                variant="outline"
                className="text-xs bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-300 gap-1"
              >
                <Clock className="h-3 w-3" />
                12h Clock Shift Applied
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="text-xs text-muted-foreground gap-1"
              >
                <Clock className="h-3 w-3" />
                Standard Clock
              </Badge>
            )}
            <Badge variant="secondary" className="text-xs">
              {upload.incident_count} Incident(s) Formed
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-6 space-y-4">
        {/* Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              Total Flows
            </div>
            <div className="mt-0.5 text-lg font-bold text-foreground">
              {upload.total_rows.toLocaleString()}
            </div>
            <div className="text-[10px] text-emerald-600">
              {upload.valid_rows.toLocaleString()} valid (≤20% NaNs)
            </div>
          </div>

          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              Malformed Records
            </div>
            <div
              className={`mt-0.5 text-lg font-bold ${malformed > 0 ? "text-amber-600" : "text-emerald-600"}`}
            >
              {malformed.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground">
              &gt;20% unusable features
            </div>
          </div>

          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              Incomplete Records
            </div>
            <div
              className={`mt-0.5 text-lg font-bold ${incomplete > 0 ? "text-blue-600" : "text-muted-foreground"}`}
            >
              {incomplete.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground">
              Partial NaNs imputed
            </div>
          </div>

          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              NaN/Inf Sanitized
            </div>
            <div
              className={`mt-0.5 text-lg font-bold ${nanInfSanitized > 0 ? "text-indigo-600" : "text-muted-foreground"}`}
            >
              {nanInfSanitized.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground">
              Cleaned & normalized
            </div>
          </div>
        </div>

        {/* Breakdown Table */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs h-8">Quality Metric</TableHead>
                <TableHead className="text-xs h-8 text-right">Count</TableHead>
                <TableHead className="text-xs h-8 text-right">
                  Percentage
                </TableHead>
                <TableHead className="text-xs h-8">System Handling</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="text-xs font-medium">
                  Valid Supervised Flows
                </TableCell>
                <TableCell className="text-xs text-right font-mono">
                  {upload.valid_rows.toLocaleString()}
                </TableCell>
                <TableCell className="text-xs text-right text-muted-foreground">
                  {upload.total_rows > 0
                    ? ((upload.valid_rows / upload.total_rows) * 100).toFixed(1)
                    : 0}
                  %
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  Scored with Random Forest & Novelty
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="text-xs font-medium">
                  Suspicious Flows (Score ≥ Threshold)
                </TableCell>
                <TableCell className="text-xs text-right font-mono font-semibold text-rose-600">
                  {upload.suspicious_rows.toLocaleString()}
                </TableCell>
                <TableCell className="text-xs text-right text-muted-foreground">
                  {upload.valid_rows > 0
                    ? (
                        (upload.suspicious_rows / upload.valid_rows) *
                        100
                      ).toFixed(1)
                    : 0}
                  %
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  Candidate for incident graph correlation
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="text-xs font-medium">
                  Unusual Novelty Flows
                </TableCell>
                <TableCell className="text-xs text-right font-mono font-semibold text-purple-600">
                  {upload.unusual_rows.toLocaleString()}
                </TableCell>
                <TableCell className="text-xs text-right text-muted-foreground">
                  {upload.valid_rows > 0
                    ? ((upload.unusual_rows / upload.valid_rows) * 100).toFixed(
                        1,
                      )
                    : 0}
                  %
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  Isolation Forest out-of-distribution alert
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="text-xs font-medium">
                  Malformed / Invalid Rows
                </TableCell>
                <TableCell className="text-xs text-right font-mono text-amber-600">
                  {malformed.toLocaleString()}
                </TableCell>
                <TableCell className="text-xs text-right text-muted-foreground">
                  {upload.total_rows > 0
                    ? ((malformed / upload.total_rows) * 100).toFixed(1)
                    : 0}
                  %
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  Dropped from correlation (unusable)
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>

        {/* Warnings */}
        {upload.warnings && upload.warnings.length > 0 && (
          <div className="space-y-1.5 pt-1">
            <div className="text-xs font-medium text-muted-foreground flex items-center gap-1">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
              Ingestion Notices & Warnings ({upload.warnings.length}):
            </div>
            <div className="rounded-md border bg-muted/30 p-2.5 space-y-1 text-xs">
              {upload.warnings.map((w) => (
                <div
                  key={w}
                  className="text-muted-foreground font-mono text-[11px] leading-relaxed"
                >
                  • {w}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
