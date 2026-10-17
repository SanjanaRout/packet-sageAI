"use client";

import { Info } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import type { FlowRecord } from "@/types/api";

interface IncidentFlowsTableProps {
  flows: FlowRecord[];
  totalFlows: number;
}

export function IncidentFlowsTable({
  flows,
  totalFlows,
}: IncidentFlowsTableProps) {
  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold">
              Evidence Flows & Behavioral Feature Deviations
            </CardTitle>
            <CardDescription className="text-xs">
              Showing {flows.length} representative flow(s) of{" "}
              {totalFlows.toLocaleString()} total associated records
            </CardDescription>
          </div>
          <Badge
            variant="outline"
            className="text-xs self-start sm:self-auto font-mono"
          >
            {totalFlows} Flagged Flows
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-6 space-y-4">
        {/* Baseline disclaimer alert */}
        <Alert className="bg-muted/40 border-border text-xs py-2 px-3">
          <Info className="h-4 w-4 text-blue-500" />
          <AlertTitle className="text-xs font-semibold">
            Statistical Deviation Disclaimer
          </AlertTitle>
          <AlertDescription className="text-[11px] text-muted-foreground mt-0.5">
            Feature brackets (e.g. &gt;99th percentile) highlight statistical
            extremity relative to the benign training traffic baseline. These
            represent observed distribution differences,{" "}
            <strong>
              not causal model explanations or SHAP attribution values
            </strong>
            .
          </AlertDescription>
        </Alert>

        {/* Flows table */}
        <div className="rounded-md border overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40">
                <TableHead className="text-xs w-[75px]">Flow ID</TableHead>
                <TableHead className="text-xs">Timestamp</TableHead>
                <TableHead className="text-xs">Source IP</TableHead>
                <TableHead className="text-xs">Target Host:Port</TableHead>
                <TableHead className="text-xs text-right">
                  Model Score
                </TableHead>
                <TableHead className="text-xs">Label</TableHead>
                <TableHead className="text-xs">Novelty</TableHead>
                <TableHead className="text-xs min-w-[280px]">
                  Statistical Deviations vs Benign Baseline
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {flows.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="text-center text-xs py-6 text-muted-foreground"
                  >
                    No individual flow records retrieved for this incident.
                  </TableCell>
                </TableRow>
              ) : (
                flows.map((flow) => {
                  const deviations = flow.deviations || [];
                  return (
                    <TableRow
                      key={flow.flow_id}
                      className="hover:bg-muted/20 align-top"
                    >
                      <TableCell className="font-mono text-xs font-semibold">
                        #{flow.flow_id}
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                        {flow.ts || "—"}
                      </TableCell>
                      <TableCell className="text-xs font-mono">
                        {flow.src_ip || "—"}
                      </TableCell>
                      <TableCell className="text-xs font-mono">
                        {flow.dst_ip || "—"}:{flow.dst_port ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs text-right font-mono font-bold text-rose-600">
                        {flow.score !== null && flow.score !== undefined
                          ? flow.score.toFixed(4)
                          : "—"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            flow.label === "suspicious"
                              ? "destructive"
                              : "secondary"
                          }
                          className="text-[10px] py-0 px-1.5"
                        >
                          {flow.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {flow.unusual ? (
                          <Badge
                            variant="outline"
                            className="text-[10px] py-0 px-1.5 bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950 dark:text-purple-300"
                          >
                            Unusual
                          </Badge>
                        ) : (
                          <span className="text-[11px] text-muted-foreground">
                            Normal
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        {deviations.length === 0 ? (
                          <span className="text-[11px] text-muted-foreground italic">
                            No notable feature deviations
                          </span>
                        ) : (
                          <div className="space-y-1">
                            {deviations.map((dev) => (
                              <div
                                key={`${dev.feature}-${dev.value}`}
                                className="text-[11px] font-mono leading-tight bg-muted/40 rounded px-1.5 py-0.5"
                              >
                                <span className="font-semibold text-foreground">
                                  {dev.feature}:
                                </span>{" "}
                                <span className="text-rose-600 font-bold">
                                  {dev.value}
                                </span>{" "}
                                <span className="text-muted-foreground text-[10px]">
                                  (p50: {dev.benign_median}, {dev.bracket})
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
