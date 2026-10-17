"use client";

import { Clock, ExternalLink, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import type { IncidentResponse } from "@/types/api";

interface IncidentListProps {
  incidents: IncidentResponse[];
  selectedIncidentId: string | null;
  onSelectIncident: (incidentId: string) => void;
}

export function IncidentList({
  incidents,
  selectedIncidentId,
  onSelectIncident,
}: IncidentListProps) {
  if (incidents.length === 0) {
    return (
      <Card className="border-border">
        <CardContent className="p-8 text-center text-sm text-muted-foreground">
          No correlated incidents formed for this upload session. All flows were
          either benign or filtered as isolated bursts.
        </CardContent>
      </Card>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case "confirmed":
        return (
          <Badge className="bg-rose-600 text-white hover:bg-rose-700 text-[10px]">
            Confirmed Threat
          </Badge>
        );
      case "incorrect":
        return (
          <Badge variant="secondary" className="text-[10px]">
            False Positive
          </Badge>
        );
      case "inconclusive":
        return (
          <Badge
            variant="outline"
            className="text-[10px] text-amber-600 border-amber-300"
          >
            Inconclusive
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="text-[10px]">
            Open Triage
          </Badge>
        );
    }
  };

  const getKindBadge = (kind: string) => {
    switch (kind.toLowerCase()) {
      case "port_scan":
        return (
          <Badge
            key={kind}
            variant="destructive"
            className="text-[10px] py-0 px-1.5 uppercase font-mono"
          >
            port_scan
          </Badge>
        );
      case "fan_in":
        return (
          <Badge
            key={kind}
            className="bg-orange-600 text-white text-[10px] py-0 px-1.5 uppercase font-mono"
          >
            fan_in
          </Badge>
        );
      default:
        return (
          <Badge
            key={kind}
            variant="secondary"
            className="text-[10px] py-0 px-1.5 uppercase font-mono"
          >
            {kind}
          </Badge>
        );
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-rose-600" />
            <div>
              <CardTitle className="text-base font-semibold">
                Correlated Incidents ({incidents.length})
              </CardTitle>
              <CardDescription className="text-xs">
                Select an incident to investigate flow evidence, feature
                deviations, and generate reports
              </CardDescription>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40">
                <TableHead className="text-xs w-[140px]">Incident ID</TableHead>
                <TableHead className="text-xs">Category</TableHead>
                <TableHead className="text-xs text-right">Flows</TableHead>
                <TableHead className="text-xs text-right">Max Score</TableHead>
                <TableHead className="text-xs">Source IP(s)</TableHead>
                <TableHead className="text-xs">Target IP(s)</TableHead>
                <TableHead className="text-xs">Clock Shift</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {incidents.map((inc) => {
                const isSelected = inc.incident_id === selectedIncidentId;
                return (
                  <TableRow
                    key={inc.incident_id}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-accent/60" : "hover:bg-muted/30"
                    }`}
                    onClick={() => onSelectIncident(inc.incident_id)}
                  >
                    <TableCell className="font-mono text-xs font-semibold">
                      {inc.incident_id}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {inc.kinds.map(getKindBadge)}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-right font-mono font-medium">
                      {inc.flow_count.toLocaleString()}
                    </TableCell>
                    <TableCell className="text-xs text-right font-mono font-bold text-rose-600">
                      {inc.max_score.toFixed(4)}
                    </TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground truncate max-w-[140px]">
                      {inc.src_ips.join(", ") || "N/A"}
                    </TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground truncate max-w-[140px]">
                      {inc.dst_ips.join(", ") || "N/A"}
                    </TableCell>
                    <TableCell>
                      {inc.time_shift_applied ? (
                        <Badge
                          variant="outline"
                          className="text-[10px] py-0 px-1.5 gap-1 bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-300"
                        >
                          <Clock className="h-2.5 w-2.5" />
                          +12h Shifted
                        </Badge>
                      ) : (
                        <span className="text-[11px] text-muted-foreground">
                          —
                        </span>
                      )}
                    </TableCell>
                    <TableCell>{getStatusBadge(inc.status)}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant={isSelected ? "default" : "outline"}
                        size="sm"
                        className="h-7 text-xs gap-1"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(inc.incident_id);
                        }}
                      >
                        Inspect
                        <ExternalLink className="h-3 w-3" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
