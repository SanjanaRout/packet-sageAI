"use client";

import { History, MessageSquare, Send } from "lucide-react";
import { useState } from "react";

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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { recordFeedback } from "@/lib/api";
import type { AnalystFeedbackEntry } from "@/types/api";

interface AnalystFeedbackSectionProps {
  incidentId: string;
  currentStatus: string;
  feedbackHistory: AnalystFeedbackEntry[];
  onFeedbackSaved: () => void;
}

export function AnalystFeedbackSection({
  incidentId,
  currentStatus,
  feedbackHistory,
  onFeedbackSaved,
}: AnalystFeedbackSectionProps) {
  const [decision, setDecision] = useState<
    "confirmed" | "incorrect" | "inconclusive"
  >("confirmed");
  const [analystName, setAnalystName] = useState<string>("");
  const [note, setNote] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!note.trim()) {
      setMessage({
        type: "error",
        text: "Please enter triage notes/rationale.",
      });
      return;
    }

    setIsSubmitting(true);
    setMessage(null);

    try {
      await recordFeedback(incidentId, {
        decision,
        name: analystName.trim() || undefined,
        note: note.trim(),
      });
      setMessage({
        type: "success",
        text: "Feedback recorded. Incident status updated.",
      });
      setNote("");
      onFeedbackSaved();
    } catch (err: unknown) {
      const errText =
        err instanceof Error ? err.message : "Failed to record feedback";
      setMessage({ type: "error", text: errText });
    } finally {
      setIsSubmitting(false);
    }
  };

  const getDecisionBadge = (dec: string) => {
    switch (dec.toLowerCase()) {
      case "confirmed":
        return (
          <Badge className="bg-rose-600 text-white text-[10px]">
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
            {dec}
          </Badge>
        );
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="h-5 w-5 text-primary" />
            <div>
              <CardTitle className="text-base font-semibold">
                Analyst Decision & Triage Feedback
              </CardTitle>
              <CardDescription className="text-xs">
                Record human-in-the-loop investigation determinations to guide
                alert disposition
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">
              Current Status:
            </span>
            {getDecisionBadge(currentStatus)}
          </div>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-6 space-y-4">
        {/* Feedback Input Form */}
        <form
          onSubmit={handleSubmit}
          className="rounded-lg border p-3.5 bg-muted/20 space-y-3"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label
                htmlFor="triage-decision-select"
                className="text-xs font-medium text-foreground block"
              >
                Triage Decision
              </label>
              <Select
                value={decision}
                onValueChange={(val) =>
                  setDecision(val as "confirmed" | "incorrect" | "inconclusive")
                }
              >
                <SelectTrigger
                  id="triage-decision-select"
                  className="text-xs h-9 bg-background"
                >
                  <SelectValue placeholder="Select decision" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="confirmed" className="text-xs">
                    Confirmed Threat (Malicious / Recon)
                  </SelectItem>
                  <SelectItem value="incorrect" className="text-xs">
                    Incorrect / False Positive (Benign Traffic)
                  </SelectItem>
                  <SelectItem value="inconclusive" className="text-xs">
                    Inconclusive (Requires Further PCAP / External Logs)
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1">
              <label
                htmlFor="analyst-name-input"
                className="text-xs font-medium text-foreground block"
              >
                Analyst Name / ID (Optional)
              </label>
              <input
                id="analyst-name-input"
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                placeholder="e.g. Alex Triage, SOC-Tier2"
                className="w-full text-xs h-9 px-3 rounded-md border border-input bg-background text-foreground"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label
              htmlFor="analyst-note-textarea"
              className="text-xs font-medium text-foreground block"
            >
              Analyst Observations & Rationale
            </label>
            <Textarea
              id="analyst-note-textarea"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Record forensic observations, scan pattern confirmation, firewall log correlations, or host justification..."
              rows={3}
              className="text-xs resize-none bg-background"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            {message ? (
              <span
                className={`text-xs font-medium ${
                  message.type === "success"
                    ? "text-emerald-600"
                    : "text-rose-600"
                }`}
              >
                {message.text}
              </span>
            ) : (
              <span className="text-[11px] text-muted-foreground">
                Decisions are persisted into append-only MongoDB audit logs.
              </span>
            )}

            <Button
              type="submit"
              size="sm"
              disabled={isSubmitting || !note.trim()}
              className="text-xs h-8 gap-1.5 px-3"
            >
              <Send className="h-3.5 w-3.5" />
              {isSubmitting ? "Recording..." : "Submit Feedback"}
            </Button>
          </div>
        </form>

        {/* Feedback History Table */}
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <History className="h-3.5 w-3.5" />
            Decision Audit History ({feedbackHistory.length} entry/entries):
          </div>

          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40">
                  <TableHead className="text-xs w-[150px]">
                    Timestamp (UTC)
                  </TableHead>
                  <TableHead className="text-xs w-[130px]">Decision</TableHead>
                  <TableHead className="text-xs w-[130px]">Analyst</TableHead>
                  <TableHead className="text-xs">Notes & Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {feedbackHistory.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      className="text-center text-xs py-4 text-muted-foreground"
                    >
                      No analyst feedback recorded yet for this incident.
                    </TableCell>
                  </TableRow>
                ) : (
                  feedbackHistory.map((item) => (
                    <TableRow
                      key={`${item.timestamp}-${item.decision}-${item.analyst_id || ""}`}
                      className="hover:bg-muted/20"
                    >
                      <TableCell className="text-xs font-mono text-muted-foreground whitespace-nowrap">
                        {item.timestamp
                          ? new Date(item.timestamp).toUTCString()
                          : "—"}
                      </TableCell>
                      <TableCell>{getDecisionBadge(item.decision)}</TableCell>
                      <TableCell className="text-xs font-medium">
                        {item.analyst_name || item.analyst_id || "Anonymous"}
                      </TableCell>
                      <TableCell className="text-xs leading-relaxed">
                        {item.note}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
