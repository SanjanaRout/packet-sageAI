"use client";

import { Activity, AlertTriangle, Info, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { getModelMetrics } from "@/lib/api";
import type { ModelMetricsResponse } from "@/types/api";

export function ModelMetricsCard() {
  const [metrics, setMetrics] = useState<ModelMetricsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    getModelMetrics()
      .then((data) => {
        if (mounted) {
          setMetrics(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err.message || "Failed to load model metrics");
        }
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  if (loading && !metrics) {
    return (
      <Card className="border-border">
        <CardContent className="p-4 text-xs text-muted-foreground flex items-center gap-2">
          <Activity className="h-4 w-4 animate-spin" />
          Loading model evaluation metrics...
        </CardContent>
      </Card>
    );
  }

  if (error || !metrics) {
    return (
      <Card className="border-amber-200 bg-amber-50/50 dark:bg-amber-950/20">
        <CardContent className="p-4 text-xs text-amber-800 dark:text-amber-300 flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4" />
            Model metrics offline ({error || "unreachable"}). Backend will use
            default threshold 0.127.
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => window.location.reload()}
          >
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
            <div>
              <CardTitle className="text-base font-semibold">
                Supervised Model Reliability & Decision Threshold
              </CardTitle>
              <CardDescription className="text-xs">
                Evaluated against CIC-IDS2017 TrafficLabelling benchmark split
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className="text-xs bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300"
            >
              Active Threshold: {metrics.decision_threshold.toFixed(4)}
            </Badge>

            <Dialog>
              <DialogTrigger className="inline-flex items-center justify-center gap-1 h-7 px-2.5 rounded-md border border-input bg-background hover:bg-muted text-xs font-medium cursor-pointer">
                <Info className="h-3.5 w-3.5" />
                Details
              </DialogTrigger>
              <DialogContent className="sm:max-w-md">
                <DialogHeader>
                  <DialogTitle className="text-base">
                    Classifier Evaluation Specifications
                  </DialogTitle>
                  <DialogDescription className="text-xs">
                    Model architecture and validation breakdown on CIC-IDS2017
                    dataset.
                  </DialogDescription>
                </DialogHeader>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Model Architecture
                      </TableCell>
                      <TableCell className="text-right text-xs">
                        {metrics.model_name}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Features Count
                      </TableCell>
                      <TableCell className="text-right text-xs">
                        {metrics.features_count} numeric features
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Supervised Threshold
                      </TableCell>
                      <TableCell className="text-right text-xs">
                        {metrics.decision_threshold.toFixed(4)}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Novelty Threshold (Isolation Forest)
                      </TableCell>
                      <TableCell className="text-right text-xs">
                        {metrics.novelty_threshold.toFixed(4)}
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Precision
                      </TableCell>
                      <TableCell className="text-right text-xs font-semibold text-emerald-600">
                        {(metrics.precision * 100).toFixed(2)}%
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        Recall
                      </TableCell>
                      <TableCell className="text-right text-xs font-semibold text-emerald-600">
                        {(metrics.recall * 100).toFixed(2)}%
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        F1 Score
                      </TableCell>
                      <TableCell className="text-right text-xs font-semibold text-emerald-600">
                        {(metrics.f1_score * 100).toFixed(2)}%
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell className="font-medium text-xs">
                        False Positive Rate (FPR)
                      </TableCell>
                      <TableCell className="text-right text-xs font-semibold text-zinc-600 dark:text-zinc-400">
                        {(metrics.false_positive_rate * 100).toFixed(2)}%
                      </TableCell>
                    </TableRow>
                    {metrics.sklearn_version && (
                      <TableRow>
                        <TableCell className="font-medium text-xs">
                          scikit-learn Version
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {metrics.sklearn_version}
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              Precision
            </div>
            <div className="mt-0.5 text-lg font-bold text-emerald-600 dark:text-emerald-400">
              {(metrics.precision * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-muted-foreground">
              TP / (TP + FP)
            </div>
          </div>
          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              Recall
            </div>
            <div className="mt-0.5 text-lg font-bold text-emerald-600 dark:text-emerald-400">
              {(metrics.recall * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-muted-foreground">
              TP / (TP + FN)
            </div>
          </div>
          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              F1 Score
            </div>
            <div className="mt-0.5 text-lg font-bold text-emerald-600 dark:text-emerald-400">
              {(metrics.f1_score * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-muted-foreground">
              Harmonic Mean
            </div>
          </div>
          <div className="rounded-lg border bg-card p-2.5">
            <div className="text-[11px] font-medium text-muted-foreground">
              False Positive Rate
            </div>
            <div className="mt-0.5 text-lg font-bold text-foreground">
              {(metrics.false_positive_rate * 100).toFixed(2)}%
            </div>
            <div className="text-[10px] text-muted-foreground">
              FP / (FP + TN)
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
