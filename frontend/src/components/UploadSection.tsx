"use client";

import { AlertCircle, FileUp, HelpCircle, UploadCloud } from "lucide-react";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { uploadFlows } from "@/lib/api";
import type { UploadResponse } from "@/types/api";

interface UploadSectionProps {
  onUploadSuccess: (upload: UploadResponse) => void;
}

export function UploadSection({ onUploadSuccess }: UploadSectionProps) {
  const [file, setFile] = useState<File | null>(null);
  const [assumePmShift, setAssumePmShift] = useState<boolean>(true);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError("Please select a network flow CSV file to upload.");
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const result = await uploadFlows(file, assumePmShift);
      onUploadSuccess(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to upload file";
      setError(message);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4 sm:px-6">
        <div className="flex items-center gap-2">
          <UploadCloud className="h-5 w-5 text-primary" />
          <div>
            <CardTitle className="text-base font-semibold">
              Upload Network Flows CSV
            </CardTitle>
            <CardDescription className="text-xs">
              Upload CIC-IDS2017 format NetFlow CSV for anomaly scoring and rule
              correlation
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
            <div className="relative flex-1 w-full">
              <input
                id="flow-csv-input"
                type="file"
                accept=".csv"
                onChange={handleFileChange}
                disabled={isUploading}
                className="block w-full text-xs text-muted-foreground file:mr-3 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-primary file:text-primary-foreground hover:file:bg-primary/90 cursor-pointer border border-input rounded-md px-2 py-1.5 bg-background"
              />
            </div>
            <Button
              type="submit"
              disabled={!file || isUploading}
              size="sm"
              className="w-full sm:w-auto text-xs gap-1.5 h-9 px-4"
            >
              <FileUp className="h-4 w-4" />
              {isUploading ? "Processing & Scoring..." : "Upload & Analyze"}
            </Button>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3 bg-muted/40">
            <div className="space-y-0.5">
              <div className="flex items-center gap-1.5 text-xs font-medium">
                <span>Assume 12-Hour PM Clock (Hours 1..7)</span>
                <Tooltip>
                  <TooltipTrigger className="text-muted-foreground hover:text-foreground inline-flex items-center cursor-help">
                    <HelpCircle className="h-3.5 w-3.5" />
                  </TooltipTrigger>
                  <TooltipContent side="right" className="max-w-xs text-xs">
                    CIC-IDS2017 and similar datasets record timestamps like
                    &quot;7/7/2017 2:51&quot; without AM/PM tags. When enabled,
                    hours 1 through 7 are automatically shifted forward by 12
                    hours (e.g. 2:51 becomes 14:51) to correctly match afternoon
                    capture windows.
                  </TooltipContent>
                </Tooltip>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Recommended for afternoon capture slices to avoid time-bin
                misalignment.
              </p>
            </div>
            <Switch
              checked={assumePmShift}
              onCheckedChange={setAssumePmShift}
              disabled={isUploading}
            />
          </div>

          {error && (
            <Alert variant="destructive" className="py-2 px-3 text-xs">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle className="text-xs font-semibold">
                Upload Error
              </AlertTitle>
              <AlertDescription className="text-xs">{error}</AlertDescription>
            </Alert>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
