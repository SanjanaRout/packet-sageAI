"use client";

import { Network, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { IncidentDetailView } from "@/components/IncidentDetailView";
import { IncidentList } from "@/components/IncidentList";
import { IngestionSummaryCard } from "@/components/IngestionSummaryCard";
import { IsolatedFlowsCard } from "@/components/IsolatedFlowsCard";
import { ModelMetricsCard } from "@/components/ModelMetricsCard";
import { UploadSection } from "@/components/UploadSection";
import { Badge } from "@/components/ui/badge";
import { getIncidents } from "@/lib/api";
import type { IncidentResponse, UploadResponse } from "@/types/api";

export default function Home() {
  const [currentUpload, setCurrentUpload] = useState<UploadResponse | null>(
    null,
  );
  const [incidents, setIncidents] = useState<IncidentResponse[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(
    null,
  );
  const [loadingIncidents, setLoadingIncidents] = useState<boolean>(false);

  const fetchIncidentsForUpload = useCallback(async (uploadId?: string) => {
    setLoadingIncidents(true);
    try {
      const data = await getIncidents(uploadId);
      setIncidents(data);
    } catch {
      setIncidents([]);
    } finally {
      setLoadingIncidents(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch of any existing incidents in database
    fetchIncidentsForUpload();
  }, [fetchIncidentsForUpload]);

  const handleUploadSuccess = (upload: UploadResponse) => {
    setCurrentUpload(upload);
    setSelectedIncidentId(null);
    fetchIncidentsForUpload(upload.upload_id);
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b bg-card sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-primary text-primary-foreground">
              <Network className="h-5 w-5" />
            </div>
            <div>
              <span className="font-bold text-sm tracking-tight">
                PacketSage AI
              </span>
              <span className="hidden sm:inline-block ml-2 text-xs text-muted-foreground border-l pl-2">
                Network Flow & Incident Correlation
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[11px] gap-1 font-mono">
              <ShieldCheck className="h-3 w-3 text-emerald-600" />
              v1.0 (Friday Baselines)
            </Badge>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 flex-1 w-full space-y-6">
        {/* Model Metrics Reliability Card */}
        <ModelMetricsCard />

        {/* Upload Section */}
        <UploadSection onUploadSuccess={handleUploadSuccess} />

        {/* Ingestion Quality & Sanitation Summary */}
        {currentUpload && <IngestionSummaryCard upload={currentUpload} />}

        {/* Isolated Flagged Flows (1-2 flow bursts) */}
        {currentUpload && (
          <IsolatedFlowsCard uploadId={currentUpload.upload_id} />
        )}

        {/* Incidents View or Detail View */}
        {selectedIncidentId ? (
          <IncidentDetailView
            incidentId={selectedIncidentId}
            onBack={() => setSelectedIncidentId(null)}
          />
        ) : (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold tracking-tight text-foreground">
                {currentUpload
                  ? `Incidents for Upload ${currentUpload.upload_id}`
                  : "Recent Flagged Incidents"}
              </h3>
              {loadingIncidents && (
                <span className="text-xs text-muted-foreground animate-pulse">
                  Updating incidents...
                </span>
              )}
            </div>
            <IncidentList
              incidents={incidents}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t py-4 text-center text-xs text-muted-foreground bg-card">
        PacketSage AI • Evidence-Grounded SOC Incident Investigation •
        CIC-IDS2017 Benchmark Evaluation
      </footer>
    </div>
  );
}
