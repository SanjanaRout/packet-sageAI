import type {
  AskIncidentRequest,
  AskIncidentResponse,
  FeedbackRequest,
  FeedbackResponse,
  IncidentDetailResponse,
  IncidentReportResponse,
  IncidentResponse,
  IsolatedFlowsResponse,
  ModelMetricsResponse,
  UploadResponse,
} from "@/types/api";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `Request failed with status ${res.status}`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") {
        errorDetail = data.detail;
      } else if (data.detail && typeof data.detail === "object") {
        errorDetail = JSON.stringify(data.detail);
      }
    } catch {
      // Non-JSON error body
    }
    throw new Error(errorDetail);
  }
  return res.json() as Promise<T>;
}

export async function uploadFlows(
  file: File,
  assumePmShift: boolean = true,
): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("assume_pm_business_hours", String(assumePmShift));

  const res = await fetch(`${API_BASE}/flows/upload`, {
    method: "POST",
    body: formData,
  });
  return handleResponse<UploadResponse>(res);
}

export async function getUploadSummary(
  uploadId: string,
): Promise<UploadResponse> {
  const res = await fetch(`${API_BASE}/uploads/${uploadId}`);
  return handleResponse<UploadResponse>(res);
}

export async function getModelMetrics(): Promise<ModelMetricsResponse> {
  const res = await fetch(`${API_BASE}/model/metrics`);
  return handleResponse<ModelMetricsResponse>(res);
}

export async function getIncidents(
  uploadId?: string,
): Promise<IncidentResponse[]> {
  const url = uploadId
    ? `${API_BASE}/incidents/?upload_id=${encodeURIComponent(uploadId)}`
    : `${API_BASE}/incidents/`;
  const res = await fetch(url);
  return handleResponse<IncidentResponse[]>(res);
}

export async function getIsolatedFlows(
  uploadId: string,
): Promise<IsolatedFlowsResponse> {
  const res = await fetch(
    `${API_BASE}/incidents/isolated?upload_id=${encodeURIComponent(uploadId)}`,
  );
  return handleResponse<IsolatedFlowsResponse>(res);
}

export async function getIncidentDetail(
  incidentId: string,
  skip = 0,
  limit = 200,
): Promise<IncidentDetailResponse> {
  const res = await fetch(
    `${API_BASE}/incidents/${encodeURIComponent(incidentId)}?skip=${skip}&limit=${limit}`,
  );
  return handleResponse<IncidentDetailResponse>(res);
}

export async function recordFeedback(
  incidentId: string,
  payload: FeedbackRequest,
): Promise<FeedbackResponse> {
  const res = await fetch(
    `${API_BASE}/incidents/${encodeURIComponent(incidentId)}/feedback`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return handleResponse<FeedbackResponse>(res);
}

export async function getIncidentReport(
  incidentId: string,
): Promise<IncidentReportResponse> {
  const res = await fetch(
    `${API_BASE}/incidents/${encodeURIComponent(incidentId)}/report?format=json`,
  );
  return handleResponse<IncidentReportResponse>(res);
}

export async function fetchMarkdownReportText(
  incidentId: string,
): Promise<string> {
  const res = await fetch(
    `${API_BASE}/incidents/${encodeURIComponent(incidentId)}/report?format=markdown`,
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch markdown report: status ${res.status}`);
  }
  return res.text();
}

export async function askIncident(
  incidentId: string,
  payload: AskIncidentRequest = {},
): Promise<AskIncidentResponse> {
  const res = await fetch(
    `${API_BASE}/incidents/${encodeURIComponent(incidentId)}/ask`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  return handleResponse<AskIncidentResponse>(res);
}
