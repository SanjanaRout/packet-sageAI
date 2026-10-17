export interface UploadResponse {
  upload_id: string;
  total_rows: number;
  valid_rows: number;
  invalid_rows: number;
  malformed_rows?: number;
  incomplete_rows?: number;
  nan_inf_sanitized_records?: number;
  suspicious_rows: number;
  unusual_rows: number;
  warnings: string[];
  incident_count: number;
  time_shift_applied?: boolean;
}

export interface StatisticalDeviation {
  feature: string;
  value: number;
  benign_median: number;
  bracket: string;
  z_score?: number;
  is_extreme?: boolean;
  extremity_weight?: number;
  disclaimer: string;
}

export interface FlowRecord {
  flow_id: number;
  upload_id: string;
  row_index: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  ts?: string | null;
  score?: number | null;
  label: string;
  unusual: boolean;
  incident_id?: string | null;
  deviations?: StatisticalDeviation[];
}

export interface IncidentResponse {
  incident_id: string;
  upload_id: string;
  kinds: string[];
  start: string;
  end: string;
  flow_count: number;
  max_score: number;
  src_ips: string[];
  dst_ips: string[];
  reasons: string[];
  flow_ids: number[];
  status: string;
  time_shift_applied: boolean;
  created_at: string;
}

export interface AnalystFeedbackEntry {
  decision: string;
  note: string;
  timestamp: string;
  analyst_id?: string | null;
  analyst_name?: string | null;
}

export interface AnalystFeedbackHistory {
  current_status: string;
  latest_decision?: string | null;
  feedback_entries: AnalystFeedbackEntry[];
}

export interface IncidentDetailResponse extends IncidentResponse {
  flows: FlowRecord[];
  total_flows: number;
  skip: number;
  limit: number;
  feedback: AnalystFeedbackEntry[];
}

export interface ObservedFacts {
  time_window: string;
  time_shift_applied: boolean;
  time_metadata_note: string;
  src_ips: string[];
  dst_ips: string[];
  dst_ports: number[];
  flow_count: number;
  rules_triggered: string[];
  reasons: string[];
  score_min: number;
  score_max: number;
  top_feature_deviations: StatisticalDeviation[];
}

export interface SupportingEvidenceFlow {
  flow_id: number;
  ts?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  score?: number | null;
  label?: string | null;
  unusual?: boolean;
  deviations: StatisticalDeviation[];
}

export interface IncidentReportResponse {
  incident_id: string;
  upload_id: string;
  generated_at: string;
  executive_summary: string;
  observed_facts: ObservedFacts;
  supporting_evidence: SupportingEvidenceFlow[];
  hypotheses_and_uncertainties: string[];
  recommended_next_steps: string[];
  analyst_feedback_history: AnalystFeedbackHistory;
  markdown_report?: string | null;
}

export interface ModelMetricsResponse {
  model_name: string;
  features_count: number;
  decision_threshold: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  novelty_threshold: number;
  sklearn_version?: string | null;
}

export interface IsolatedFlowsResponse {
  upload_id: string;
  flow_ids: number[];
  total_count: number;
}

export interface FeedbackRequest {
  decision: "confirmed" | "incorrect" | "inconclusive";
  note: string;
  analyst_id?: string;
  name?: string;
}

export interface FeedbackResponse {
  incident_id: string;
  decision: string;
  note: string;
  timestamp: string;
  feedback_count: number;
  analyst_id?: string | null;
  analyst_name?: string | null;
}

export interface AskIncidentRequest {
  question?: string;
}

export interface AskIncidentResponse {
  answer: string;
  cited_flow_ids: number[];
  invalid_citations: number[];
  provider: string;
  model: string;
}
