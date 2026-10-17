# PacketSage AI Backend

PacketSage AI is a network flow analysis and incident correlation assistant that combines supervised machine learning, unsupervised novelty detection, graph-based correlation rules, and a GenAI assistant grounded in verified network flow evidence.

## Architecture

- **Flow Service**: Streaming CSV parser enforcing upload limits, RFC 5952 / IP validation using Python's `ipaddress` module, port validation (0-65535), and synchronous batch scoring via threadpools.
- **Model Service**: Random Forest classifier (78 CIC-IDS features) with a supervised threshold and an Isolation Forest novelty detector.
- **Correlation Engine**: Vectorized multi-flow correlation identifying port scans, fan-in patterns, and suspicious bursts, merging incident graphs via an inverted index.
- **GenAI Assistant Service**: Evidence-grounded synthesis with strict flow citations (`[flow <id>]`), prompt injection sanitization, analyst feedback persistence, and pluggable LLM provider support (OpenAI-compatible and Anthropic).

## Timestamp Candidates & Format Handling

During correlation, timestamps are parsed against the following candidate format order:
1. `"%d/%m/%Y %H:%M:%S"`
2. `"%d/%m/%Y %H:%M"`
3. `"%d/%m/%Y %I:%M:%S %p"`
4. `"%Y-%m-%d %H:%M:%S"` (ISO format)

> [!NOTE]
> Timestamp formats are currently unverified against real TrafficLabelling files and may require additional candidate patterns depending on the capture environment.

## Known Limitations

- **Timestamps lack AM/PM**: CIC-IDS2017 timestamps record time without AM/PM tags (e.g. `7/7/2017 2:51` for an afternoon capture). The `ASSUME_NO_AMPM_BUSINESS_HOURS` configuration provides a 12-hour forward shift for hours 1..7 as a heuristic; however, mixed captures without unambiguous AM/PM indicators cannot be distinguished deterministically from metadata alone.
- **Fixed 60s Bins & Minute Resolution**: The port-scan rule uses fixed 60-second tumbling time bins. Because CIC-IDS2017 timestamps only possess minute-level resolution (seconds are not recorded), implementing a sliding window would not provide sub-minute granularity or improve precision.
- **Reversed Direction Flows**: Flow exporters like CICFlowMeter can record flows with reversed client/server source and destination roles. When external servers return traffic to varied client ephemeral ports (>= 32768), this can be misinterpreted by naive port-scan rules as outbound scanning activity.
- **Lab Evaluation Scope**: Incident correlation was evaluated against a small set of traffic windows with CIC-IDS2017 ground-truth labels and represents lab evidence only. Production deployments require tuning thresholds against target network baselines.
- **Training Dataset Quality & Generalization**: The underlying machine learning model was trained on CIC-IDS2017, a benchmark dataset with well-documented artifacts and quality issues. Standard random-split metrics are optimistic; the leave-one-family-out cross-validation results provide the realistic estimate of out-of-distribution generalization.
- **Novelty Flags as Leads**: The Isolation Forest detector flags statistical deviations (`unusual=yes`) from training distributions. Novelty detections are investigative leads for human triage, not standalone threat alerts.

## Privacy & Data Use Notice

- **Assistant LLM Communications**: Calling `POST /api/v1/incidents/{id}/ask` transmits flow summary metadata (source IP, destination IP, destination port, timestamp, model score, novelty flag) and analyst feedback notes to the configured third-party LLM provider(s) (Gemini, Groq, Mistral).
- **Data Protection**: Do not submit sensitive, classified, or PII-containing network traces without verifying each provider's data handling and retention policies.
- **No Raw Feature Vectors**: The assistant prompt builder transmits *only* the aforementioned flow metadata fields, incident summary, and analyst feedback. Raw 78-dimensional feature vectors are **never** transmitted to the LLM.

## Credential Security & Redaction

- **Zero Key Leaks**: All provider API keys (`GEMINI_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `LLM_API_KEY`) are stripped and redacted via `_sanitize_error()` before logging.
- **Generic Responses**: Provider error responses returned to clients never contain upstream vendor response bodies, raw error dumps, or credentials (verified in test `test_manager_all_providers_failed_generic_error_and_key_redaction`).

## Evaluation Results & Recommended Settings

> [!NOTE]
> All metrics and evaluations below were derived from three Friday capture windows of the CIC-IDS2017 TrafficLabelling dataset using ground-truth labels for lab evaluation and verification only.

### 1. Extended Destination Port Thresholds (`SCAN_MAX_DST_PORT`)

Evaluated on `portscan_slice.csv` (30,000 rows, 7 PortScan flows, false-positive test) and `portscan_window_dense.csv` (30,000 rows, 29,689 PortScan flows, scan detection test):

| Evaluation Window | `SCAN_MAX_DST_PORT` | PortScan Incidents | Zero-Attack Incidents (FP) | PortScan Ground-Truth Flow Coverage |
| :--- | :--- | :--- | :--- | :--- |
| `portscan_slice.csv` | `None` (default) | 4 | 4 (100% FP) | 4 / 7 (57.14%) |
| `portscan_slice.csv` | `1024` | 0 | 0 | 4 / 7 (57.14%) |
| `portscan_slice.csv` | `10000` | 0 | 0 | 4 / 7 (57.14%) |
| `portscan_slice.csv` | `32768` | 0 | 0 | 4 / 7 (57.14%) |
| `portscan_slice.csv` | `49152` | 0 | 0 | 4 / 7 (57.14%) |
| `portscan_window_dense.csv` | `None` (default) | 2 | 1 (50% FP) | 29,689 / 29,689 (100.00%) |
| `portscan_window_dense.csv` | `1024` | 1 | 0 | 29,689 / 29,689 (100.00%) |
| `portscan_window_dense.csv` | `10000` | 1 | 0 | 29,689 / 29,689 (100.00%) |
| `portscan_window_dense.csv` | `32768` | 1 | 0 | 29,689 / 29,689 (100.00%) |
| `portscan_window_dense.csv` | `49152` | 1 | 0 | 29,689 / 29,689 (100.00%) |

### 2. Classifier-Blind Correlation Check

Forcing every flow's label to `"benign"` prior to correlation to evaluate structural heuristic rules independently of ML classification:

| Dataset Window | Attack Type | Ground-Truth Attack Flows | Flows Covered in Incidents (Classifier-Blind) | Coverage Ratio |
| :--- | :--- | :--- | :--- | :--- |
| `portscan_window_dense.csv` | PortScan | 29,689 | 29,689 | 100.00% |
| `sample_real_flows.csv` | PortScan | 700 | 657 | 93.86% |
| `sample_real_flows.csv` | DDoS | 700 | 0 | 0.00% |
| `sample_real_flows.csv` | Bot | 700 | 0 | 0.00% |

*Key finding: Structural port-scan detection operates robustly without machine learning labels (100% of dense scan and 93.86% of sample port scan flows captured). Distributed low-rate attacks (DDoS and Bot) depend on supervised classification (`suspicious_burst`).*

### 3. Isolated Flows Evaluation (`ISOLATED_FLOW_MAX=2` vs Baseline `ISOLATED_FLOW_MAX=0`)

Suppresses small bursts ($\le 2$ flows) into an `isolated_flagged_flows` list on the upload document rather than generating incident clutter:

| Dataset Window | Setting | Incidents Formed | Isolated Flows | Bot Coverage (Inc / Comb) | DDoS Coverage (Inc / Comb) | PortScan Coverage (Inc / Comb) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `sample_real_flows.csv` | Baseline (`0`) | 45 | 0 | 97.71% / 97.71% | 100.00% / 100.00% | 100.00% / 100.00% |
| `sample_real_flows.csv` | `ISOLATED_FLOW_MAX=2` | 29 (-35.6%) | 18 | 97.71% / 99.29% | 100.00% / 100.00% | 99.71% / 100.00% |
| `portscan_slice.csv` | Baseline (`0`) | 25 | 0 | N/A | N/A | 57.14% / 57.14% |
| `portscan_slice.csv` | `ISOLATED_FLOW_MAX=2` | 14 (-44.0%) | 12 | N/A | N/A | 57.14% / 57.14% |
| `portscan_window_dense.csv` | Baseline (`0`) | 7 | 0 | N/A | N/A | 100.00% / 100.00% |
| `portscan_window_dense.csv` | `ISOLATED_FLOW_MAX=2` | 2 (-71.4%) | 5 | N/A | N/A | 100.00% / 100.00% |

### 4. Recommended Operational Settings

| Parameter | Recommended Setting | Default in Config | Rationale (Based on Friday Evaluation Windows) |
| :--- | :--- | :--- | :--- |
| `SCAN_MAX_DST_PORT` | `32768` | `None` | Filters destination ports in dynamic/ephemeral range ($\ge 32768$), eliminating 100% of false-positive scans on benign return traffic while preserving 100% of real scans. *(Chosen on Friday windows only)*. |
| `ISOLATED_FLOW_MAX` | `2` | `2` | Replaces single/double-flow false alarm incidents with an isolated flagged flows tracking list, reducing noise incidents by 35%–71% while retaining 99.29%–100% total attack coverage. |
| `SCAN_MIN_PORTS` | `20` | `20` | Reliably catches dense scanning activity within 60s tumbling windows. |
| `MIN_BURST_FLOWS` | `1` | `1` | Kept at 1 as baseline; small bursts are safely routed to `isolated_flagged_flows` by `ISOLATED_FLOW_MAX`. |
| `assume_pm_business_hours` | per-upload option | `False` | Resolves 12-hour clock ambiguities for afternoon captures (hours 1..7) without shifting ambiguous or morning captures. |

