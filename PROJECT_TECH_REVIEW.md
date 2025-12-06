## 1) Executive Summary (Cập nhật)

Dự án cung cấp pipeline phát hiện bất thường log an ninh mạng, từ ingest đa nguồn (Windows/Sysmon/Zeek/Syslog/FortiGate/IPS/Beats hoặc Elasticsearch), chuẩn hóa ECS, tạo đặc trưng mạng + đăng nhập, huấn luyện và chấm điểm Isolation Forest, chọn alert, giải thích SHAP, ánh xạ MITRE ATT&CK tự động, đóng gói forensic bundle, và hiển thị qua UI Streamlit. AI Agent (DeepSeek/Gemini/stub) phân tích, gợi ý hành động và ghi MITRE vào bundle/UI.


## 2) Kiến trúc tổng quan

```
Log Sources (files/UDP/Elasticsearch)
    → Ingest + ECS Normalize (parsers/*, ecs_mapper)
    → Parquet Store (data/ecs_parquet/…)
    → Feature Engineering (features/*)
    → Modeling (Isolation Forest)
    → Scoring (scores.parquet)
    → Alerting (threshold + top-N)
    → Explainability (SHAP)
    → MITRE Mapping (ai/mitre_mapper.py)
    → Forensic Bundle (pipeline/bundle.py)
    → UI/AI Analysis (Streamlit + AI Agent)
```

- Config: `config/models.yaml`, `config/paths.yaml`, `config/ecs_mapping.yaml`, `config/mitre_mapping.yaml`.
- Alerting: ngưỡng quantile (1 - contamination), top-N.
- Bundle: raw ±5m, features, SHAP, model_meta, AI+MITRE, manifest.
- UI: timeline, drop/allow chart, IPS table, alert table + MITRE filters, bundle/AI viewer.


## 3) Cấu trúc thư mục & vai trò

- `config/`: YAML cấu hình
  - `paths.yaml`: đường dẫn data/models/scores/bundles, Elastic host/index patterns, cổng syslog FortiGate (5514)/IPS (514)/Beats (5044).
  - `models.yaml`: hyperparams Isolation Forest, top_n, threshold_method.
  - `ecs_mapping.yaml`: mapping raw → ECS cho Windows/Sysmon/Zeek/Syslog/FortiGate/IPS/Packetbeat.
  - `policy.yaml`: SOAR actions (PowerShell).
  - `mitre_mapping.yaml`: rule ánh xạ alert/feature → MITRE tactic/technique (T1110, T1021, T1046; hỗ trợ >, >=, <, <=, ==, string/list).

- `parsers/`: Chuẩn hóa log → ECS
  - `base_reader.py`: read JSONL, write partitioned Parquet.
  - `ecs_mapper.py`: map dot-path theo config.
  - `evtx_parser.py`, `sysmon_parser.py`, `zeek_parser.py`, `syslog_parser.py`, `csv_parser.py`, `log_parser.py`.
  - `fortigate_parser.py`: syslog FortiGate (file/UDP 5514).
  - `ips_parser.py`: Snort/Suricata (file/UDP 514).
  - `beats_parser.py`: Packetbeat/Filebeat/Winlogbeat JSONL.

- `features/`: Feature engineering
  - `build_features.py`: hợp nhất ECS, flags login_failed/conn_suspicious/allow/deny/ips, entropy, sessionize, rolling counts 1/5/15m theo host/user/src/dst, uniq IP/port, rolling bytes/packets, deny_ratio, login_failed_ratio; xuất `features.parquet` + partition.
  - `windowing.py`, `entropy.py`, `sessionize.py`, `scalers.py`.

- `models/`: ML & đánh giá
  - `train_if.py`: train Isolation Forest, lưu payload (model+scaler+feature_cols+meta).
  - `infer.py`: score → `scores.parquet` (+ partition).
  - `evaluate.py`: tính TPR/FPR/Precision/Recall/F1 (có nhãn).
  - `utils.py`: get_paths, load config, sha256, write_json.

- `explain/`: Explainability
  - `shap_explain.py`: SHAP (Tree → Kernel → fallback).
  - `thresholding.py`: ngưỡng quantile.

- `ai/`: AI Agent & MITRE
  - `agent.py`: LLM phân tích, tương quan đa nguồn, MITRE mapping, SOAR actions, markdown.
  - `mitre_mapper.py`: load/cache mapping, áp rule MITRE (tactic/technique) dựa trên alert + features.

- `pipeline/`: Orchestration
  - `ingest.py`: ingest từ file/Elastic; optional UDP FortiGate/IPS; CSV/syslog auth.
  - `build_store.py`: chạy toàn bộ parsers.
  - `alerting.py`: chọn top alerts ≥ threshold.
  - `bundle.py`: build bundle (raw, features, SHAP, model_meta, AI+MITRE, manifest, COC).
  - `run_demo.py`: end-to-end demo.
  - `respond.py`: SOAR actions (dry-run/apply).
  - `coc.py`: chain of custody.

- `ui/`: Streamlit
  - `streamlit_app.py`: entry, status cards, nav.
  - `pages/1_Overview.py`: timeline anomaly, lọc action/module, chart drop/allow, bảng IPS.
  - `pages/2_Hosts.py`: view theo host.
  - `pages/3_Alerts.py`: bảng alert, SHAP bar, context ±5m, bundle download, AI analysis, cột & lọc MITRE.
  - `disabled_pages/`: LSTM/SOAR cũ (tắt).

- `cli/`: Typer CLI
  - `anom_score.py`: `ingest` (files/Elastic/UDP), `featurize`, `train`, `score`, `bundle`, `evaluate`, `respond`, `demo`.

- `tests/`: Kiểm thử
  - `test_mitre_mapper.py`: unit test MITRE mapper.

- `split_log/`: Tiện ích chia log theo ngày/keyword/range.

- `README.md`: Hướng dẫn chạy, MITRE mapping, ingest Elastic, evaluate.
- `PROJECT_TECH_REVIEW.md`: (file này) mô tả kỹ thuật chi tiết.


## 4) Mỗi file làm gì (bản đầy đủ, cập nhật)

| Path | API/CLI | Chức năng chính | Ghi chú |
| --- | --- | --- | --- |
| `config/paths.yaml` | n/a | Đường dẫn data/models/scores/bundles; Elastic host/index patterns; cổng syslog/beats | Dùng `models/utils.get_paths` để resolve |
| `config/models.yaml` | n/a | Hyperparams IF; scaling; scoring top_n/threshold_method | contamination ảnh hưởng ngưỡng quantile |
| `config/ecs_mapping.yaml` | n/a | Mapping raw→ECS cho Windows/Sysmon/Zeek/Syslog/FortiGate/IPS/Packetbeat | Định nghĩa timestamp & map dot-path |
| `config/policy.yaml` | n/a | SOAR PowerShell actions theo ngưỡng | Dùng trong respond |
| `config/mitre_mapping.yaml` | n/a | Rule MITRE (T1110/T1021/T1046…) với điều kiện số/chuỗi/list | Có thể thêm rule mới không cần sửa code |
| `parsers/base_reader.py` | `read_jsonl`, `write_partitioned_parquet` | Đọc JSONL, ghi Parquet theo dt | Bỏ dòng hỏng để demo bền |
| `parsers/ecs_mapper.py` | `map_record` | Map dict lồng nhau sang ECS | Ưu tiên timestamp cấu hình |
| `parsers/evtx_parser.py` | `parse_evtx` | Windows EVTX JSONL → ECS | Gán event.module/dataset |
| `parsers/sysmon_parser.py` | `parse_sysmon` | Sysmon JSONL → ECS | Trường network/process |
| `parsers/zeek_parser.py` | `parse_zeek_conn` | Zeek conn → ECS | conn_state → event.outcome |
| `parsers/syslog_parser.py` | `parse_auth_log` | Syslog auth → ECS (regex) | Infer Success/Failure |
| `parsers/log_parser.py` | `parse_auth_logs` | Đọc .log syslog (recursive) | |
| `parsers/csv_parser.py` | `parse_csv_file` | CSV generic → ECS | Dùng `CSV_TIME_COL` env nếu khác tên |
| `parsers/fortigate_parser.py` | `parse_fortigate` | FortiGate syslog (file/UDP 5514) → ECS | KV parser, ghép timestamp date+time |
| `parsers/ips_parser.py` | `parse_ips` | Snort/Suricata (file/UDP 514) → ECS | Regex classification/priority/proto/src/dst |
| `parsers/beats_parser.py` | `parse_beats` | Packetbeat/Filebeat/Winlogbeat JSONL → ECS | Ưu tiên mapping packetbeat |
| `features/build_features.py` | `build_feature_table` | Hợp nhất ECS; flags login_failed/conn_suspicious/allow/deny/ips; entropy; sessionize; rolling counts 1/5/15m; uniq IP/port; bytes/packets; deny_ratio; login_failed_ratio; xuất features | Partition per-day, sample |
| `features/windowing.py` | `add_time_window_counts` | Rolling sum cờ nhị phân | on @timestamp, min_periods=1 |
| `features/entropy.py` | `shannon_entropy` | Entropy chuỗi | |
| `features/sessionize.py` | `sessionize_network` | Session 5-tuple + timeout | |
| `features/scalers.py` | helper | Scaler utils | |
| `models/train_if.py` | `train_model` | Train IF, RobustScaler, drop constant cols, lưu payload | out: isolation_forest.joblib |
| `models/infer.py` | `score_features` | Score features (partition-aware) → scores.parquet | anom.score = -decision_function |
| `models/evaluate.py` | `evaluate_model` | Đọc scores + nhãn → TPR/FPR/Precision/Recall/F1 | Output `evaluate_report.json` |
| `models/utils.py` | `get_paths`, `load_models_config`, `write_json`, `sha256_file` | Resolve path, IO | Hỗ trợ list/URL/số |
| `explain/thresholding.py` | `compute_threshold` | Quantile (1 - contamination) | |
| `explain/shap_explain.py` | `top_shap_for_rows` | SHAP Tree → Kernel → fallback ranking | Tắt JIT để tránh lỗi numba |
| `ai/mitre_mapper.py` | `load_mitre_mapping`, `map_to_mitre` | Ánh xạ MITRE từ alert+features theo YAML rule | Cache mapping |
| `ai/agent.py` | `analyze_alert_with_llm`, `analyze_alert` | Prompt LLM, risk, actions, correlations, MITRE auto, threat.*; markdown | Provider DeepSeek→Gemini→stub |
| `pipeline/ingest.py` | `ingest_all`, `ingest_from_elastic` | Ingest file/Elastic; optional UDP FortiGate/IPS; CSV/syslog auth | |
| `pipeline/build_store.py` | `run_ingest` | Chạy tất cả parsers | |
| `pipeline/alerting.py` | `select_alerts` | Chọn top-N ≥ threshold | |
| `pipeline/bundle.py` | `build_bundle_for_alert`, `build_bundles_for_top_alerts` | Bundle raw/context ±5m, features, SHAP, model_meta, AI+MITRE, manifest, COC | manifest chứa threshold/score |
| `pipeline/run_demo.py` | `run_all` | ingest→features→train→score→alerts→bundles | |
| `pipeline/respond.py` | `respond` | SOAR PowerShell (dry-run/apply) | |
| `pipeline/coc.py` | `build_coc` | Chain-of-custody | |
| `cli/anom_score.py` | Typer commands | ingest (files/Elastic/UDP), featurize, train, score, bundle, evaluate, respond, demo | Đã bỏ lệnh LSTM/ensemble |
| `ui/streamlit_app.py` | n/a | Status cards, nav | |
| `ui/pages/1_Overview.py` | n/a | Timeline anomaly, lọc action/module, chart drop/allow, bảng IPS | |
| `ui/pages/2_Hosts.py` | n/a | View theo host | |
| `ui/pages/3_Alerts.py` | n/a | Bảng alert + lọc action/module + lọc MITRE, SHAP, context, bundle, AI | |
| `tests/test_mitre_mapper.py` | unittest | Kiểm thử map_to_mitre | |


## 5) Pipeline end-to-end (cập nhật)

- Ingest: file/Elastic/UDP → `data/ecs_parquet/{source}/dt=.../part.parquet`.
- Features: hợp nhất, tính flags/rolling/uniq/bytes/ratios → `data/features/features.parquet` (+ partitions).
- Train: IF → `data/models/isolation_forest.joblib`.
- Score: → `data/scores/scores.parquet` (+ partitions).
- Alerting: threshold quantile (1-contamination), lấy top-N.
- Explain + MITRE: SHAP + map_to_mitre (config/mitre_mapping.yaml).
- Bundle: raw ±5m, features, shap, model_meta, ai_analysis (kèm MITRE), manifest, COC.
- UI: đọc scores/alerts/bundles; hiển thị MITRE, SHAP, context; tải bundle.


## 6) Dữ liệu & ECS (mở rộng nguồn)

- Nguồn log: Windows EVTX, Sysmon, Zeek conn, Syslog auth, FortiGate syslog, IPS (Snort/Suricata), Packetbeat/Filebeat/Winlogbeat; hoặc truy vấn trực tiếp Elasticsearch (index patterns cấu hình).
- Trường ECS chính: `@timestamp`, host/user, source/destination (ip/port), network.transport/protocol, event.action/outcome/severity, process.*, rule.*, network.bytes/packets.


## 7) Features (mở rộng mạng)

- Flags: login_failed, conn_suspicious, action_allow/deny, ips_alert.
- Rolling counts 1/5/15m theo host/user/src/dst.
- Uniq IP/port theo cửa sổ; rolling bytes/packets; deny_ratio; login_failed_ratio.
- Entropy: command_line/message; sessionize 5-tuple.


## 8) Modeling

- Isolation Forest (duy nhất, không còn LSTM/ensemble), RobustScaler, loại constant cols.
- Scoring: anom.score = -decision_function.
- Evaluate: tính TPR/FPR/Precision/Recall/F1 qua `models/evaluate.py`.


## 9) Explainability & AI/LLM

- SHAP top features (fallback Kernel/ranking).
- AI Agent: LLM tiếng Việt (DeepSeek→Gemini→stub), tương quan đa nguồn, gợi ý SOAR, markdown, MITRE auto mapping (threat.* + mitre_attack payload).


## 10) Forensic Bundle

- Gồm: raw_logs.jsonl (±5m), features.json, shap_explanation.json, model_meta.json, ai_analysis.json/md (có MITRE), evidence_manifest, manifest (sha256, threshold, alert_score), coc.


## 11) CLI & UI (hiển thị MITRE)

- CLI: thêm `evaluate`; ingest hỗ trợ Elastic/UDP; bỏ lệnh LSTM/ensemble.
- UI Alerts: cột + bộ lọc MITRE tactics/techniques, lọc action/module, đồ thị drop/allow, SHAP bar, context ±5m, bundle download, AI analysis.


## 12) Cấu hình & phụ thuộc (cập nhật)

- `config/mitre_mapping.yaml` mới; `requirements.txt` bỏ tensorflow/keras, thêm `requests`.
- `models/utils.get_paths` hỗ trợ list/URL/số (cho index patterns).


## 13) Kiểm thử

- Đã thêm `tests/test_mitre_mapper.py` (unit test MITRE). Các test khác chưa có; khuyến nghị bổ sung E2E + unit cho parsers/features/thresholding.


## 14) Rủi ro & đề xuất (rút gọn hiện tại)

- Rủi ro: dữ liệu demo nhỏ; SHAP có thể lỗi môi trường; thiếu logging/metrics; chưa có test đầy đủ.
- Đề xuất: thêm logging chuẩn; validate schema/time; test E2E + unit; per-source threshold; UI search/pagination/heatmap; caching SHAP; mở rộng parser DNS/HTTP/TLS.


## 15) Gap Analysis (điểm mới)

- Chuẩn hóa ECS đa nguồn: đã mở rộng FortiGate/IPS/Beats/Elastic.
- Features: đã thêm ratio/uniq/bytes; vẫn có thể bổ sung duration/session bytes.
- Explainability/Bundle: đã thêm MITRE vào AI/bundle/manifest; có thể thêm timeline.json.
- CLI/UI: đã thêm MITRE filter/cột; còn thiếu search nâng cao/pagination.


## 16) Runbook nhanh

- Tạo venv, cài deps: `pip install -r requirements.txt`
- Ingest Elastic: `python -m cli.anom_score ingest --source elasticsearch --elastic-host http://10.10.20.100:9200 --elastic-index-patterns "lab-logs-network-syslog-*,siem-*"`
- Hoặc ingest file/UDP demo: `python -m cli.anom_score ingest --enable-udp`
- Featurize + train + score: `python -m cli.anom_score featurize && python -m cli.anom_score train && python -m cli.anom_score score`
- Evaluate: `python -m cli.anom_score evaluate --labels-path <path_labels>`
- Streamlit: `streamlit run ui/streamlit_app.py`
- Làm sạch: xóa `data/` và `bundles/` nếu cần.

