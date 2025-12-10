## 1) Executive Summary (Cập nhật)

Hệ thống phát hiện bất thường log an ninh mạng end-to-end, offline-first, hỗ trợ ingest đa nguồn (Windows/Sysmon/Zeek/Syslog/FortiGate/IPS/Packetbeat hoặc Elasticsearch), chuẩn hóa ECS, tạo đặc trưng mạng + đăng nhập, huấn luyện và chấm điểm Isolation Forest, ánh xạ MITRE ATT&CK tự động, giải thích SHAP, phân tích AI Agent (Gemini/DeepSeek/stub) và hiển thị trên Streamlit (kèm trang báo cáo một trang). Bundle pháp chứng là tùy chọn cho POC; pipeline chính vẫn chạy trơn trên files/Elastic mà không cần bundle.


## 2) Kiến trúc tổng quan

```
Nguồn log (files/UDP/Elasticsearch)
  → Ingest + ECS Normalize (parsers/*, ecs_mapper)
  → Parquet Store (data/ecs_parquet/…)
  → Feature Engineering (features/*)
  → Modeling (Isolation Forest)
  → Scoring (scores.parquet)
  → Alerting (threshold + top-N)
  → MITRE Mapping (ai/mitre_mapper.py)
  → (Tùy chọn) Bundle pháp chứng
  → UI/AI Analysis (Streamlit + AI Agent)
```

- Config: `config/models.yaml`, `paths.yaml`, `ecs_mapping.yaml`, `mitre_mapping.yaml`.
- Alerting: ngưỡng quantile (1 - contamination), top-N.
- UI: timeline, drop/allow chart, IPS table, alert table + MITRE filters, trang báo cáo tổng hợp.


## 3) Cấu trúc thư mục & vai trò

- `config/`: cấu hình đường dẫn, mô hình, ECS mapping, MITRE rule, SOAR policy.
- `parsers/`: chuẩn hóa log đa nguồn (Windows, Sysmon, Zeek, Syslog auth, CSV, FortiGate, IPS, Packetbeat).
- `features/`: đặc trưng mạng + đăng nhập (flags, entropy, session, rolling counts/uniq/bytes/ratios).
- `models/`: train/score Isolation Forest, evaluate; utils path/hash/json.
- `explain/`: ngưỡng quantile, SHAP (Tree→Kernel→fallback).
- `ai/`: MITRE mapper, AI Agent (Gemini/DeepSeek/stub) + threat.*.
- `pipeline/`: ingest, alerting, (tùy chọn) bundle, respond SOAR, demo end-to-end.
- `ui/`: Streamlit (trang chính + báo cáo tổng hợp 4_Report).
- `cli/`: Typer CLI (ingest/featurize/train/score/evaluate/respond/demo/bundle).
- `tests/`: test_mitre_mapper.
- `sample_data/`: dữ liệu giả (normal, attack) + script generate.
- `split_log/`: tiện ích chia log.


## 4) Mỗi file làm gì (bản đầy đủ)

| Path | Chức năng | Ghi chú |
|---|---|---|
| `config/paths.yaml` | Đường dẫn data/models/scores/bundles; Elastic host/index patterns; cổng syslog/beats | Dùng `models/utils.get_paths`; hỗ trợ override env |
| `config/models.yaml` | Hyperparams IF, scaling, scoring top_n/threshold | contamination ảnh hưởng ngưỡng quantile |
| `config/ecs_mapping.yaml` | Mapping raw→ECS Windows/Sysmon/Zeek/Syslog/FortiGate/IPS/Packetbeat | Định nghĩa timestamp & dot-path |
| `config/policy.yaml` | SOAR PowerShell actions | Dùng trong respond |
| `config/mitre_mapping.yaml` | Rule MITRE (T1110/T1021/T1046…), so sánh số/chuỗi/list | Nới lỏng: T1110 (count>7, ratio>0.4), T1046 (uniq_dport>8), T1021 (port 22/3389/445 + allow) |
| `parsers/base_reader.py` | Đọc JSONL, ghi Parquet dt=YYYY-MM-DD | Bỏ dòng hỏng |
| `parsers/ecs_mapper.py` | Map dict lồng nhau sang ECS | Ưu tiên timestamp cấu hình |
| `evtx_parser.py`, `sysmon_parser.py`, `zeek_parser.py`, `syslog_parser.py`, `csv_parser.py`, `log_parser.py` | Parser nguồn tương ứng | |
| `fortigate_parser.py` | FortiGate syslog (file/UDP) → ECS | KV parser |
| `ips_parser.py` | Snort/Suricata (file/UDP) → ECS | Regex classification/priority/proto/src/dst |
| `beats_parser.py` | Packetbeat/Filebeat/Winlogbeat JSONL → ECS | |
| `features/build_features.py` | Hợp nhất ECS; flags login_failed/conn_suspicious/allow/deny/ips; entropy; sessionize; rolling 1/5/15m theo host/user/src/dst; uniq IP/port; bytes/packets; deny_ratio; login_failed_ratio; xuất features | Partition per-day |
| `features/windowing.py`, `entropy.py`, `sessionize.py`, `scalers.py` | Tiện ích rolling/entropy/session/scaler | |
| `models/train_if.py` | Train IF + RobustScaler, drop constant cols | out: `data/models/isolation_forest.joblib` |
| `models/infer.py` | Score features (partition-aware) → `scores.parquet` | anom.score = -decision_function |
| `models/evaluate.py` | Tính TPR/FPR/Precision/Recall/F1 (nếu có nhãn) | out: `evaluate_report.json` |
| `models/utils.py` | get_paths, load config, write_json, sha256 | Hỗ trợ list/URL/số |
| `explain/thresholding.py` | Quantile threshold | |
| `explain/shap_explain.py` | SHAP Tree→Kernel→fallback ranking | |
| `ai/mitre_mapper.py` | Load/cache mapping, map_to_mitre(alert, features) | |
| `ai/agent.py` | LLM phân tích, risk, actions, correlations, MITRE auto, threat.*; markdown | Provider: DeepSeek→Gemini→stub |
| `pipeline/ingest.py` | ingest files/Elastic; optional UDP FortiGate/IPS; CSV/syslog auth | |
| `pipeline/build_store.py` | Chạy tất cả parsers | |
| `pipeline/alerting.py` | Chọn top-N ≥ threshold | |
| `pipeline/bundle.py` | (Tùy chọn) bundle raw/features/SHAP/AI/MITRE/manifest | POC có thể bỏ qua |
| `pipeline/run_demo.py` | ingest→features→train→score→alerts→bundles | |
| `pipeline/respond.py` | SOAR PowerShell (dry-run/apply) | |
| `pipeline/coc.py` | Chain-of-custody | |
| `cli/anom_score.py` | Typer CLI ingest/featurize/train/score/bundle/evaluate/respond/demo | |
| `ui/streamlit_app.py` | Trang chính + link báo cáo | |
| `ui/pages/1_Overview.py` | Timeline, metrics, drop/allow chart, IPS table | |
| `ui/pages/3_Alerts.py` | Bảng alert, SHAP bar, context ±5m, AI analysis, MITRE filters | |
| `ui/pages/4_Report.py` | Báo cáo một trang: tổng quan, metrics, risk, anom.score hist, MITRE, SHAP tổng hợp, AI markdown (nếu có), timeline alert, bảng chi tiết | |
| `tests/test_mitre_mapper.py` | Unit test MITRE | |


## 5) Pipeline end-to-end (khuyến nghị, không bundle)

1) Sinh dữ liệu giả:
```
python sample_data/generate_synthetic_logs.py
```
2) Train trên normal:
```
python -m cli.anom_score ingest --source files --reset --data-dir sample_data/normal
python -m cli.anom_score featurize --reset
python -m cli.anom_score train
```
3) Score trên attack:
```
python -m cli.anom_score ingest --source files --reset --data-dir sample_data/attack
python -m cli.anom_score featurize --reset
python -m cli.anom_score score --reset
```
4) (Tùy chọn) bundle & SHAP/AI markdown:
```
python -m cli.anom_score bundle
```
5) (Tùy chọn) evaluate nếu có nhãn:
```
python -m cli.anom_score evaluate --labels-path <file_labels> --label-col label
```
6) UI:
```
streamlit run ui/streamlit_app.py   # trang Báo cáo tổng hợp (4_Report) hiển thị alerts, MITRE, risk, timeline, SHAP, metrics
```


## 6) Dữ liệu & ECS

- Nguồn: Windows EVTX, Sysmon, Zeek conn, Syslog auth, FortiGate syslog, IPS (Snort/Suricata), Packetbeat; hoặc Elasticsearch index patterns.
- Trường ECS chính: `@timestamp`, host/user, source/destination ip/port, network.transport/protocol, event.action/outcome/severity, process.*, rule.*, network.bytes/packets.
- Synthetic data (normal/attack) sinh từ `sample_data/generate_synthetic_logs.py`.


## 7) Features (mạng + đăng nhập)

- Flags: login_failed, conn_suspicious, action_allow/deny, ips_alert, cbs_failed.
- Rolling counts 1/5/15m theo host/user/src/dst (cbs_failed thêm process.name).
- Unique IP/port (uniq_dst_per_src, uniq_src_per_dst, uniq_dport_per_src).
- Rolling bytes/packets theo host/src/dst; ratios: deny_ratio_{w}m, login_failed_ratio_{w}m.
- Entropy: command_line, message; fallback text_entropy; sessionize 5-tuple.


## 8) MITRE ATT&CK mapping (đang áp dụng)

- `config/mitre_mapping.yaml` (đã nới lỏng):
  - T1110 Brute Force: login_failed_count_5m > 7, login_failed_ratio_5m > 0.4.
  - T1046 Network Service Discovery: uniq_dport_per_src_1m > 8, conn_suspicious == 1.
  - T1021 Remote Services: destination.port ∈ {22, 3389, 445}, event.action == "allow".
- `ai/mitre_mapper.py` đọc YAML, match điều kiện (AND), không match nếu field None; đã cache để tránh đọc lại nhiều lần.
- Trang báo cáo và Alerts đều tính/hiển thị MITRE (recompute trên alert nếu thiếu).


## 9) Modeling

- Isolation Forest (duy nhất), RobustScaler, loại constant cols.
- anom.score = -decision_function.
- Evaluate (tùy chọn) với nhãn: TPR/FPR/Precision/Recall/F1.


## 10) Explainability & AI/LLM

- SHAP top features (Tree → Kernel → fallback ranking).
- AI Agent: ưu tiên Gemini (GEMINI_API_KEY); fallback DeepSeek (DEEPSEEK_API_KEY); cuối cùng stub offline. Điền threat.* nếu có MITRE; trả về risk_level, actions (PowerShell/SOAR), correlations, markdown.


## 11) UI Streamlit

- `streamlit_app.py`: status, link trang Báo cáo tổng hợp.
- `pages/4_Report.py`: báo cáo một trang (tổng quan, metrics, risk, anom hist, MITRE chart, SHAP tổng hợp từ bundle nếu có, AI markdown nếu có, timeline alert, bảng chi tiết có lọc).
- `pages/1_Overview.py`: timeline anomaly, drop/allow, IPS table.
- `pages/3_Alerts.py`: bảng alert + lọc MITRE, SHAP bar, context ±5m, AI analysis (bundle nếu có).


## 12) Cấu hình & phụ thuộc

- `requirements.txt`: numpy, pandas, pyarrow, fastparquet, scikit-learn, shap, typer/click, streamlit, google-generativeai (Gemini), requests, python-dotenv.
- Không còn tensorflow/keras (LSTM đã bỏ).


## 13) Kiểm thử & chất lượng

- Có `tests/test_mitre_mapper.py`. Chưa có E2E/parsings/feature tests; khuyến nghị bổ sung.
- Synthetic data + pipeline rút gọn giúp kiểm thử nhanh.


## 14) Rủi ro & đề xuất

- Rủi ro: dataset nhỏ; SHAP có thể lỗi môi trường; thiếu logging/metrics; thiếu test E2E; MITRE phụ thuộc đầy đủ field/feature.
- Đề xuất: thêm logging chuẩn; validate schema/time; thêm test E2E; per-source threshold; UI search/pagination/heatmap; caching SHAP; parser DNS/HTTP/TLS.


## 15) Runbook nhanh (không bundle)

```
python -m venv venv; venv\Scripts\activate
pip install -r requirements.txt
python sample_data/generate_synthetic_logs.py

# Train trên normal
python -m cli.anom_score ingest --source files --reset --data-dir sample_data/normal
python -m cli.anom_score featurize --reset
python -m cli.anom_score train

# Score trên attack
python -m cli.anom_score ingest --source files --reset --data-dir sample_data/attack
python -m cli.anom_score featurize --reset
python -m cli.anom_score score --reset

# (tùy chọn) bundle + SHAP/AI markdown
python -m cli.anom_score bundle

# (tùy chọn) evaluate nếu có nhãn
python -m cli.anom_score evaluate --labels-path <file_labels> --label-col label

streamlit run ui/streamlit_app.py  # xem báo cáo tổng hợp
```