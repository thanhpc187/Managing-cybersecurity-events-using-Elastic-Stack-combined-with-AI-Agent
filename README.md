# Managing Cybersecurity Events using Elastic Stack combined with AI Agent

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Hệ thống phát hiện bất thường (anomaly detection) trong log an ninh mạng sử dụng Elastic Common Schema (ECS), Machine Learning (Isolation Forest), và AI Agent để phân tích và ánh xạ MITRE ATT&CK + NIST CSF 2.0.

## 📋 Tổng quan

Dự án này là một hệ thống end-to-end giúp:
- **Thu thập và chuẩn hóa log** từ nhiều nguồn (Windows Security, Sysmon, Zeek, Syslog, FortiGate, IPS, Beats/Packetbeat/Filebeat/Winlogbeat) về chuẩn ECS
- **Phát hiện bất thường** sử dụng Isolation Forest (unsupervised learning)
- **Trích xuất đặc trưng** theo thời gian, hành vi đăng nhập và lưu lượng mạng
- **Ánh xạ chuẩn an ninh**: MITRE ATT&CK (tactic/technique) và NIST CSF 2.0 (Function/Category/Subcategory)
- **Phân tích bằng AI Agent** (DeepSeek/Gemini) để diễn giải alert, ước lượng mức rủi ro và gợi ý hành động phản ứng
- **Trình bày kết quả** trên giao diện Streamlit một trang dành cho báo cáo SOC

## ✨ Tính năng chính

- 🔍 **Multi-source Log Ingestion**: Hỗ trợ Windows Event Logs, Sysmon, Zeek, Syslog, **FortiGate firewall**, **IPS (Snort/Suricata)**, **Packetbeat/Filebeat/Winlogbeat** và (tùy chọn) ingest từ Elasticsearch
- 📊 **ECS Normalization**: Chuẩn hóa tất cả log về Elastic Common Schema
- 🤖 **Anomaly Detection**: Sử dụng Isolation Forest để phát hiện bất thường không cần nhãn
- 📈 **Feature Engineering**: 
  - Time-window features (1/5/15 phút)
  - Entropy analysis cho command lines / message
  - Sessionization theo 5-tuple network
  - **Network metrics**: deny/allow ratio, uniq IP/port per window, bytes/packets per window
- 🧠 **AI-Powered Analysis**: Tích hợp AI Agent (DeepSeek/Gemini) để phân tích alert, ước lượng risk level, trích IOC và gợi ý hành động (PowerShell/SOAR)
- 🧩 **MITRE ATT&CK + NIST CSF 2.0 Mapping**:
  - Rule-based từ `config/mitre_mapping.yaml` và `config/nist_csf_mapping.yaml`
  - Heuristic mapping từ nội dung log và đặc trưng
  - Fallback LLM (Gemini) để suy luận MITRE/NIST khi rule không khớp
- 📦 **Forensic Bundles (tùy chọn)**: Tự động tạo gói pháp chứng với:
  - Raw logs (±5 phút context)
  - Feature vectors
  - SHAP explanations
  - Model metadata
  - SHA256 manifest và chain-of-custody
- 🖥️ **Streamlit Dashboard (one-page)**: Giao diện web để xem tổng quan dữ liệu, phân phối anom.score, risk level, ánh xạ MITRE/NIST, timeline alert và bảng alert chi tiết
- ⚡ **CLI Tools**: Typer-based CLI để chạy pipeline từng bước, đánh giá mô hình hoặc end-to-end

## 📖 Hướng dẫn sử dụng (pipeline chính)

### Chạy từng bước với dữ liệu log đã có

Thay vì chạy toàn bộ pipeline trong một lệnh, bạn có thể chạy tuần tự:

```bash
# 1. Ingest logs và chuẩn hóa ECS (từ file hoặc Elasticsearch tùy cấu hình)
python -m cli.anom_score ingest --reset

# Hoặc ingest trực tiếp từ Elasticsearch
python -m cli.anom_score ingest \
  --source elasticsearch \
  --elastic-host http://10.10.20.100:9200 \
  --elastic-index-patterns "logs-ubuntu.system-*,lab-logs-network-syslog-*,siem-*"

# 2. Tạo features
python -m cli.anom_score featurize --reset

# 3. Train model (nếu cần huấn luyện lại)
python -m cli.anom_score train

# 4. Score anomalies
python -m cli.anom_score score --reset

# 5. (Khuyến nghị) Validate nhanh: ECS/Features/Scores/MITRE/NIST có đủ dữ liệu chưa
# - Tạo file report JSON: data/scores/validate_report.json
# - Exit code != 0 nếu thiếu field/feature/mapping then chốt
python -m cli.anom_score validate

# Validate trực tiếp từ Elasticsearch (không cần parquet có sẵn)
python -m cli.anom_score validate --source elasticsearch \
  --elastic-host http://10.10.20.100:9200 \
  --elastic-index-patterns "logs-ubuntu.auth-*,logs-generic-*,logs-network.firewall-*,logs-network.coresw-*,logs-network.accesssw-*"

# 6. (Tùy chọn) Đánh giá mô hình (cần cột label hoặc file nhãn)
python -m cli.anom_score evaluate --labels-path data/labels/labels.parquet --label-col label
```

Sau khi pipeline hoàn tất, chạy UI:

```bash
streamlit run ui/streamlit_app.py
```

## MITRE ATT&CK & NIST CSF 2.0 Mapping

- Rule MITRE cấu hình tại `config/mitre_mapping.yaml` (ví dụ: brute force T1110, remote service T1021, port scan T1046).
- Rule NIST CSF 2.0 cấu hình tại `config/nist_csf_mapping.yaml`, ánh xạ từ các kỹ thuật MITRE sang Function/Category/Subcategory.
- Điều kiện rule hỗ trợ so sánh số (`>`, `>=`, `<`, `<=`, `==`) và khớp chuỗi/danh sách.
- AI Agent và UI:
  - Tự động gán tactic/technique (MITRE) và Function (NIST) cho từng alert.
  - Thông tin này được:
    - Ghi vào `ai_analysis.json`/`.md` trong bundle (nếu bật bundle).
    - Hiển thị trên UI (bar chart + bảng và bộ lọc MITRE/NIST).
- Muốn thêm rule mới: bổ sung mục mới vào YAML với `id/description/tactic/technique/subtechnique/conditions`, không cần sửa code.

### Thêm dữ liệu mới

1. **Thêm log files:**
   - Đặt file `.log` (syslog format) hoặc `.csv`/`.jsonl` vào thư mục `sample_data/` hoặc nguồn log mà bạn lựa chọn.
   - Đối với CSV, đảm bảo có cột thời gian (Timestamp, Start Time, DateTime, ...) hoặc thiết lập biến môi trường: `CSV_TIME_COL=YourTimeColumn`.

2. **Chạy lại pipeline:**

```bash
python -m cli.anom_score ingest --reset
python -m cli.anom_score featurize --reset
python -m cli.anom_score train      # Optional: chỉ train nếu muốn retrain
python -m cli.anom_score score --reset
python -m cli.anom_score validate   # Khuyến nghị
```

3. **Reload Streamlit** để xem dữ liệu mới.

### Cấu hình

Các file cấu hình nằm trong thư mục `config/`:

- **`config/paths.yaml`**: Đường dẫn thư mục (data, models, bundles, ...) và thông số mạng:
  - `elastic_host`, `elastic_index_patterns`, `fortigate_syslog_port=5514`, `ips_syslog_port=514`, `beats_port=5044`
- **`config/models.yaml`**: Tham số mô hình (Isolation Forest, threshold, top_n, ...)
- **`config/ecs_mapping.yaml`**: Mapping từ raw log fields sang ECS fields
- **`config/policy.yaml`**: Policy rules cho SOAR actions
- **`config/mitre_mapping.yaml`**: Rule ánh xạ alert/feature → MITRE ATT&CK
- **`config/nist_csf_mapping.yaml`**: Rule ánh xạ từ MITRE technique → NIST CSF 2.0

## 📁 Cấu trúc dự án

```text
Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent/
├── README.md
├── requirements.txt
├── .gitignore
├── config/                    # Cấu hình YAML
│   ├── paths.yaml
│   ├── models.yaml
│   ├── ecs_mapping.yaml
│   ├── mitre_mapping.yaml
│   ├── nist_csf_mapping.yaml
│   └── policy.yaml
├── sample_data/              # Dữ liệu mẫu (demo / thử nghiệm)
├── parsers/                  # Log parsers và ECS mapper
│   ├── base_reader.py
│   ├── ecs_mapper.py
│   ├── evtx_parser.py
│   ├── sysmon_parser.py
│   ├── zeek_parser.py
│   ├── syslog_parser.py
│   ├── log_parser.py
│   ├── csv_parser.py
│   ├── fortigate_parser.py
│   ├── ips_parser.py
│   └── beats_parser.py
├── features/                 # Feature engineering
│   ├── build_features.py
│   ├── windowing.py
│   ├── entropy.py
│   ├── sessionize.py
│   └── scalers.py
├── models/                   # ML models
│   ├── train_if.py          # Isolation Forest training
│   ├── infer.py             # Inference
│   ├── evaluate.py          # Đánh giá TPR/FPR/Precision/Recall/F1
│   └── utils.py
├── explain/                  # Explainability
│   ├── shap_explain.py      # SHAP explanations
│   └── thresholding.py      # Threshold computation
├── pipeline/                 # Pipeline orchestration
│   ├── ingest.py
│   ├── build_store.py
│   ├── alerting.py
│   ├── bundle.py            # Forensic bundle creation (tùy chọn)
│   ├── coc.py               # Chain of custody
│   ├── respond.py           # SOAR response actions
│   └── run_demo.py          # End-to-end demo
├── ai/                       # AI Agent & mapping frameworks
│   ├── agent.py             # AI analysis và action suggestions
│   ├── mitre_mapper.py      # Rule-based MITRE mapping
│   └── nist_mapper.py       # Rule-based NIST CSF mapping
├── ui/                       # Streamlit dashboard (one-page)
│   └── streamlit_app.py
├── cli/                      # CLI commands
│   └── anom_score.py
├── split_log/                # Log utilities
│   ├── log_by_date.py
│   ├── log_by_keyword.py
│   └── log_by_range.py
├── data/                     # Generated data (gitignored)
│   ├── ecs_parquet/         # ECS normalized logs
│   ├── features/            # Feature tables
│   ├── models/              # Trained models
│   └── scores/              # Anomaly scores
└── bundles/                  # Forensic bundles (gitignored, tùy chọn)
    └── alert_*.zip
```

## 🎯 Workflow (tóm tắt)

1. **Ingest**: thu thập log từ file hoặc Elasticsearch, chuẩn hóa về ECS và lưu Parquet.
2. **Featurize**: trích xuất đặc trưng theo thời gian, hành vi đăng nhập, kết nối mạng.
3. **Train**: huấn luyện Isolation Forest trên log “bình thường” (nếu cần).
4. **Score**: tính `anom.score` cho từng record và xác định alerts theo threshold.
5. **(Tùy chọn) Bundle**: tạo forensic bundles + AI analysis chi tiết.
6. **UI**: mở Streamlit để xem báo cáo một trang (tổng quan, MITRE/NIST, timeline, bảng alert).

## ⚖️ Copyright

- **Copyright**: All code is copyright © 2024 thanhpc187
- **License**: MIT License (see [LICENSE](LICENSE))
- **Attribution**: Please credit the original author (thanhpc187) when using this code

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

If you use this code, please credit the original author (thanhpc187) and include a link to this repository.

## 👤 Author & Copyright

**Copyright (c) 2024 thanhpc187**

- GitHub: [@thanhpc187](https://github.com/thanhpc187)
- Repository: [Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent](https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent)

**Lưu ý**: Dự án này là một demo/POC. Để sử dụng trong môi trường production, cần:
- Mở rộng dataset và features
- Tối ưu hóa model performance
- Thêm logging và monitoring
- Cải thiện error handling và validation
