# Managing Cybersecurity Events using Elastic Stack combined with AI Agent

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Hệ thống phát hiện bất thường (anomaly detection) trong log an ninh mạng sử dụng Elastic Common Schema (ECS), Machine Learning (Isolation Forest), và AI Agent để phân tích và tạo gói pháp chứng (forensic bundles) tự động.

## 📋 Tổng quan

Dự án này là một hệ thống end-to-end offline giúp:
- **Thu thập và chuẩn hóa log** từ nhiều nguồn (Windows Security, Sysmon, Zeek, Syslog) về chuẩn ECS
- **Phát hiện bất thường** sử dụng Isolation Forest (unsupervised learning)
- **Giải thích kết quả** bằng SHAP (SHapley Additive exPlanations)
- **Tạo gói pháp chứng** tự động với đầy đủ thông tin cho điều tra
- **Tích hợp AI Agent** để phân tích và đề xuất hành động phản ứng

## ✨ Tính năng chính

- 🔍 **Multi-source Log Ingestion**: Hỗ trợ Windows Event Logs, Sysmon, Zeek, Syslog, **FortiGate firewall**, **IPS (Snort/Suricata)**, **Packetbeat/Filebeat/Winlogbeat**
- 📊 **ECS Normalization**: Chuẩn hóa tất cả log về Elastic Common Schema
- 🤖 **Anomaly Detection**: Sử dụng Isolation Forest để phát hiện bất thường không cần nhãn
- 📈 **Feature Engineering**: 
  - Time-window features (1/5/15 phút)
  - Entropy analysis cho command lines
  - Sessionization theo 5-tuple network
  - **Network metrics**: deny/allow ratio, uniq IP/port per window, bytes/packets per window
- 🧠 **AI-Powered Analysis**: Tích hợp AI Agent (DeepSeek/Gemini) để phân tích alert và đề xuất hành động
- 📦 **Forensic Bundles**: Tự động tạo gói pháp chứng với:
  - Raw logs (±5 phút context)
  - Feature vectors
  - SHAP explanations
  - Model metadata
  - SHA256 manifest
- 🖥️ **Streamlit Dashboard**: Giao diện web để xem timeline, alerts, MITRE tactic/technique, và tải bundles
- ⚡ **CLI Tools**: Typer-based CLI để chạy pipeline từng bước, đánh giá mô hình hoặc end-to-end

## 📖 Hướng dẫn sử dụng

### Chạy từng bước

Thay vì chạy toàn bộ pipeline, bạn có thể chạy từng bước:

```bash
# 1. Ingest logs và chuẩn hóa ECS
python -m cli.anom_score ingest --reset

# Hoặc ingest trực tiếp từ Elasticsearch
python -m cli.anom_score ingest --source elasticsearch --elastic-host http://10.10.20.100:9200 --elastic-index-patterns "lab-logs-network-syslog-*,siem-*"

# 2. Tạo features
python -m cli.anom_score featurize --reset

# 3. Train model
python -m cli.anom_score train

# 4. Score anomalies
python -m cli.anom_score score --reset

# 5. Tạo forensic bundles
python -m cli.anom_score bundle

# 6. Đánh giá mô hình (cần cột label hoặc file nhãn)
python -m cli.anom_score evaluate --labels-path data/labels/labels.parquet --label-col label
```

## MITRE ATT&CK Mapping

- Rule cấu hình tại `config/mitre_mapping.yaml` (ví dụ: brute force T1110, remote service T1021, port scan T1046).
- Điều kiện hỗ trợ so sánh số (`>`, `>=`, `<`, `<=`, `==`) và khớp chuỗi/danh sách.
- AI Agent tự động gán tactic/technique vào `ai_analysis.json`/`.md` trong bundle, đồng thời hiển thị ở UI Alerts (cột `mitre.techniques`) kèm bộ lọc theo tactic/technique.
- Muốn thêm rule mới: bổ sung mục mới vào YAML với `id/description/tactic/technique/subtechnique/conditions`, không cần sửa code.

### Thêm dữ liệu mới

1. **Thêm log files:**
   - Đặt file `.log` (syslog format) hoặc `.csv` vào thư mục `sample_data/`
   - Đối với CSV, đảm bảo có cột thời gian (Timestamp, Start Time, DateTime, ...)
   - Nếu tên cột khác, set biến môi trường: `CSV_TIME_COL=YourTimeColumn`

2. **Chạy lại pipeline:**
```bash
python -m cli.anom_score ingest --reset
python -m cli.anom_score featurize --reset
python -m cli.anom_score train  # Optional: chỉ train nếu muốn retrain
python -m cli.anom_score score --reset
python -m cli.anom_score bundle
```

3. **Reload Streamlit** để xem dữ liệu mới

### Cấu hình

Các file cấu hình nằm trong thư mục `config/`:

- **`config/paths.yaml`**: Đường dẫn thư mục (data, models, bundles, ...)
-   - Thông số mạng: `elastic_host`, `elastic_index_patterns`, `fortigate_syslog_port=5514`, `ips_syslog_port=514`, `beats_port=5044`
- **`config/models.yaml`**: Tham số mô hình (Isolation Forest, threshold, top_n, ...)
- **`config/ecs_mapping.yaml`**: Mapping từ raw log fields sang ECS fields
- **`config/policy.yaml`**: Policy rules cho SOAR actions
- **`config/mitre_mapping.yaml`**: Rule ánh xạ alert/feature → MITRE ATT&CK; hỗ trợ so sánh số (> >= < <= ==) và khớp chuỗi/danh sách, dễ chỉnh sửa để thêm kỹ thuật mới.

## 📁 Cấu trúc dự án

```
Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent/
├── README.md
├── requirements.txt
├── .gitignore
├── config/                    # Cấu hình YAML
│   ├── paths.yaml
│   ├── models.yaml
│   ├── ecs_mapping.yaml
│   └── policy.yaml
├── sample_data/              # Dữ liệu mẫu (gitignored)
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
│   ├── bundle.py            # Forensic bundle creation
│   ├── coc.py               # Chain of custody
│   ├── respond.py            # SOAR response actions
│   └── run_demo.py          # End-to-end demo
├── ai/                       # AI Agent integration
│   └── agent.py             # AI analysis và action suggestions
├── ui/                       # Streamlit dashboard
│   ├── streamlit_app.py
│   ├── pages/
│   │   ├── 1_Overview.py
│   │   ├── 2_Hosts.py
│   │   └── 3_Alerts.py
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
└── bundles/                  # Forensic bundles (gitignored)
    └── alert_*.zip
```

## 🎯 Workflow

### Quy trình xử lý dữ liệu mới

1. Thêm file log vào `sample_data/`
2. Chạy ingest: `python -m cli.anom_score ingest --reset`
3. Tạo features: `python -m cli.anom_score featurize --reset`
4. (Tùy chọn) Retrain: `python -m cli.anom_score train`
5. Score: `python -m cli.anom_score score --reset`
6. Tạo bundles: `python -m cli.anom_score bundle`
7. Reload Streamlit dashboard

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
