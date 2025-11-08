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

- 🔍 **Multi-source Log Ingestion**: Hỗ trợ Windows Event Logs, Sysmon, Zeek, Syslog
- 📊 **ECS Normalization**: Chuẩn hóa tất cả log về Elastic Common Schema
- 🤖 **Anomaly Detection**: Sử dụng Isolation Forest để phát hiện bất thường không cần nhãn
- 📈 **Feature Engineering**: 
  - Time-window features (1/5/15 phút)
  - Entropy analysis cho command lines
  - Sessionization theo 5-tuple network
- 🧠 **AI-Powered Analysis**: Tích hợp AI Agent (DeepSeek/Gemini) để phân tích alert và đề xuất hành động
- 📦 **Forensic Bundles**: Tự động tạo gói pháp chứng với:
  - Raw logs (±5 phút context)
  - Feature vectors
  - SHAP explanations
  - Model metadata
  - SHA256 manifest
- 🖥️ **Streamlit Dashboard**: Giao diện web để xem timeline, alerts, và tải bundles
- ⚡ **CLI Tools**: Typer-based CLI để chạy pipeline từng bước hoặc end-to-end

## 🚀 Quick Start

### Yêu cầu

- Python 3.12+
- Windows/Linux/macOS

### Cài đặt

1. **Clone repository:**
```bash
git clone https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent.git
cd Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent
```

2. **Tạo virtual environment:**
```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux/macOS
python -m venv venv
source venv/bin/activate
```

3. **Cài đặt dependencies:**
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

4. **Cấu hình môi trường (tùy chọn):**
Tạo file `.env` trong thư mục gốc để cấu hình API keys cho AI Agent:
```env
# AI Agent Configuration (optional)
DEEPSEEK_API_KEY=your_deepseek_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# DeepSeek Configuration
DEEPSEEK_API_BASE=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# Gemini Configuration
GEMINI_MODEL=gemini-1.5-flash
```

### Chạy Demo

1. **Chạy toàn bộ pipeline:**
```bash
python -m cli.anom_score demo
```

Lệnh này sẽ tự động:
- Ingest logs từ `sample_data/`
- Chuẩn hóa về ECS và lưu Parquet
- Tạo features (time windows, entropy, sessions)
- Train Isolation Forest model
- Score anomalies
- Tạo forensic bundles cho top alerts

2. **Khởi động Streamlit Dashboard:**
```bash
streamlit run ui/streamlit_app.py
```

Truy cập http://localhost:8501 để xem:
- **Overview**: Timeline điểm anomaly, tổng số events
- **Hosts**: Phân tích theo host, trends
- **Alerts**: Top alerts với SHAP explanations, raw context, và tải bundles

## 📖 Hướng dẫn sử dụng chi tiết

### Chạy từng bước

Thay vì chạy toàn bộ pipeline, bạn có thể chạy từng bước:

```bash
# 1. Ingest logs và chuẩn hóa ECS
python -m cli.anom_score ingest --reset

# 2. Tạo features
python -m cli.anom_score featurize --reset

# 3. Train model
python -m cli.anom_score train

# 4. Score anomalies
python -m cli.anom_score score --reset

# 5. Tạo forensic bundles
python -m cli.anom_score bundle
```

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
- **`config/models.yaml`**: Tham số mô hình (Isolation Forest, threshold, top_n, ...)
- **`config/ecs_mapping.yaml`**: Mapping từ raw log fields sang ECS fields
- **`config/policy.yaml`**: Policy rules cho SOAR actions

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
│   └── csv_parser.py
├── features/                 # Feature engineering
│   ├── build_features.py
│   ├── windowing.py
│   ├── entropy.py
│   ├── sessionize.py
│   └── scalers.py
├── models/                   # ML models
│   ├── train_if.py          # Isolation Forest training
│   ├── infer.py             # Inference
│   ├── lstm_anomaly.py      # LSTM model (optional)
│   ├── ensemble.py          # Ensemble models
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
│   └── disabled_pages/       # Disabled features
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

## 🔧 Troubleshooting

| Vấn đề | Cách xử lý |
|--------|-----------|
| `No module named 'cli'` | Đảm bảo đang ở thư mục gốc repo và có `__init__.py` trong các thư mục |
| Không thấy dữ liệu mới | Reset phần liên quan: `ingest --reset`, `featurize --reset`, `score --reset` |
| Không tạo bundle | Kiểm tra `data/scores/scores.parquet` tồn tại và có alerts vượt ngưỡng |
| CSV bị skip | Đảm bảo CSV có cột thời gian hoặc set `CSV_TIME_COL` environment variable |
| SHAP lỗi | Retrain model: `python -m cli.anom_score train` |
| AI Agent không hoạt động | Kiểm tra API keys trong `.env` hoặc environment variables |

## 🎯 Workflow

### Quy trình xử lý dữ liệu mới

1. Thêm file log vào `sample_data/`
2. Chạy ingest: `python -m cli.anom_score ingest --reset`
3. Tạo features: `python -m cli.anom_score featurize --reset`
4. (Tùy chọn) Retrain: `python -m cli.anom_score train`
5. Score: `python -m cli.anom_score score --reset`
6. Tạo bundles: `python -m cli.anom_score bundle`
7. Reload Streamlit dashboard

## 🔐 Security Notes

- File `.env` chứa API keys **KHÔNG** được commit vào git
- Các thư mục `data/` và `bundles/` chứa dữ liệu nhạy cảm và được gitignored
- Forensic bundles chứa SHA256 manifest để đảm bảo integrity

## ⚖️ Copyright & Attribution

- **Copyright**: All code is copyright © 2024 thanhpc187
- **License**: MIT License (see [LICENSE](LICENSE))
- **Attribution**: Please credit the original author (thanhpc187) when using this code
- **See Also**: [AUTHORS.md](AUTHORS.md) and [COPYRIGHT_NOTICE.md](COPYRIGHT_NOTICE.md)

## 📚 Tài liệu thêm

Xem file `PROJECT_TECH_REVIEW.md` để biết chi tiết về:
- Kiến trúc hệ thống
- Data flow và pipeline
- Feature engineering
- Model training và inference
- Forensic bundle structure

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

If you use this code, please credit the original author (thanhpc187) and include a link to this repository.

## 👤 Author & Copyright

**Copyright (c) 2024 thanhpc187**

- GitHub: [@thanhpc187](https://github.com/thanhpc187)
- Repository: [Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent](https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent)

See [AUTHORS.md](AUTHORS.md) for attribution requirements and academic use guidelines.

## 🙏 Acknowledgments

- Elastic Common Schema (ECS) for log normalization
- scikit-learn for Isolation Forest implementation
- SHAP for model explainability
- Streamlit for the dashboard framework

---

**Lưu ý**: Dự án này là một demo/POC. Để sử dụng trong môi trường production, cần:
- Mở rộng dataset và features
- Tối ưu hóa model performance
- Thêm logging và monitoring
- Cải thiện error handling và validation
