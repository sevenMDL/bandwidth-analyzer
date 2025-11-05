# 📊 Bandwidth Analyzer Pro

**Professional Router Traffic Analytics & Reset Detection Tool**

This tool analyzes router bandwidth logs to detect resets, visualize usage patterns, and generate insights — all locally and securely.

---

## 🚀 Features
- Detects **router counter resets** and missing log segments automatically  
- Aggregates and visualizes **daily, weekly, and monthly bandwidth usage**
- **Color-coded terminal output** for quick diagnostics
- Supports **exporting CSV summaries** and **interactive charts**
- Works seamlessly with periodic router log captures or traffic snapshots

---

## 🧠 How It Works
The analyzer scans the `bandwidth/` directory for log snapshots (e.g., `traffic_snapshot_20251104_215101.txt`) and aggregates the results.

It intelligently detects:
- Counter wraparounds
- Sudden drop anomalies
- Unreported data gaps due to router reboots or ISP resets

---

## 🧩 Example Usage
```bash
# Analyze recent traffic data
./analyze_bandwidth.py

# Export reports to CSV and generate charts
./analyze_bandwidth.py --export --charts
```

---

📂 Directory Structure

bandwidth-analyzer/
├── analyze_bandwidth.py
├── .bandwidth_analyzer_cache
├── bandwidth/
│   ├── charts/
│   ├── exports/
│   └── logs...


---

⚙️ Requirements

Python 3.8+

See requirements.txt for full dependencies.


Install with:

pip install -r requirements.txt


---

🧾 License

MIT License © 2025 sevenMDL


---

🌍 Author

Developed by sevenMDL
GitHub: @sevenMDL

