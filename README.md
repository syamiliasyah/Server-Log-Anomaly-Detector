# Server-Log-Anomaly-Detector

# Server Log Anomaly Detector (Mini SIEM)

A lightweight Log Auditing & Threat Detection tool built with Python to parse server logs, detect SSH brute-force attacks, and identify malicious web directory probing (fuzzing).

## 📌 Features
- **Brute-Force Detection:** Parses log files for failed authentication thresholds.
- **Directory Probing Alert:** Identifies requests targeting sensitive endpoints (`/.env`, `/admin`).
- **SIEM Reporting:** Outputs structured security logs for incident response auditing.

## 🛠️ Project Structure
- `log_anomaly_detector.py` - Main log parsing logic using Regex.
- `log_parser_rules.py` - Regular Expression pattern matching rules.
- `mock_logs_generator.py` - Script generating sample audit logs for testing.

## 🚀 How to Run
```bash
python log_anomaly_detector.py
