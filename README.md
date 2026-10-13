# AI-SHIELD: AI-Powered Intrusion Detection and Prevention System (IDS/IPS)

**AI-SHIELD** is an enterprise-grade cybersecurity monitoring and automated response system. It bridges real-time network flow telemetry with machine learning multi-threat classification, dynamic incident triage, and automated firewall enforcement (IPS).

---

## 🚀 Key Highlights & Capabilities

- **8-Screen Integrated SOC Interface**:
  1. **Dashboard** (`/`): Real-time executive security posture, threat counters, dynamic charts (Volume & Attack distribution), and recent incident feeds.
  2. **Live Monitoring** (`/monitoring`): Real-time packet/flow sniffer and simulated telemetry generator with inline microsecond AI inference.
  3. **AI Threat Detection** (`/detection`): Interactive single-flow tester with attack presets (DoS, PortScan, Normal), plus batch CSV benchmark evaluation.
  4. **Alerts Center** (`/alerts`): SOC incident triage workflow with distinct **Acknowledge** and **Resolve** state transitions and modal flow inspection.
  5. **Prevention Center (IPS)** (`/prevention`): Automated and manual firewall enforcement (`netsh advfirewall` on Windows / Lab Sandbox), quarantine TTL timers, and whitelist protection.
  6. **Logs & Reports** (`/reports`): Immutable SQLite audit trail with one-click CSV report exports (Traffic, Alerts, Audit logs).
  7. **Dataset & Model** (`/model`): Architecture transparency, 10-feature schema dictionary, Gini feature importance explainability, and real confusion matrix.
  8. **Settings** (`/settings`): Detection threshold tuning, quarantine TTL configuration, and demo reset controls.

- **Real Machine Learning Engine**:
  - Model: Optimized **Random Forest Multi-Threat Classifier** (`n_estimators=120`, `max_depth=16`).
  - Preprocessing: `StandardScaler` pipeline.
  - Threat Classes: `Normal`, `DoS / DDoS`, `PortScan`, `Brute Force`, `Web Attack`.
  - Benchmark Performance: **99.93% Accuracy**, **99.93% F1-Score**.

- **Active IPS with Failsafe Guardrails**:
  - Netsh Windows Firewall integration for active IP quarantining.
  - Safeguard whitelist protecting localhost, loopback (`127.0.0.1`), and default gateways (`192.168.1.1`).
  - Verified lab sandbox fallback mode for safe non-elevated demonstrations.

---

## 🛠️ Quick Installation & Startup

1. **Install Dependencies**:
   ```bash
   py -m pip install -r requirements.txt
   ```

2. **Train / Verify Model Artifacts**:
   ```bash
   py detection/train_model.py
   ```

3. **Launch AI-SHIELD**:
   ```bash
   py app.py
   ```

4. **Access the Web Dashboard**:
   Open your browser at `http://127.0.0.1:5000`

---

## 📋 Evaluation Demonstration Script (Step-by-Step)

| Step | Action | Expected Evaluator Result |
| :---: | :--- | :--- |
| **1** | Open `http://127.0.0.1:5000` | High-tech dark SOC console displays "SYSTEM ARMED", zero errors, database connected. |
| **2** | Go to **Live Monitoring** & click **"Start Capture"** | Real-time traffic stream populates with normal browsing and telemetry packets. |
| **3** | Go to **AI Threat Detection** & click **"Preset: DoS"** $\rightarrow$ **"Execute AI Prediction"** | Instantly classifies flow as `DoS / DDoS` with >95% confidence. |
| **4** | Check **Alerts Center** (`/alerts`) | New critical alert appears. Click **"Inspect"** to show raw flow features, then click **"Ack"** and **"Resolve"**. |
| **5** | Switch to **Prevention Center** (`/prevention`) $\rightarrow$ Enable **"Auto-Block (IPS)"** | Enter test IP `192.168.1.185` and click **"Enforce Firewall Block"**. Shows verified quarantine and TTL. |
| **6** | Go to **Logs & Reports** (`/reports`) | Click **"Audit Trail CSV"** or **"Traffic CSV"** to demonstrate downloadable compliance evidence. |
