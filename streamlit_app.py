import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import json
from datetime import datetime

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="AI-SHIELD | IDS & IPS Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    .stApp {
        background-color: #070d19;
        color: #f1f5f9;
    }
    .main-header {
        font-size: 26px;
        font-weight: 800;
        color: #00d2ff;
        margin-bottom: 2px;
    }
    .sub-header {
        font-size: 13px;
        color: #94a3b8;
        margin-bottom: 20px;
    }
    .metric-card {
        background-color: #131f37;
        border: 1px solid #1e3156;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .badge-normal { background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-dos { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-portscan { background-color: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-bruteforce { background-color: rgba(168, 85, 247, 0.2); color: #a855f7; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-webattack { background-color: rgba(236, 72, 153, 0.2); color: #ec4899; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Backend Imports
from database.db import init_db, get_db_connection, get_setting, set_setting, log_audit
from detection.model_loader import ModelLoader
from detection.detector import Detector
from detection.feature_extractor import FeatureExtractor
from monitoring.capture import TrafficMonitor
from monitoring.dataset_reader import DatasetReader
from prevention.firewall import FirewallManager
from prevention.policy import PreventionPolicy
from config import Config

# Ensure Database & Model are Ready
init_db()
loader = ModelLoader.get_instance()

# Sidebar Navigation
st.sidebar.markdown("## 🛡️ **AI-SHIELD**")
st.sidebar.caption("AI-Powered Intrusion Detection & Prevention System")
st.sidebar.markdown("---")

# Telemetry in Sidebar
monitor = TrafficMonitor.get_instance()
prev_mode = get_setting('prevention_mode', 'Alert Only')

st.sidebar.markdown(f"**Engine Status:** {'🟢 Armed & Active' if loader.is_loaded else '🔴 Model Not Loaded'}")
st.sidebar.markdown(f"**IPS Mode:** `{prev_mode}`")
st.sidebar.markdown(f"**Capture Status:** {'🟢 Monitoring' if monitor.is_running else '🟡 Idle'}")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation Console",
    [
        "📊 Dashboard",
        "📡 Live Monitoring",
        "🧠 AI Threat Detection",
        "🚨 Alerts Center",
        "🛑 Prevention Center (IPS)",
        "📑 Logs & Reports",
        "🧬 Dataset & Model",
        "⚙️ Settings"
    ]
)

# -------------------------------------------------------------
# PAGE 1: DASHBOARD
# -------------------------------------------------------------
if menu == "📊 Dashboard":
    st.markdown('<div class="main-header">Executive Threat Overview</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Real-time AI threat intelligence and automated mitigation posture</div>', unsafe_allow_html=True)

    # Top Controls
    col_c1, col_c2, col_c3 = st.columns([1, 1, 2])
    with col_c1:
        if st.button("▶️ Start Traffic Monitor", use_container_width=True, type="primary"):
            monitor.start(mode='simulation')
            st.rerun()
    with col_c2:
        if st.button("⏹️ Stop Capture", use_container_width=True):
            monitor.stop()
            st.rerun()

    conn = get_db_connection()
    total_flows = conn.execute("SELECT COUNT(*) as c FROM traffic_records").fetchone()['c']
    normal_flows = conn.execute("SELECT COUNT(*) as c FROM traffic_records WHERE predicted_class = 'Normal'").fetchone()['c']
    malicious_flows = total_flows - normal_flows
    active_blocks = len(FirewallManager.get_active_blocks())

    # 4 Key Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Flows Analyzed", f"{total_flows:,}")
    m2.metric("Normal / Benign Flows", f"{normal_flows:,}")
    m3.metric("Confirmed Malicious", f"{malicious_flows:,}", delta=f"{malicious_flows} Threats", delta_color="inverse")
    m4.metric("Active IPS Blocks", f"{active_blocks}", delta="Quarantined")

    st.markdown("---")

    # Visualizations
    col_g1, col_g2 = st.columns([2, 1])

    with col_g1:
        st.subheader("Network Flow Ingestion Over Time")
        recent_flows = conn.execute("SELECT timestamp, predicted_class FROM traffic_records ORDER BY timestamp DESC LIMIT 60").fetchall()
        if recent_flows:
            df_recent = pd.DataFrame([dict(r) for r in recent_flows])
            df_recent['time'] = pd.to_datetime(df_recent['timestamp'])
            df_counts = df_recent.groupby([pd.Grouper(key='time', freq='5s'), 'predicted_class']).size().unstack(fill_value=0)
            st.line_chart(df_counts, use_container_width=True)
        else:
            st.info("Start traffic capture above to view live timeline.")

    with col_g2:
        st.subheader("Threat Classification Distribution")
        attack_rows = conn.execute("SELECT predicted_class, COUNT(*) as c FROM traffic_records GROUP BY predicted_class").fetchall()
        if attack_rows:
            df_atk = pd.DataFrame([dict(r) for r in attack_rows])
            df_atk.set_index('predicted_class', inplace=True)
            st.bar_chart(df_atk, use_container_width=True)
        else:
            st.info("Awaiting traffic data...")

    st.markdown("---")

    # Recent Alerts & Live Stream Snippet
    ra_col, rt_col = st.columns(2)
    with ra_col:
        st.subheader("Recent Security Alerts")
        recent_alerts = conn.execute("SELECT timestamp, threat_type, src_ip, severity, status FROM alerts ORDER BY timestamp DESC LIMIT 6").fetchall()
        if recent_alerts:
            st.dataframe(pd.DataFrame([dict(r) for r in recent_alerts]), use_container_width=True)
        else:
            st.write("No active threats detected.")

    with rt_col:
        st.subheader("Recent Ingested Flows")
        recent_traffic = conn.execute("SELECT src_ip, protocol, packet_count, predicted_class, confidence FROM traffic_records ORDER BY timestamp DESC LIMIT 6").fetchall()
        if recent_traffic:
            st.dataframe(pd.DataFrame([dict(r) for r in recent_traffic]), use_container_width=True)
        else:
            st.write("Awaiting traffic stream.")
    conn.close()

# -------------------------------------------------------------
# PAGE 2: LIVE MONITORING
# -------------------------------------------------------------
elif menu == "📡 Live Monitoring":
    st.markdown('<div class="main-header">Live Network Traffic Monitoring</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Real-time packet and flow inspection with inline AI inference</div>', unsafe_allow_html=True)

    c_mode, c_iface, c_act = st.columns([1.5, 1.5, 1])
    with c_mode:
        sel_mode = st.selectbox("Capture Mode", ["simulation", "dataset_replay", "live"], index=0)
    with c_iface:
        sel_iface = st.selectbox("Interface", ["Default Adapter (Ethernet/WiFi)", "Lab Virtual Network (192.168.1.0/24)", "Loopback (127.0.0.1)"])
    with c_act:
        st.write("")
        st.write("")
        if not monitor.is_running:
            if st.button("▶️ Start Capture", type="primary", use_container_width=True):
                monitor.start(mode=sel_mode, interface=sel_iface)
                st.rerun()
        else:
            if st.button("⏹️ Stop Capture", type="secondary", use_container_width=True):
                monitor.stop()
                st.rerun()

    st.markdown("---")

    # Filters
    f1, f2 = st.columns([1, 2])
    with f1:
        filter_cls = st.selectbox("Filter Class", ["All", "Normal", "DoS / DDoS", "PortScan", "Brute Force", "Web Attack"])
    with f2:
        search_ip = st.text_input("Search Source/Dest IP", "")

    conn = get_db_connection()
    q = "SELECT timestamp, src_ip, dst_ip, protocol, packet_count, byte_count, duration, predicted_class, confidence, source_mode FROM traffic_records WHERE 1=1"
    params = []
    if filter_cls != "All":
        q += " AND predicted_class = ?"
        params.append(filter_cls)
    if search_ip:
        q += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
        params.extend([f"%{search_ip}%", f"%{search_ip}%"])
    q += " ORDER BY timestamp DESC LIMIT 100"

    rows = conn.execute(q, params).fetchall()
    conn.close()

    if rows:
        st.dataframe(pd.DataFrame([dict(r) for r in rows]), use_container_width=True, height=450)
    else:
        st.info("No traffic records matching current filters. Click 'Start Capture' above.")

# -------------------------------------------------------------
# PAGE 3: AI THREAT DETECTION
# -------------------------------------------------------------
elif menu == "🧠 AI Threat Detection":
    st.markdown('<div class="main-header">AI Threat Detection & Inference Lab</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Inspect model predictions, test custom flow vectors, and benchmark datasets</div>', unsafe_allow_html=True)

    col_t1, col_t2 = st.columns([1, 1])

    with col_t1:
        st.subheader("Single-Flow Interactive Tester")
        
        # Presets
        preset = st.radio("Load Attack Presets:", ["Custom", "DoS / DDoS Burst", "PortScan Probe", "Normal Web Traffic"], horizontal=True)
        
        def_ip = "192.168.1.185"
        def_proto = "TCP"
        def_dur = 1.5
        def_pkts = 50
        def_bytes = 4000
        def_syn = 0.10
        def_ack = 0.85
        def_err = 0.02

        if preset == "DoS / DDoS Burst":
            def_ip, def_dur, def_pkts, def_bytes, def_syn, def_ack, def_err = "192.168.1.105", 2.4, 8500, 520000, 0.94, 0.02, 0.88
        elif preset == "PortScan Probe":
            def_ip, def_dur, def_pkts, def_bytes, def_syn, def_ack, def_err = "192.168.1.200", 0.05, 2, 80, 1.0, 0.0, 1.0
        elif preset == "Normal Web Traffic":
            def_ip, def_dur, def_pkts, def_bytes, def_syn, def_ack, def_err = "192.168.1.50", 1.8, 35, 2400, 0.08, 0.88, 0.01

        with st.form("single_flow_form"):
            s_ip = st.text_input("Source IP", def_ip)
            s_proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"], index=0)
            c_a, c_b = st.columns(2)
            with c_a:
                s_dur = st.number_input("Duration (seconds)", value=float(def_dur), step=0.1)
                s_pkts = st.number_input("Packet Count", value=int(def_pkts), step=1)
                s_syn = st.slider("SYN Flag Ratio", 0.0, 1.0, float(def_syn))
            with c_b:
                s_bytes = st.number_input("Byte Count", value=int(def_bytes), step=100)
                s_ack = st.slider("ACK Flag Ratio", 0.0, 1.0, float(def_ack))
                s_err = st.slider("SYN Error Rate", 0.0, 1.0, float(def_err))
            
            submit_btn = st.form_submit_button("⚡ Run AI Prediction", use_container_width=True, type="primary")

        if submit_btn:
            payload = {
                'src_ip': s_ip,
                'protocol': s_proto,
                'duration': s_dur,
                'packet_count': s_pkts,
                'byte_count': s_bytes,
                'syn_ratio': s_syn,
                'ack_ratio': s_ack,
                'serror_rate': s_err,
                'dst_host_count': 5
            }
            res = Detector.classify_flow(payload, source_mode="manual_test")
            st.success(f"**Classification:** `{res['predicted_class']}` | **Confidence:** `{res['confidence']*100:.2f}%` | **Severity:** `{res['severity']}` | **Action:** `{res['action_taken']}`")

    with col_t2:
        st.subheader("Batch Benchmark Dataset Evaluation")
        st.write("Compare model predictions against known ground-truth labels:")

        if st.button("🧪 Evaluate Preloaded Attack Suite (test_attack_suite.csv)", use_container_width=True):
            benchmark_path = os.path.join(Config.DATASETS_DIR, 'test_attack_suite.csv')
            res = DatasetReader.process_csv_batch(benchmark_path, max_rows=200)
            if res.get('metrics'):
                m = res['metrics']
                e1, e2, e3, e4 = st.columns(4)
                e1.metric("Accuracy", f"{m['accuracy']*100:.1f}%")
                e2.metric("Precision", f"{m['precision']*100:.1f}%")
                e3.metric("Recall", f"{m['recall']*100:.1f}%")
                e4.metric("F1-Score", f"{m['f1_score']*100:.1f}%")

            st.write("Classified Attack Distribution:")
            st.json(res.get('attack_counts', {}))

        st.markdown("---")
        uploaded_file = st.file_uploader("Upload Custom Flow CSV Dataset", type=['csv'])
        if uploaded_file is not None:
            temp_path = os.path.join(Config.DATASETS_DIR, 'streamlit_upload.csv')
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            res = DatasetReader.process_csv_batch(temp_path)
            st.write(f"Analyzed {res.get('total_processed', 0)} records:")
            st.dataframe(pd.DataFrame(res.get('records', [])), use_container_width=True)

# -------------------------------------------------------------
# PAGE 4: ALERTS CENTER
# -------------------------------------------------------------
elif menu == "🚨 Alerts Center":
    st.markdown('<div class="main-header">Security Alerts Incident Triage</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Investigate suspicious network intrusions and manage SOC workflow states</div>', unsafe_allow_html=True)

    col_flt1, col_flt2 = st.columns(2)
    with col_flt1:
        sev_filter = st.selectbox("Severity Filter", ["All", "Critical", "High", "Medium", "Low"])
    with col_flt2:
        stat_filter = st.selectbox("Status Filter", ["All", "New", "Acknowledged", "Resolved"])

    conn = get_db_connection()
    q = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if sev_filter != "All":
        q += " AND severity = ?"
        params.append(sev_filter)
    if stat_filter != "All":
        q += " AND status = ?"
        params.append(stat_filter)
    q += " ORDER BY timestamp DESC LIMIT 50"

    alerts = conn.execute(q, params).fetchall()

    if alerts:
        for a in alerts:
            with st.expander(f"Alert #{a['id']} - [{a['severity']}] {a['threat_type']} from {a['src_ip']} ({a['status']})"):
                st.write(f"**Timestamp:** {a['timestamp']}")
                st.write(f"**Target IP:** {a['dst_ip']}")
                st.write(f"**AI Confidence:** {a['confidence']*100:.2f}%")
                st.write(f"**Details:** {a['details']}")

                b_c1, b_c2, b_c3 = st.columns(3)
                with b_c1:
                    if a['status'] == 'New':
                        if st.button(f"Acknowledge #{a['id']}", key=f"ack_{a['id']}"):
                            conn.execute("UPDATE alerts SET status = 'Acknowledged' WHERE id = ?", (a['id'],))
                            conn.commit()
                            log_audit('ALERT_ACKNOWLEDGED', f"Alert #{a['id']} acknowledged", actor='SOC_OPERATOR')
                            st.rerun()
                with b_c2:
                    if a['status'] != 'Resolved':
                        if st.button(f"Resolve #{a['id']}", key=f"res_{a['id']}"):
                            conn.execute("UPDATE alerts SET status = 'Resolved' WHERE id = ?", (a['id'],))
                            conn.commit()
                            log_audit('ALERT_RESOLVED', f"Alert #{a['id']} resolved", actor='SOC_OPERATOR')
                            st.rerun()
                with b_c3:
                    if st.button(f"Quarantine IP {a['src_ip']}", key=f"blk_{a['id']}"):
                        FirewallManager.block_ip(a['src_ip'], reason=f"Quarantine from Alert #{a['id']}")
                        st.success(f"Quarantine rule applied for {a['src_ip']}")
                        st.rerun()
    else:
        st.info("No security alerts matching current filters.")
    conn.close()

# -------------------------------------------------------------
# PAGE 5: PREVENTION CENTER (IPS)
# -------------------------------------------------------------
elif menu == "🛑 Prevention Center (IPS)":
    st.markdown('<div class="main-header">Automated IPS Prevention Center</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Active firewall rule enforcement, endpoint quarantine, and safeguard whitelisting</div>', unsafe_allow_html=True)

    # Global Policy Mode
    st.subheader("Global IPS Enforcement Policy")
    col_p1, col_p2, col_p3 = st.columns(3)
    curr_mode = get_setting('prevention_mode', 'Alert Only')

    with col_p1:
        if st.button("Disabled", use_container_width=True, type="primary" if curr_mode == "Disabled" else "secondary"):
            set_setting('prevention_mode', 'Disabled')
            st.rerun()
    with col_p2:
        if st.button("Alert Only (IDS)", use_container_width=True, type="primary" if curr_mode == "Alert Only" else "secondary"):
            set_setting('prevention_mode', 'Alert Only')
            st.rerun()
    with col_p3:
        if st.button("🛡️ Auto-Block (IPS)", use_container_width=True, type="primary" if curr_mode == "Enabled" else "secondary"):
            set_setting('prevention_mode', 'Enabled')
            st.rerun()

    st.markdown("---")

    col_b1, col_b2 = st.columns([2, 1])

    with col_b1:
        st.subheader("Active Quarantined IP Addresses")
        active = FirewallManager.get_active_blocks()
        if active:
            for b in active:
                c_ip, c_rsn, c_exp, c_btn = st.columns([2, 3, 2, 1.5])
                c_ip.write(f"`{b['target_ip']}`")
                c_rsn.write(b['reason'])
                c_exp.write(f"Expires: {b['expires_at'].split(' ')[1] if b['expires_at'] else '10m'}")
                if c_btn.button("Unblock", key=f"un_{b['target_ip']}"):
                    FirewallManager.unblock_ip(b['target_ip'])
                    st.rerun()
        else:
            st.info("No IP addresses currently quarantined.")

    with col_b2:
        st.subheader("Manual Lab Quarantine")
        with st.form("manual_block_form"):
            t_ip = st.text_input("Target Test IP", "192.168.1.185")
            t_dur = st.number_input("Duration (Minutes)", value=10, min_value=1)
            t_rsn = st.text_input("Reason", "Manual Operator Evaluation Block")
            b_submit = st.form_submit_button("⛔ Enforce Block Rule", use_container_width=True)

        if b_submit:
            res = FirewallManager.block_ip(t_ip, reason=t_rsn, duration_minutes=t_dur)
            if res.get('success'):
                st.success(f"Quarantined {t_ip} successfully ({res.get('status')})")
                st.rerun()
            else:
                st.error(res.get('message', 'Block failed'))

# -------------------------------------------------------------
# PAGE 6: LOGS & REPORTS
# -------------------------------------------------------------
elif menu == "📑 Logs & Reports":
    st.markdown('<div class="main-header">Audit Logs & Compliance Reporting</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Immutable SQLite security logs and exportable forensics</div>', unsafe_allow_html=True)

    # One-click Downloads
    conn = get_db_connection()
    c_d1, c_d2, c_d3 = st.columns(3)
    
    with c_d1:
        traffic_df = pd.DataFrame([dict(r) for r in conn.execute("SELECT * FROM traffic_records ORDER BY timestamp DESC LIMIT 300").fetchall()])
        st.download_button("📥 Download Traffic CSV", traffic_df.to_csv(index=False), "traffic_records.csv", "text/csv", use_container_width=True)
    with c_d2:
        alerts_df = pd.DataFrame([dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()])
        st.download_button("🚨 Download Alerts CSV", alerts_df.to_csv(index=False), "alerts_export.csv", "text/csv", use_container_width=True)
    with c_d3:
        audit_df = pd.DataFrame([dict(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC").fetchall()])
        st.download_button("📑 Download Audit Trail CSV", audit_df.to_csv(index=False), "audit_logs.csv", "text/csv", use_container_width=True)

    st.markdown("---")
    st.subheader("Persistent Audit Log Stream")
    logs = conn.execute("SELECT id, timestamp, event_type, actor, details, status FROM audit_logs ORDER BY timestamp DESC LIMIT 60").fetchall()
    st.dataframe(pd.DataFrame([dict(r) for r in logs]), use_container_width=True)
    conn.close()

# -------------------------------------------------------------
# PAGE 7: DATASET & MODEL
# -------------------------------------------------------------
elif menu == "🧬 Dataset & Model":
    st.markdown('<div class="main-header">Dataset & AI Model Architecture</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Underlying machine learning architecture, feature schema, and evaluation matrix</div>', unsafe_allow_html=True)

    meta = loader.metadata
    c_m1, c_m2, c_m3 = st.columns(3)
    c_m1.metric("Classifier", "Random Forest (120 Trees)")
    c_m2.metric("Accuracy", f"{meta.get('accuracy', 0.999)*100:.2f}%")
    c_m3.metric("F1-Score", f"{meta.get('f1_score', 0.999)*100:.2f}%")

    st.markdown("---")
    st.subheader("Gini Feature Importance Ranking (Explainability)")
    if meta.get('feature_importances'):
        df_imp = pd.DataFrame(list(meta['feature_importances'].items()), columns=['Feature', 'Importance']).sort_values(by='Importance', ascending=True)
        df_imp.set_index('Feature', inplace=True)
        st.bar_chart(df_imp, use_container_width=True)

    st.subheader("Holdout Confusion Matrix")
    if meta.get('confusion_matrix'):
        cm = np.array(meta['confusion_matrix'])
        classes = ['Normal', 'DoS', 'PortScan', 'BruteForce', 'WebAttack']
        st.dataframe(pd.DataFrame(cm, index=classes, columns=classes), use_container_width=True)

# -------------------------------------------------------------
# PAGE 8: SETTINGS
# -------------------------------------------------------------
elif menu == "⚙️ Settings":
    st.markdown('<div class="main-header">System Settings & Operational Guardrails</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Configure detection sensitivities, firewall policies, and lab scope constraints</div>', unsafe_allow_html=True)

    with st.form("settings_form"):
        th = st.slider("AI Alert Confidence Threshold", 0.50, 0.95, float(get_setting('detection_threshold', 0.70)))
        dur = st.number_input("Auto-Block Quarantine Duration (Minutes)", value=int(get_setting('block_duration_minutes', 10)), min_value=1)
        sev = st.selectbox("Minimum Auto-Block Severity", ["Critical", "High", "Medium"], index=0)
        s_btn = st.form_submit_button("💾 Save Settings", use_container_width=True)

    if s_btn:
        set_setting('detection_threshold', th)
        set_setting('block_duration_minutes', dur)
        set_setting('auto_block_severity', sev)
        st.success("Settings saved successfully!")

    st.markdown("---")
    if st.button("⚠️ Reset Demonstration Records (Clears Flows & Alerts)", type="secondary"):
        conn = get_db_connection()
        conn.execute("DELETE FROM traffic_records")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM prevention_actions")
        conn.commit()
        conn.close()
        st.success("Demo records reset!")
        st.rerun()
