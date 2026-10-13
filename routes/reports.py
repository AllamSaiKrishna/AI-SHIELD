import io
import csv
from flask import Blueprint, render_template, request, jsonify, Response
from database.db import get_db_connection, get_setting, set_setting, log_audit
from detection.model_loader import ModelLoader

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
def index():
    return render_template('reports.html', active_page='reports')

@reports_bp.route('/model')
def model_view():
    loader = ModelLoader.get_instance()
    return render_template('model.html', active_page='model', metadata=loader.metadata)

@reports_bp.route('/settings')
def settings_view():
    return render_template('settings.html', active_page='settings')

@reports_bp.route('/api/logs', methods=['GET'])
def get_logs():
    event_type = request.args.get('event_type', '')
    status = request.args.get('status', '')
    
    conn = get_db_connection()
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if status:
        query += " AND status = ?"
        params.append(status)
        
    query += " ORDER BY timestamp DESC LIMIT 100"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])

@reports_bp.route('/api/reports/export', methods=['GET'])
def export_csv():
    report_type = request.args.get('type', 'traffic') # 'traffic', 'alerts', 'audit'
    conn = get_db_connection()
    output = io.StringIO()
    writer = csv.writer(output)
    
    if report_type == 'alerts':
        writer.writerow(['Alert ID', 'Timestamp', 'Threat Type', 'Severity', 'Status', 'Source IP', 'Target IP', 'Confidence', 'Details'])
        rows = conn.execute("SELECT id, timestamp, threat_type, severity, status, src_ip, dst_ip, confidence, details FROM alerts ORDER BY timestamp DESC").fetchall()
        for r in rows:
            writer.writerow(list(r))
        filename = "ai_shield_alerts_export.csv"
        
    elif report_type == 'audit':
        writer.writerow(['Log ID', 'Timestamp', 'Event Type', 'Actor', 'Details', 'Status'])
        rows = conn.execute("SELECT id, timestamp, event_type, actor, details, status FROM audit_logs ORDER BY timestamp DESC").fetchall()
        for r in rows:
            writer.writerow(list(r))
        filename = "ai_shield_audit_logs.csv"
        
    else: # Default traffic
        writer.writerow(['Record ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Src Port', 'Dst Port', 'Duration', 'Packets', 'Bytes', 'Class', 'Confidence', 'Source Mode'])
        rows = conn.execute("SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, duration, packet_count, byte_count, predicted_class, confidence, source_mode FROM traffic_records ORDER BY timestamp DESC LIMIT 500").fetchall()
        for r in rows:
            writer.writerow(list(r))
        filename = "ai_shield_traffic_export.csv"
        
    conn.close()
    output.seek(0)
    
    log_audit('REPORT_EXPORTED', f"Exported {report_type} report to CSV", actor='SOC_OPERATOR')
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@reports_bp.route('/api/settings/update', methods=['POST'])
def update_settings():
    data = request.get_json() or {}
    threshold = data.get('detection_threshold')
    block_duration = data.get('block_duration_minutes')
    auto_block_sev = data.get('auto_block_severity')
    
    if threshold is not None:
        set_setting('detection_threshold', float(threshold))
    if block_duration is not None:
        set_setting('block_duration_minutes', int(block_duration))
    if auto_block_sev is not None:
        set_setting('auto_block_severity', auto_block_sev)
        
    log_audit('SETTINGS_UPDATED', "Security and detection settings updated by operator", actor='SOC_OPERATOR')
    return jsonify({'success': True, 'message': 'Settings saved successfully'})

@reports_bp.route('/api/system/reset', methods=['POST'])
def reset_demo():
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM traffic_records")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM prevention_actions")
    conn.close()
    
    log_audit('SYSTEM_RESET', "Cleared traffic records, alerts, and active blocks for demonstration reset", actor='SOC_OPERATOR')
    return jsonify({'success': True, 'message': 'Demo state cleared successfully'})
