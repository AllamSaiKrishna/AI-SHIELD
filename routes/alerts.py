from flask import Blueprint, render_template, request, jsonify
from database.db import get_db_connection, log_audit

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
def index():
    return render_template('alerts.html', active_page='alerts')

@alerts_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    
    conn = get_db_connection()
    query = """
        SELECT a.*, t.protocol, t.src_port, t.dst_port, t.duration, t.packet_count, t.byte_count, t.packet_rate
        FROM alerts a
        LEFT JOIN traffic_records t ON a.traffic_id = t.id
        WHERE 1=1
    """
    params = []
    
    if severity:
        query += " AND a.severity = ?"
        params.append(severity)
    if status:
        query += " AND a.status = ?"
        params.append(status)
    if search:
        query += " AND (a.src_ip LIKE ? OR a.threat_type LIKE ? OR a.details LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        
    query += " ORDER BY a.timestamp DESC LIMIT 100"
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])

@alerts_bp.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert_detail(alert_id):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT a.*, t.protocol, t.src_port, t.dst_port, t.duration, t.packet_count, t.byte_count, t.packet_rate
        FROM alerts a
        LEFT JOIN traffic_records t ON a.traffic_id = t.id
        WHERE a.id = ?
    """, (alert_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Alert not found'}), 404
        
    return jsonify(dict(row))

@alerts_bp.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE alerts SET status = 'Acknowledged' WHERE id = ?", (alert_id,))
    conn.close()
    log_audit('ALERT_ACKNOWLEDGED', f"Alert #{alert_id} marked as Acknowledged by operator", actor='SOC_OPERATOR')
    return jsonify({'success': True, 'alert_id': alert_id, 'status': 'Acknowledged'})

@alerts_bp.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    conn = get_db_connection()
    with conn:
        conn.execute("UPDATE alerts SET status = 'Resolved' WHERE id = ?", (alert_id,))
    conn.close()
    log_audit('ALERT_RESOLVED', f"Alert #{alert_id} resolved by operator", actor='SOC_OPERATOR')
    return jsonify({'success': True, 'alert_id': alert_id, 'status': 'Resolved'})
