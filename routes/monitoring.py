from flask import Blueprint, render_template, request, jsonify
from monitoring.capture import TrafficMonitor
from database.db import get_db_connection

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/monitoring')
def index():
    return render_template('monitoring.html', active_page='monitoring')

@monitoring_bp.route('/api/monitor/start', methods=['POST'])
def start_monitor():
    data = request.get_json() or {}
    mode = data.get('mode', 'simulation')
    interface = data.get('interface', 'Default (Ethernet/WiFi)')
    monitor = TrafficMonitor.get_instance()
    res = monitor.start(mode=mode, interface=interface)
    return jsonify(res)

@monitoring_bp.route('/api/monitor/stop', methods=['POST'])
def stop_monitor():
    monitor = TrafficMonitor.get_instance()
    res = monitor.stop()
    return jsonify(res)

@monitoring_bp.route('/api/traffic', methods=['GET'])
def get_traffic():
    limit = int(request.args.get('limit', 50))
    filter_class = request.args.get('class', '')
    filter_proto = request.args.get('protocol', '')
    search = request.args.get('search', '')
    
    conn = get_db_connection()
    query = "SELECT * FROM traffic_records WHERE 1=1"
    params = []
    
    if filter_class:
        query += " AND predicted_class = ?"
        params.append(filter_class)
    if filter_proto:
        query += " AND protocol = ?"
        params.append(filter_proto)
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])
