from flask import Blueprint, render_template, jsonify
from database.db import get_db_connection, get_setting
from detection.model_loader import ModelLoader
from monitoring.capture import TrafficMonitor
from prevention.firewall import FirewallManager

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    return render_template('dashboard.html', active_page='dashboard')

@dashboard_bp.route('/api/status', methods=['GET'])
def get_status():
    monitor = TrafficMonitor.get_instance()
    loader = ModelLoader.get_instance()
    prev_mode = get_setting('prevention_mode', 'Alert Only')
    
    return jsonify({
        'status': 'Online',
        'monitoring': monitor.get_status(),
        'model_loaded': loader.is_loaded,
        'model_name': loader.metadata.get('model_name', 'Not Loaded'),
        'prevention_mode': prev_mode,
        'is_admin': FirewallManager.is_admin()
    })

@dashboard_bp.route('/api/metrics', methods=['GET'])
def get_metrics():
    conn = get_db_connection()
    
    # Total flows
    total_flows = conn.execute("SELECT COUNT(*) as count FROM traffic_records").fetchone()['count']
    normal_flows = conn.execute("SELECT COUNT(*) as count FROM traffic_records WHERE predicted_class = 'Normal'").fetchone()['count']
    malicious_flows = total_flows - normal_flows
    
    # Active alerts
    total_alerts = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()['count']
    unresolved_alerts = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE status != 'Resolved'").fetchone()['count']
    
    # Active blocks
    active_blocks = len(FirewallManager.get_active_blocks())
    
    # Attack class breakdown
    attack_rows = conn.execute("""
        SELECT predicted_class, COUNT(*) as count 
        FROM traffic_records 
        GROUP BY predicted_class
    """).fetchall()
    breakdown = {r['predicted_class']: r['count'] for r in attack_rows}
    
    # Recent alerts
    recent_alerts = conn.execute("""
        SELECT * FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 6
    """).fetchall()
    
    # Recent traffic records
    recent_traffic = conn.execute("""
        SELECT * FROM traffic_records 
        ORDER BY timestamp DESC 
        LIMIT 10
    """).fetchall()
    
    conn.close()
    
    return jsonify({
        'total_flows': total_flows,
        'normal_flows': normal_flows,
        'malicious_flows': malicious_flows,
        'total_alerts': total_alerts,
        'unresolved_alerts': unresolved_alerts,
        'active_blocks': active_blocks,
        'breakdown': breakdown,
        'recent_alerts': [dict(a) for a in recent_alerts],
        'recent_traffic': [dict(t) for t in recent_traffic]
    })
