from flask import Blueprint, render_template, request, jsonify
from config import Config
from database.db import get_setting, set_setting, get_db_connection, log_audit
from prevention.firewall import FirewallManager

prevention_bp = Blueprint('prevention', __name__)

@prevention_bp.route('/prevention')
def index():
    return render_template('prevention.html', active_page='prevention')

@prevention_bp.route('/api/prevention/status', methods=['GET'])
def get_status():
    mode = get_setting('prevention_mode', 'Alert Only')
    active_blocks = FirewallManager.get_active_blocks()
    
    return jsonify({
        'mode': mode,
        'active_blocks': active_blocks,
        'whitelist': Config.WHITELIST_IPS,
        'allowed_subnets': Config.ALLOWED_LAB_NETWORKS,
        'is_admin': FirewallManager.is_admin()
    })

@prevention_bp.route('/api/prevention/mode', methods=['POST'])
def set_mode():
    data = request.get_json() or {}
    new_mode = data.get('mode')
    if new_mode not in ['Disabled', 'Alert Only', 'Enabled']:
        return jsonify({'error': 'Invalid prevention mode'}), 400
        
    set_setting('prevention_mode', new_mode)
    log_audit('PREVENTION_MODE_CHANGED', f"Operator changed IPS prevention mode to {new_mode}", actor='SOC_OPERATOR')
    return jsonify({'success': True, 'mode': new_mode})

@prevention_bp.route('/api/prevention/block', methods=['POST'])
def block_ip():
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual Operator Block')
    duration = int(data.get('duration', 10))
    
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
        
    res = FirewallManager.block_ip(ip, reason=reason, duration_minutes=duration)
    return jsonify(res)

@prevention_bp.route('/api/prevention/unblock', methods=['POST'])
def unblock_ip():
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
        
    res = FirewallManager.unblock_ip(ip)
    return jsonify(res)

@prevention_bp.route('/api/prevention/history', methods=['GET'])
def get_history():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM prevention_actions 
        ORDER BY applied_at DESC 
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
