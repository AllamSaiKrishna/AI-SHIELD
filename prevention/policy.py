import ipaddress
from config import Config
from database.db import get_setting, log_audit
from prevention.firewall import FirewallManager

class PreventionPolicy:
    @classmethod
    def is_in_lab_scope(cls, ip):
        """
        Validates if target IP is in the authorized lab scope.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in Config.ALLOWED_LAB_NETWORKS:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            return False
        except ValueError:
            return False

    @classmethod
    def evaluate_and_respond(cls, src_ip, threat_type, severity, confidence):
        """
        Evaluates the current IPS policy and executes authorized automated response.
        """
        mode = get_setting('prevention_mode', 'Alert Only')
        
        if mode == 'Disabled':
            return 'Logged Only'
            
        if mode == 'Alert Only':
            return 'Alert Dispatched'
            
        if mode == 'Enabled':
            # Check if threat severity qualifies for automated block
            min_severity = get_setting('auto_block_severity', 'Critical')
            severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
            
            if severity_order.get(severity, 1) < severity_order.get(min_severity, 4):
                return 'Alert Only (Below Block Threshold)'
                
            # Check lab network authorization
            if not cls.is_in_lab_scope(src_ip):
                log_audit('IPS_OUT_OF_SCOPE', f"IP {src_ip} outside authorized lab scope. Automated block skipped.", status='WARNING')
                return 'Alert Only (Outside Authorized Lab Subnet)'
                
            # Check if already active
            active = FirewallManager.get_active_blocks()
            if any(b['target_ip'] == src_ip for b in active):
                return 'Already Quarantined'
                
            duration = int(get_setting('block_duration_minutes', 10))
            res = FirewallManager.block_ip(
                ip=src_ip, 
                reason=f"Automated IPS: {threat_type} [{severity}] ({confidence*100:.1f}%)", 
                duration_minutes=duration
            )
            
            if res.get('success'):
                return f"Auto-Blocked ({res.get('status')})"
            else:
                return f"Block Failed: {res.get('message', 'Error')}"
                
        return 'Logged'
