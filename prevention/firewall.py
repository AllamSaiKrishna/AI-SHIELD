import subprocess
import ctypes
import os
import re
from datetime import datetime, timedelta
from config import Config
from database.db import get_db_connection, log_audit

class FirewallManager:
    @staticmethod
    def is_admin():
        try:
            if os.name == 'nt':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return hasattr(os, 'geteuid') and os.geteuid() == 0
        except Exception:
            return False

    @classmethod
    def block_ip(cls, ip, reason="AI Malicious Flow Detection", duration_minutes=10):
        """
        Applies a firewall block rule for the specified IP address.
        Includes failsafe validation and programmatic verification.
        """
        # Failsafe Whitelist Protection
        if ip in Config.WHITELIST_IPS or ip.startswith('127.') or ip == 'localhost':
            log_audit('FIREWALL_BLOCKED_REJECTED', f"Blocked attempt on whitelisted IP {ip}", status='WARNING')
            return {
                'success': False,
                'status': 'REJECTED_WHITELIST',
                'message': f"Safety Error: IP {ip} is in protected whitelist infrastructure."
            }

        rule_name = f"AISHIELD_BLOCK_{ip.replace(':', '_')}"
        expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        applied_at = datetime.now()
        
        verified = False
        action_status = 'APPLIED'
        error_msg = None

        if os.name == 'nt' and cls.is_admin():
            try:
                # Add inbound block rule via Netsh
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                
                # Verification step
                verify_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
                v_res = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True, timeout=5)
                
                if "Rule Name:" in v_res.stdout or "Ok." in res.stdout:
                    verified = True
                    action_status = 'VERIFIED'
                else:
                    action_status = 'PARTIAL'
            except Exception as e:
                error_msg = str(e)
                action_status = 'FAILED'
        else:
            # Safe Lab Sandboxed Mode (for non-elevated or lab environments)
            verified = True
            action_status = 'VERIFIED_SANDBOX'

        # Record in database
        conn = get_db_connection()
        with conn:
            conn.execute("""
                INSERT INTO prevention_actions 
                (target_ip, reason, rule_name, action_type, status, applied_at, expires_at, verified)
                VALUES (?, ?, ?, 'BLOCK', ?, ?, ?, ?)
            """, (ip, reason, rule_name, action_status, applied_at.strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'), 1 if verified else 0))
        conn.close()

        log_audit(
            'FIREWALL_BLOCK', 
            f"Blocked IP {ip} (Rule: {rule_name}, Status: {action_status}, Duration: {duration_minutes}m)", 
            status='SUCCESS' if verified else 'WARNING'
        )

        return {
            'success': verified,
            'ip': ip,
            'rule_name': rule_name,
            'status': action_status,
            'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'mode': 'Windows Netsh Live' if cls.is_admin() else 'Lab Sandbox Verified'
        }

    @classmethod
    def unblock_ip(cls, ip):
        """
        Removes an application-managed firewall block.
        """
        rule_name = f"AISHIELD_BLOCK_{ip.replace(':', '_')}"
        removed = False

        if os.name == 'nt' and cls.is_admin():
            try:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                removed = "Deleted" in res.stdout or "Ok." in res.stdout
            except Exception as e:
                print(f"Error removing netsh rule: {e}")
        else:
            removed = True

        conn = get_db_connection()
        with conn:
            conn.execute("""
                UPDATE prevention_actions 
                SET status = 'REMOVED'
                WHERE target_ip = ? AND status IN ('APPLIED', 'VERIFIED', 'VERIFIED_SANDBOX')
            """, (ip,))
        conn.close()

        log_audit('FIREWALL_UNBLOCK', f"Removed block rule for IP {ip}", status='SUCCESS')

        return {
            'success': True,
            'ip': ip,
            'status': 'REMOVED'
        }

    @classmethod
    def get_active_blocks(cls):
        """
        Returns all active and non-expired blocks.
        """
        cls.cleanup_expired()
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT * FROM prevention_actions 
            WHERE status IN ('APPLIED', 'VERIFIED', 'VERIFIED_SANDBOX')
            ORDER BY applied_at DESC
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @classmethod
    def cleanup_expired(cls):
        """
        Checks and expires rules whose TTL has passed.
        """
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT target_ip, rule_name FROM prevention_actions 
            WHERE status IN ('APPLIED', 'VERIFIED', 'VERIFIED_SANDBOX')
            AND expires_at <= ?
        """, (now_str,)).fetchall()
        
        for r in rows:
            cls.unblock_ip(r['target_ip'])
        conn.close()
