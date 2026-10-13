import os
import sys
import socket
import webbrowser
from threading import Timer
from waitress import serve
from app import app

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def open_browser():
    try:
        webbrowser.open_new("http://127.0.0.1:5000")
    except Exception as e:
        print(f"Could not open browser automatically: {e}")

if __name__ == '__main__':
    local_ip = get_local_ip()
    port = 5000
    
    print("=" * 65)
    print("🛡️   AI-SHIELD SOC PRODUCTION SERVER (WAITRESS)")
    print("=" * 65)
    print(f"  • Local Machine Access: http://127.0.0.1:{port}")
    print(f"  • Network / Lab Access: http://{local_ip}:{port}")
    print("  • Production Engine:    Waitress WSGI (Multi-Threaded)")
    print("  • Status:               ACTIVE & MONITORING READY")
    print("=" * 65)
    print("Opening browser automatically in 1.5 seconds...\n")
    
    Timer(1.5, open_browser).start()
    
    # Run production multi-threaded WSGI server
    serve(app, host='0.0.0.0', port=port, threads=8)
