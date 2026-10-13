import os
from flask import Flask, jsonify
from config import Config
from database.db import init_db
from detection.model_loader import ModelLoader

# Import Blueprints
from routes.dashboard import dashboard_bp
from routes.monitoring import monitoring_bp
from routes.detection import detection_bp
from routes.alerts import alerts_bp
from routes.prevention import prevention_bp
from routes.reports import reports_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Database Schema & Settings
    init_db()

    # Preload Machine Learning Model & Preprocessor
    loader = ModelLoader.get_instance()
    if loader.is_loaded:
        print("[+] AI-SHIELD Model Engine loaded into memory successfully.")
    else:
        print("[!] Warning: Model artifacts not found. Run 'py detection/train_model.py' to generate.")

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(detection_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(prevention_bp)
    app.register_blueprint(reports_bp)

    @app.route('/api/health')
    def health():
        loader = ModelLoader.get_instance()
        return jsonify({
            'status': 'HEALTHY',
            'database': os.path.exists(Config.DATABASE_PATH),
            'model_loaded': loader.is_loaded,
            'classes': loader.metadata.get('classes', [])
        })

    @app.errorhandler(404)
    def page_not_found(e):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify({'error': 'Internal server error'}), 500

    return app

app = create_app()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  AI-SHIELD SOC Web Application Starting...")
    print("🌐  Access Dashboard at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
