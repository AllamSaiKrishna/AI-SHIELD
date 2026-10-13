import os
from flask import Blueprint, render_template, request, jsonify
from config import Config
from detection.model_loader import ModelLoader
from detection.detector import Detector
from monitoring.dataset_reader import DatasetReader

detection_bp = Blueprint('detection', __name__)

@detection_bp.route('/detection')
def index():
    return render_template('detection.html', active_page='detection')

@detection_bp.route('/api/model/info', methods=['GET'])
def model_info():
    loader = ModelLoader.get_instance()
    return jsonify({
        'is_loaded': loader.is_loaded,
        'metadata': loader.metadata
    })

@detection_bp.route('/api/detection/predict', methods=['POST'])
def test_predict():
    data = request.get_json() or {}
    res = Detector.classify_flow(data, source_mode='manual_test')
    return jsonify(res)

@detection_bp.route('/api/dataset/analyze', methods=['POST'])
def analyze_dataset():
    # Check if a file was uploaded
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        temp_path = os.path.join(Config.DATASETS_DIR, 'uploaded_temp.csv')
        file.save(temp_path)
        res = DatasetReader.process_csv_batch(temp_path)
        return jsonify(res)
    else:
        # Fallback to preloaded benchmark suite
        benchmark_path = os.path.join(Config.DATASETS_DIR, 'test_attack_suite.csv')
        if os.path.exists(benchmark_path):
            res = DatasetReader.process_csv_batch(benchmark_path, max_rows=150)
            return jsonify(res)
        return jsonify({'error': 'No dataset provided and benchmark not found'}), 400
