from flask import Flask, request, render_template, jsonify
from check_attachment import scan_file, VT_API_KEY
import os
import requests

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan-attachment', methods=['POST'])
def scan_attachment():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    result = scan_file(file_path)
    return jsonify(result)

@app.route('/check-status/<analysis_id>', methods=['GET'])
def check_status(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return jsonify({
                "done": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "explanation": f"This file was flagged by {malicious + suspicious} security engines."
            })
        return jsonify({"done": False})
    else:
        return jsonify({"error": "Failed to check status"}), 500

if __name__ == '__main__':
    app.run(debug=True)
