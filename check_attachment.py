import requests
import hashlib
import os

VT_API_KEY = "a7a7576fc86eb99b25c11d72e3b9337467e89264a5b561d3f8db2b48657c5d0b"  # Replace with your actual VirusTotal API key

def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def scan_file(file_path):
    file_hash = get_file_hash(file_path)
    headers = {"x-apikey": VT_API_KEY}
    report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    # Check if file hash is known
    r = requests.get(report_url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        return {
            "file": os.path.basename(file_path),
            "malicious": malicious,
            "suspicious": suspicious,
            "explanation": f"This file was flagged by {malicious + suspicious} security engines.",
            "link": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
        }

    # Upload file to VirusTotal
    with open(file_path, "rb") as f:
        upload = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files={"file": f})

    if upload.status_code == 200:
        upload_data = upload.json()
        analysis_id = upload_data['data']['id']
        return {
            "file": os.path.basename(file_path),
            "status": "Uploaded for analysis",
            "note": "File is being analyzed...",
            "link": f"https://www.virustotal.com/gui/file/{file_hash}/detection",
            "analysis_id": analysis_id
        }

    return {"error": "VirusTotal scan failed", "status_code": upload.status_code}
