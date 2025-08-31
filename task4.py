import sys
import json
import hashlib
import requests
import time

arguments = sys.argv

if len(arguments) != 4:
    print("Incorrect input format")
    print("Correct format: python task1.py input_file_path output_file_path API_KEY")
    sys.exit(1)

input_file_path = arguments[1]
output_file_path = arguments[2]
API_KEY = arguments[3]

# compute sha256 hash of the apk
sha256_hash = hashlib.sha256()
with open(input_file_path, "rb") as f:
    for block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(block)
apk_hash = sha256_hash.hexdigest()

# prepare virustotal url
url = f"https://www.virustotal.com/api/v3/files/{apk_hash}"
headers = {"x-apikey": API_KEY}

# send request to virustotal
response = requests.get(url, headers=headers)
if response.status_code == 429:
    # handle rate limit by waiting
    time.sleep(60)
    response = requests.get(url, headers=headers)

# handle case when file not found
if response.status_code == 404:
    vt_report = None
else:
    vt_report = response.json()

# parse response if data exists
if vt_report and "data" in vt_report and "attributes" in vt_report["data"]:
    attributes = vt_report["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})
    malicious_count = stats.get("malicious", 0)
    total_engines = sum(stats.values())
    detection_ratio = f"{malicious_count}/{total_engines}"
    
    # collect engines that flagged apk as malicious
    malicious_engines = []
    for engine_name, result in results.items():
        if result.get("category") == "malicious":
            malicious_engines.append(engine_name)
    
    output_data = {
        "sha256": apk_hash,
        "detection_ratio": detection_ratio,
        "malicious_engines": sorted(malicious_engines)
    }
else:
    # if no data is available
    output_data = {
        "sha256": apk_hash,
        "detection_ratio": "N/A",
        "malicious_engines": []
    }

# save json file
with open(output_file_path, "w", encoding="utf-8") as f:
    json.dump(output_data, f, indent=4, sort_keys=True)

print(f"json file created")
