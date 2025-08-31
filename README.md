# Static-Analysis-of-an-APK-file-using-Androguard

## Instructions for Execution
- ensure **python 3.11.0** and **androguard 4.1.3** are installed  
- run inside a linux-compatible environment (e.g., conda virtual environment)  
- use the following command-line arguments for each task

  ---

  ## Summary of Implementation

  ### Task 1: AndroidManifest Analysis
- implemented in `task1.py` using **androguard**  
- extracts the following features from the apk’s `AndroidManifest`:  
  - package name  
  - activities, services, receivers, and content providers (with counts)  
  - aosp and third-party permissions (with counts)  
  - hardware features  
  - intent filters  
- all lists are sorted alphabetically, and json keys are sorted before saving  

**execution:**
```bash
python task1.py <input_apk_path> <output_json_path>
```

### Task 2: Certificate & Signature Analysis
- implemented in `task2.py` using **androguard** and **cryptography**  
- extracts certificate and signing details:
  - issuer
  - subject
  - serial number
  - validity period (not before & not after)
  - signature algorithm
  - md5, sha1, sha256 fingerprints
- if any field is missing, value is `"NA"`
- json keys are sorted before saving to file

**execution**
```bash
python task2.py <input_apk_path> <output_json_path>
```

### Task 3: DEX Code Feature Extraction
- implemented in `task3.py` using **androguard**  
- extracts features from dex code:
  - api call frequency
  - api package frequency
  - opcode frequency
  - reflection / dynamic / native usage (`Class.forName`, `DexClassLoader`, `System.loadLibrary`)
  - network addresses (ip addresses / domains)
  - used permissions (via provided pscout mapping json)
  - restricted apis (api requires permission not declared in manifest)
  - system commands and their frequency
- all outputs saved in json with sorted keys

**execution**
```bash
python task3.py <input_apk_path> <output_json_path>
```

### Task 4: VirusTotal Reputation Lookup
- implemented in `task4.py` using **requests**  
- computes sha256 hash of apk file
- queries **virustotal api v3** using user-provided api key
- extracts:
  - detection ratio (e.g., `8/72`)
  - malicious engines (sorted alphabetically)
- handles api rate limits (status `429`)
- if apk not found, sets detection ratio as `"N/A"`
- json keys and lists are sorted before saving

**execution**
```bash
python task4.py <input_apk_path> <output_json_path> <API_KEY>

