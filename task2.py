import sys
import json
from androguard.core.apk import APK
from cryptography import x509
from cryptography.hazmat.primitives import hashes

arguments = sys.argv

if len(arguments) != 3:
    print("Incorrect input format")
    print("Correct format: python task1.py input_file_path output_json_path")

input_file_path = arguments[1]
output_json_path = arguments[2]

# load apk
apk_obj = APK(input_file_path)

# extract certificates depending on signature version
certs = []
if apk_obj.is_signed_v3():
    certs = apk_obj.get_certificates_der_v3()
elif apk_obj.is_signed_v2():
    certs = apk_obj.get_certificates_der_v2()
elif apk_obj.is_signed():
    certs = [cert.dump() for cert in apk_obj.get_certificates()]

if not certs:
    print("APK is not signed")

# parse certificate
cert = x509.load_der_x509_certificate(certs[0])

# extract fields safely
try:
    Issuer = cert.issuer.rfc4514_string()
except:
    Issuer = "NA"
try:
    Subject = cert.subject.rfc4514_string()
except:
    Subject = "NA"
try:
    Serial_no = str(cert.serial_number)
except:
    Serial_no = "NA"
try:
    Not_before = cert.not_valid_before_utc.isoformat()
except:
    Not_before = "NA"
try:
    Not_after = cert.not_valid_after_utc.isoformat()
except:
    Not_after = "NA"
try:
    Signature_algorithm = cert.signature_algorithm_oid._name
except:
    Signature_algorithm = "NA"
try:
    md5 = cert.fingerprint(hashes.MD5()).hex()
except:
    md5 = "NA"
try:
    sha1 = cert.fingerprint(hashes.SHA1()).hex()
except:
    sha1 = "NA"
try:
    sha256 = cert.fingerprint(hashes.SHA256()).hex()
except:
    sha256 = "NA"

# store extracted info in dict
dict_cert = {
    "issuer" : Issuer,
    "subject" : Subject,
    "serial_no" : Serial_no,
    "validity_period" : {
        "not_before" : Not_before,
        "not_after" : Not_after
    },
    "signature_algorithm" : Signature_algorithm,
    "MD5" : md5,
    "SHA1" : sha1,
    "SHA256" : sha256
}

# save json
with open(output_json_path, "w", encoding="utf-8") as file:
    json.dump(dict_cert, file, indent=4, sort_keys = True)

print("json file created")
