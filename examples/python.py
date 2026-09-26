import os
import sys
import urllib.request
import json

key = os.environ.get("C2PA_API_KEY")
url = sys.argv[1] if len(sys.argv) > 1 else None
if not key or not url:
    sys.exit("usage: C2PA_API_KEY=... python python.py <url>")

request = urllib.request.Request(
    "https://api.c2pa.design/v1/verifications",
    data=json.dumps({"url": url}).encode(),
    headers={"authorization": f"Bearer {key}", "content-type": "application/json"},
)

with urllib.request.urlopen(request) as response:
    result = json.load(response)["result"]

signer = (result.get("signer") or {}).get("organization", "no signer")
print(result["credential"]["status"], "·", signer)
sys.exit(0 if result["credential"]["status"] == "valid_trusted" else 1)
