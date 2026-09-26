#!/usr/bin/env bash
set -euo pipefail

: "${C2PA_API_KEY:?export C2PA_API_KEY=c2pa_live_...}"
url="${1:?usage: curl.sh <url>}"

curl -fsS https://api.c2pa.design/v1/verifications \
  -H "authorization: Bearer $C2PA_API_KEY" \
  -H "content-type: application/json" \
  -d "{\"url\":\"$url\"}" \
| jq -e '.result.credential.status == "valid_trusted"' > /dev/null \
  || { echo "not trusted"; exit 1; }

echo "trusted"
