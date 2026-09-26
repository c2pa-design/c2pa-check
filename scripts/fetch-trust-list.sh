#!/usr/bin/env bash
set -euo pipefail

base="https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list"
out="$(dirname "$0")/../crates/c2pa-check-core/trust"

curl -fsSL "$base/C2PA-TRUST-LIST.pem" -o "$out/C2PA-TRUST-LIST.pem"
curl -fsSL "$base/C2PA-TSA-TRUST-LIST.pem" -o "$out/C2PA-TSA-TRUST-LIST.pem"
date -u +%Y-%m-%d > "$out/VERSION"

certs=$(grep -c "BEGIN CERTIFICATE" "$out/C2PA-TRUST-LIST.pem")
if [ "$certs" -lt 20 ]; then
  echo "refusing a trust list with only $certs certificates" >&2
  exit 1
fi

echo "official: $certs certificates"
echo "tsa:      $(grep -c 'BEGIN CERTIFICATE' "$out/C2PA-TSA-TRUST-LIST.pem") certificates"
