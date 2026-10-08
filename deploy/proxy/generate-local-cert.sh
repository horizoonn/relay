#!/usr/bin/env bash
set -euo pipefail

proxy_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cert_dir="$proxy_dir/certs"
ca_dir="$proxy_dir/local-ca"

if [[ -e "$cert_dir/server.crt" || -e "$cert_dir/server.key" ||
      -e "$ca_dir/ca.crt" || -e "$ca_dir/ca.key" ]]; then
  echo 'Local TLS files already exist; refusing to replace them.' >&2
  exit 1
fi

umask 077
mkdir -p "$cert_dir" "$ca_dir"

request_file="$ca_dir/server.csr"
extensions_file="$ca_dir/server.ext"
trap 'rm -f "$request_file" "$extensions_file"' EXIT

openssl req -x509 -newkey rsa:3072 -sha256 -noenc -days 365 \
  -subj '/CN=Relay local development CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$ca_dir/ca.key" -out "$ca_dir/ca.crt"

openssl req -new -newkey rsa:2048 -sha256 -noenc \
  -subj '/CN=localhost' \
  -keyout "$cert_dir/server.key" -out "$request_file"

cat > "$extensions_file" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "$request_file" \
  -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" -CAcreateserial \
  -out "$cert_dir/server.crt" -days 30 -sha256 \
  -extfile "$extensions_file"

echo "Local certificate created. Trust $ca_dir/ca.crt on your host/browser."
