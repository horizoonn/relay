#!/usr/bin/env bash
set -euo pipefail

deploy_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key_dir="$deploy_dir/identity/keys"

if [[ -e "$key_dir/signing.pem" || -e "$key_dir/public.pem" ]]; then
  echo 'Identity key files already exist; refusing to replace them.' >&2
  exit 1
fi

umask 077
mkdir -p "$key_dir"
chmod 700 "$key_dir"
openssl genpkey -algorithm ED25519 -out "$key_dir/signing.pem"
openssl pkey -in "$key_dir/signing.pem" -pubout -out "$key_dir/public.pem"

chmod 444 "$key_dir/signing.pem"
chmod 644 "$key_dir/public.pem"
echo 'Local Identity signing key created. Keep its key ID stable while using it.'
