#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir=$(mktemp -d)
container="relay-proxy-test-$$"
proxy_image=$(sed -n 's/^    image: //p' "$root_dir/deploy/compose/proxy/compose.yml")

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$work_dir/server.key" -out "$work_dir/server.crt" >/dev/null 2>&1
# Keep the production template; substitute only the unavailable test upstream.
sed 's/set $content_upstream content:8080;/set $content_upstream 127.0.0.1:65535;/' \
  "$root_dir/deploy/proxy/default.conf.template" > "$work_dir/default.conf.template"

for https_port in 443 8443; do
  docker run -d --name "$container" --network none \
    -e RELAY_SERVER_NAME=localhost -e RELAY_HTTPS_PORT="$https_port" \
    -e 'NGINX_ENVSUBST_FILTER=RELAY_SERVER_NAME|RELAY_HTTPS_PORT' \
    --mount "type=bind,src=$work_dir/default.conf.template,dst=/etc/nginx/templates/default.conf.template,readonly" \
    --mount "type=bind,src=$work_dir,dst=/etc/nginx/certs,readonly" \
    "$proxy_image" >/dev/null

  marker="relay-private-log-marker-$https_port"
  location=$(docker exec "$container" curl -sS --retry 5 --retry-connrefused --retry-delay 1 \
    -o /dev/null -w '%{redirect_url}' "http://localhost/review-probe?secret=$marker")
  authority=localhost
  if [[ "$https_port" != 443 ]]; then
    authority="localhost:$https_port"
  fi
  if [[ "$location" != "https://$authority/review-probe?secret=$marker" ]]; then
    echo "HTTP redirect did not preserve HTTPS port $https_port" >&2
    exit 1
  fi

  status=$(docker exec "$container" curl -ksS -o /dev/null -w '%{http_code}' \
    -H "Referer: https://localhost/private?secret=$marker" \
    "https://localhost/api/v1/items/search?q=$marker")
  [[ "$status" == 502 ]] || { echo 'Expected an upstream failure' >&2; exit 1; }
  status=$(docker exec "$container" curl -ksS -o /dev/null -w '%{http_code}' \
    "https://localhost/$marker")
  [[ "$status" == 404 ]] || { echo 'Unknown route must return 404' >&2; exit 1; }

  docker exec "$container" nginx -s quit >/dev/null 2>&1
  [[ "$(docker wait "$container")" == 0 ]]
  docker logs "$container" > "$work_dir/logs" 2>&1
  if grep -Fq "$marker" "$work_dir/logs"; then
    echo 'Private request data appeared in proxy logs' >&2
    exit 1
  fi
  python3 - "$work_dir/logs" <<'PY'
import json
import sys
from pathlib import Path

records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith('{')]
assert {record['status'] for record in records} >= {308, 404, 502}, 'HTTP failures must remain observable'
assert all({'method', 'request_id', 'duration_seconds', 'upstream_status'} <= record.keys() for record in records)
PY
  docker rm "$container" >/dev/null
  echo "Proxy redirect and log privacy passed for HTTPS port $https_port"
done
