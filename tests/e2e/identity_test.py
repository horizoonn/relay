#!/usr/bin/env python3
"""Run Identity and Content rate-limit checks through curl and an isolated HTTPS Compose stack."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
os.umask(0o077)


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        # Emit infrastructure errors only, never captured HTTP payloads or service logs.
        lines = result.stderr.splitlines()
        infrastructure = [line for line in lines if any(term in line.lower() for term in
                          ("error response from daemon", "failed to", "invalid", "allocation", "overlap", "ports"))]
        detail = "\n".join(infrastructure[-5:])
        raise RuntimeError(f"{args[0]} exited with {result.returncode}: {detail}")
    return result.stdout


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def proxy_subnet():
    ids = run(["docker", "network", "ls", "-q"]).split()
    networks = json.loads(run(["docker", "network", "inspect", *ids])) if ids else []
    used = [ipaddress.ip_network(item["Subnet"]) for network in networks
            for item in (network.get("IPAM", {}).get("Config") or []) if item.get("Subnet")]
    for third in range(200, 254):
        candidate = ipaddress.ip_network(f"172.31.{third}.0/28")
        if not any(candidate.overlaps(existing) for existing in used):
            return str(candidate)
    raise RuntimeError("no free test proxy subnet")


def check_content(request, compose, work, private):
    marker = "content-rate-runtime-" + secrets.token_hex(8)
    credentials = {"email": f"{marker}@example.com", "password": "correct password with sufficient length"}
    request("register owner", "POST", "/api/v1/auth/register", 201, credentials)
    jars = [work / f"content-owner-{index}.cookies" for index in range(2)]
    for jar in jars:
        request("login owner", "POST", "/api/v1/auth/login", 200, credentials, jar)
        jar.write_bytes((work / "next.cookies").read_bytes())
    second = work / "second-owner.cookies"
    other = {"email": f"other-{marker}@example.com", "password": credentials["password"]}
    request("register second owner", "POST", "/api/v1/auth/register", 201, other)
    request("login second owner", "POST", "/api/v1/auth/login", 200, other, second)
    second.write_bytes((work / "next.cookies").read_bytes())
    body = {"source_type": "text", "text": marker}
    receipt = request("capture", "POST", "/api/v1/items", 201, body, jars[0],
                      extra_headers=["Idempotency-Key: capture-1"])
    path = "/api/v1/items/" + receipt["item_id"]
    request("capture shared across sessions", "POST", "/api/v1/items", 429, body, jars[1],
            extra_headers=["Idempotency-Key: capture-2"])
    request("get item", "GET", path, 200, jar=jars[0])
    for collection in ("recent", "library", "later"):
        request(f"shared read {collection}", "GET", f"/api/v1/items/{collection}", 429, jar=jars[1])
    request("search", "GET", f"/api/v1/items/search?q={marker}", 200, jar=jars[0])
    request("search shared across sessions", "GET", "/api/v1/items/search?q=other", 429, jar=jars[1])
    request("patch", "PATCH", path, 200, {"keep": True}, jars[0],
            extra_headers=["Content-Type: application/merge-patch+json"])
    request("shared mutation delete", "DELETE", path, 429, jar=jars[1])
    request("different owner budget", "GET", "/api/v1/items/recent", 200, jar=second)
    request("Identity quota independent", "GET", "/api/v1/auth/session", 200, jar=jars[0])
    compose("stop", "redis")
    request("outage get", "GET", path, 200, jar=jars[0])
    request("foreign item stays private", "GET", path, 404, jar=second)
    for collection in ("recent", "library", "later"):
        request(f"outage {collection}", "GET", f"/api/v1/items/{collection}", 200, jar=jars[0])
    request("outage search", "GET", f"/api/v1/items/search?q={marker}", 200, jar=jars[0])
    # A replay is charged but leaves the original persisted Capture intact.
    replay = request("outage capture replay", "POST", "/api/v1/items", 201, body, jars[0],
                     extra_headers=["Idempotency-Key: capture-1"])
    assert replay["item_id"] == receipt["item_id"]
    request("outage patch", "PATCH", path, 200, {"keep": False}, jars[0],
            extra_headers=["Content-Type: application/merge-patch+json"])
    request("outage delete", "DELETE", path, 204, jar=jars[0])
    request("deleted item", "GET", path, 404, jar=jars[0])
    request("Identity outage login", "POST", "/api/v1/auth/login", 503, credentials)
    compose("stop", "identity")
    request("valid access survives Identity stop", "GET", "/api/v1/items/recent", 200, jar=jars[0])
    # Keep production TTL unchanged. Sign a short-lived fixture with this stack's test key.
    fields = next(line.split("\t") for line in jars[0].read_text().splitlines()
                  if len(line.split("\t")) == 7 and line.split("\t")[5] == "__Host-relay_access")
    parts = fields[6].split(".")
    claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    claims["iat"], claims["exp"] = int(time.time()), int(time.time()) + 3
    payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
    signing_input = work / "short-access.input"
    signature = work / "short-access.signature"
    signing_input.write_text(parts[0] + "." + payload)
    run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
         "-in", str(signing_input), "-out", str(signature)])
    fields[6] = signing_input.read_text() + "." + base64.urlsafe_b64encode(signature.read_bytes()).decode().rstrip("=")
    short_jar = work / "short-access.cookies"
    short_jar.write_text("\t".join(fields) + "\n")
    request("short access accepted", "GET", "/api/v1/items/recent", 200, jar=short_jar)
    # The test runner and service can have different clocks. Wait for the service
    # to reject the token instead of assuming a fixed wall-clock sleep is enough.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = request("wait for access expiry", "GET", "/api/v1/items/recent", (200, 401), jar=short_jar)
        if response.get("code") == "UNAUTHENTICATED":
            assert response["status"] == 401
            break
        time.sleep(0.25)
    else:
        raise AssertionError("Content continued accepting the short-lived access token")
    print("expired access rejected with Identity stopped: 401", flush=True)
    return marker, credentials["password"]


def check_account(request, email_token, email_message, work, compose):
    credentials = {"email": "account-recovery-" + secrets.token_hex(8) + "@example.com",
                   "password": "original-password-with-sufficient-length"}
    request("register without session", "POST", "/api/v1/auth/register", 201, credentials)
    request("unverified login rejected", "POST", "/api/v1/auth/login", 403, credentials)
    verification = email_token(credentials["email"], "Confirm your Relay email")
    request("confirm email", "POST", "/api/v1/auth/email/verification", 204, {"token": verification})
    request("verification is single use", "POST", "/api/v1/auth/email/verification", 400, {"token": verification})
    jar = work / "recovery.cookies"
    request("verified login", "POST", "/api/v1/auth/login", 200, credentials, jar)
    jar.write_bytes((work / "next.cookies").read_bytes())
    request("unknown recovery is generic", "POST", "/api/v1/auth/password/reset-requests", 202, {"email": "unknown-" + credentials["email"]})
    compose("stop", "mailpit")
    request("request recovery while SMTP is down", "POST", "/api/v1/auth/password/reset-requests", 202, {"email": credentials["email"]})
    time.sleep(1.2)
    compose("start", "mailpit")
    reset = email_token(credentials["email"], "Reset your Relay password")
    request("wrong token purpose", "POST", "/api/v1/auth/email/verification", 400, {"token": reset})
    request("weak replacement rejected", "POST", "/api/v1/auth/password/reset", 400, {"token": reset, "password": "short"})
    password = "replacement-password-with-sufficient-length"
    request("reset password", "POST", "/api/v1/auth/password/reset", 204, {"token": reset, "password": password})
    notice = email_message(credentials["email"], "Your Relay password was changed")
    assert "#token=" not in notice and password not in notice and credentials["password"] not in notice
    print("password change notification delivered without credentials", flush=True)
    request("reset is single use", "POST", "/api/v1/auth/password/reset", 400, {"token": reset, "password": password})
    request("old session revoked", "GET", "/api/v1/auth/session", 401, jar=jar)
    request("old refresh revoked", "POST", "/api/v1/auth/refresh", 401, jar=jar)
    request("old password rejected", "POST", "/api/v1/auth/login", 401, credentials)
    credentials["password"] = password
    request("new password login", "POST", "/api/v1/auth/login", 200, credentials)
    request("verified email resend is generic", "POST", "/api/v1/auth/email/verification-requests", 202, {"email": credentials["email"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--content", action="store_true", help="Check Content budgets with real Identity authentication")
    parser.add_argument("--account", action="store_true", help="Check email verification and password recovery through Mailpit")
    options = parser.parse_args()
    content, account = options.content, options.account
    env = dict(os.environ, COMPOSE_PROJECT_NAME=f"relay-rate-runtime-{os.getpid()}",
               MAILPIT_HTTP_PORT="0", CONTENT_HTTP_PORT="0", POSTGRES_BIND_HOST="127.0.0.1", POSTGRES_EXTERNAL_PORT="0",
               PROXY_BIND_HOST="127.0.0.1", PROXY_HTTPS_PORT=str(free_port()),
               PROXY_HTTP_PORT=str(free_port()), IDENTITY_PROXY_SUBNET=proxy_subnet())
    origin = f"https://localhost:{env['PROXY_HTTPS_PORT']}"
    env["IDENTITY_ALLOWED_ORIGIN"] = origin
    env["CONTENT_ALLOWED_ORIGIN"] = origin
    with tempfile.TemporaryDirectory(prefix="relay-rate-runtime-") as directory:
        work = Path(directory)
        certs = work / "certs"
        certs.mkdir()
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-keyout", str(certs / "server.key"),
             "-out", str(certs / "server.crt")])
        private = work / "signing.pem"
        run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)])
        private.chmod(0o444)  # Parent directory is private; container secret mount is read-only.
        policies = dict(IDENTITY_RATE_EMAIL_IP="10000/1h/10000", IDENTITY_RATE_EMAIL_ACCOUNT="10000/1h/10000", IDENTITY_RATE_ACTION_IP="10000/1h/10000", IDENTITY_RATE_LIMIT_KEY=secrets.token_hex(32),
                        IDENTITY_RATE_LOGIN_IP="10/1h/10", IDENTITY_RATE_LOGIN_ACCOUNT="1/1h/1",
                        IDENTITY_RATE_REGISTER_IP="3/1h/3", IDENTITY_RATE_REFRESH_IP="1/1h/1",
                        IDENTITY_RATE_READ_USER="2/1h/2", IDENTITY_RATE_LOGOUT_IP="1/1h/1",
                        IDENTITY_RATE_REVOKE_USER="2/1h/2")
        override = work / "compose.json"
        configuration = {"services": {
            "identity": {"environment": policies},
            "nginx": {"volumes": [f"{certs}:/etc/nginx/certs:ro"]}},
            "secrets": {"identity_signing_key": {"file": str(private)}}}
        if content or account:
            for name in policies:
                if name != "IDENTITY_RATE_LIMIT_KEY":
                    policies[name] = "10000/1h/10000"
        policies["IDENTITY_CURSOR_SIGNING_KEY"] = secrets.token_hex(32)
        policies["IDENTITY_MAIL_ENCRYPTION_KEY"] = secrets.token_hex(32)
        policies["IDENTITY_SMTP_ALLOW_INSECURE"] = "true"
        if content:
            public = work / "public.pem"
            run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)])
            public.chmod(0o444)
            configuration["services"]["content"] = {
                "environment": {
                    "CONTENT_ACCESS_PUBLIC_KEY_FILES": "local-1=/run/keys/identity-public.pem",
                    "CONTENT_RATE_LIMIT_KEY": secrets.token_hex(32),
                    "CONTENT_CURSOR_SIGNING_KEY": secrets.token_hex(32),
                    "CONTENT_RATE_CAPTURE_USER": "1/1h/1", "CONTENT_RATE_WRITE_USER": "1/1h/1",
                    "CONTENT_RATE_READ_USER": "1/1h/1", "CONTENT_RATE_SEARCH_USER": "1/1h/1"},
                "volumes": [f"{public}:/run/keys/identity-public.pem:ro"]}
        override.write_text(json.dumps(configuration))
        command = ["docker", "compose"]
        for service in ("core", "content", "delivery", "identity", "processing"):
            command.extend(["--env-file", str(ROOT / "deploy/env" / f"{service}.env")])
        command.extend(["-f", str(ROOT / "compose.yml"), "-f", str(override), "--profile", "gateway", "--profile", "mail"])

        def compose(*args):
            return run([*command, *args], cwd=ROOT, env=env)

        delivered_ids = set()

        def email_message(email, subject):
            port = compose("port", "mailpit", "8025").splitlines()[0].rsplit(":", 1)[1]
            base = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    with urllib.request.urlopen(base + "/api/v1/messages", timeout=3) as response:
                        messages = json.load(response)["messages"]
                except urllib.error.URLError:
                    time.sleep(0.1)
                    continue
                for message in messages:
                    if message["ID"] in delivered_ids or message["Subject"] != subject:
                        continue
                    if not any(recipient["Address"] == email for recipient in message["To"]):
                        continue
                    with urllib.request.urlopen(base + "/api/v1/message/" + message["ID"], timeout=3) as response:
                        text = json.load(response)["Text"]
                    delivered_ids.add(message["ID"])
                    return text
                time.sleep(0.1)
            raise AssertionError("Mailpit did not receive the requested account email")

        def email_token(email, subject):
            message = email_message(email, subject)
            token = message.split("#token=", 1)[1].split()[0]
            assert len(token) == 43
            return token

        def request(label, method, path, expected, body=None, jar=None, spoof=None, extra_headers=None):
            headers = [f"Origin: {origin}", *(extra_headers or [])]
            if body is not None and not any(header.lower().startswith("content-type:") for header in headers):
                headers.append("Content-Type: application/json")
            if jar is not None and jar.exists():
                for line in jar.read_text().splitlines():
                    fields = line.split("\t")
                    if len(fields) == 7 and fields[5] == "__Host-relay_csrf":
                        headers.append(f"X-CSRF-Token: {fields[6]}")
            if spoof:
                headers.append(f"X-Forwarded-For: {spoof}")
            header_file = work / "request.headers"
            header_file.write_text("\n".join(headers) + "\n")
            response_headers, response_body = work / "response.headers", work / "response.json"
            args = ["curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "10",
                    "--request", method, "--header", f"@{header_file}",
                    "--dump-header", str(response_headers), "--output", str(response_body),
                    "--write-out", "%{http_code}"]
            if body is not None:
                payload = work / "payload.json"
                payload.write_text(json.dumps(body))
                args.extend(["--data-binary", f"@{payload}"])
            if jar is not None:
                args.extend(["--cookie", str(jar), "--cookie-jar", str(work / "next.cookies")])
            status = int(run([*args, origin + path]))
            allowed = expected if isinstance(expected, tuple) else (expected,)
            assert status in allowed, f"{label}: status {status}, expected {expected}"
            raw_headers = response_headers.read_text().lower()
            if expected in (429, 503):
                assert "set-cookie:" not in raw_headers, f"{label}: changed cookies on rejection"
                problem = json.loads(response_body.read_text())
                assert problem["status"] == expected
                assert problem["code"] == (("RATE_LIMITED" if "/auth/" in path else "TOO_MANY_REQUESTS") if expected == 429 else "SERVICE_UNAVAILABLE")
            if expected == 429:
                assert "retry-after:" in raw_headers
            print(f"{label}: {status}", flush=True)
            if path == "/api/v1/auth/register" and status == 201 and not account:
                token = email_token(body["email"], "Confirm your Relay email")
                request("confirm registered email", "POST", "/api/v1/auth/email/verification", 204, {"token": token})
            return json.loads(response_body.read_text()) if response_body.stat().st_size else {}

        try:
            compose("up", "-d", "--wait", "postgres", "redis", "mailpit")
            compose("run", "--rm", "db-bootstrap")
            compose("up", "-d", "--build", "identity", "nginx", *(["content"] if content else []))
            for _ in range(100):
                probe = subprocess.run([*command, "exec", "-T", "nginx", "curl", "-fsS", "--max-time", "1",
                                        "http://identity-api:8080/readyz"], cwd=ROOT, env=env,
                                       capture_output=True, timeout=5)
                if probe.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("Identity did not become ready")
            if account:
                check_account(request, email_token, email_message, work, compose)
                logs = compose("logs", "--no-color", "identity", "nginx")
                assert "account-recovery-" not in logs
                assert "replacement-password" not in logs
                compose("stop", "identity", "nginx")
                stopped = json.loads(compose("ps", "--all", "--format", "json", "identity"))
                assert stopped["ExitCode"] == 0
                print("HTTPS email verification, Mailpit delivery, password recovery, session revocation and shutdown passed", flush=True)
                return
            if content:
                for _ in range(100):
                    probe = subprocess.run([*command, "exec", "-T", "nginx", "curl", "-fsS", "--max-time", "1",
                                            "http://content:8080/readyz"], cwd=ROOT, env=env,
                                           capture_output=True, timeout=5)
                    if probe.returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Content did not become ready")
                marker, password = check_content(request, compose, work, private)
                logs = compose("logs", "--no-color", "identity", "content", "nginx")
                assert marker not in logs, "private content or email leaked into logs"
                assert password not in logs, "password leaked into logs"
                compose("stop", "identity", "content", "nginx")
                for service in ("identity", "content"):
                    stopped = json.loads(compose("ps", "--all", "--format", "json", service))
                    assert stopped["ExitCode"] == 0
                print("HTTPS Content budgets, Identity isolation, Redis outage, privacy and shutdown checks passed", flush=True)
                return
            owners = []
            marker = "rate-runtime-" + secrets.token_hex(8)
            for index in range(3):
                credentials = {"email": f"{marker}-{index}@example.com",
                               "password": "correct password with sufficient length"}
                request("register", "POST", "/api/v1/auth/register", 201, credentials)
                jar = work / f"owner-{index}.cookies"
                login = request("login", "POST", "/api/v1/auth/login", 200, credentials, jar)
                jar.write_bytes((work / "next.cookies").read_bytes())
                owners.append((credentials, jar, login["session_id"]))
            credentials, jar, own_session = owners[0]
            request("registration budget", "POST", "/api/v1/auth/register", 429, credentials)
            request("account budget", "POST", "/api/v1/auth/login", 429, credentials)
            request("current session", "GET", "/api/v1/auth/session", 200, jar=jar)
            request("session list", "GET", "/api/v1/auth/sessions", 200, jar=jar)
            request("shared read budget", "GET", "/api/v1/auth/session", 429, jar=jar)
            request("refresh", "POST", "/api/v1/auth/refresh", 200, jar=jar)
            request("refresh budget", "POST", "/api/v1/auth/refresh", 429, jar=jar)
            other_jar = owners[1][1]
            for _ in range(2):
                request("foreign revocation", "DELETE", f"/api/v1/auth/sessions/{own_session}", 404, jar=other_jar)
            request("revocation budget", "DELETE", "/api/v1/auth/sessions", 429, jar=other_jar)
            request("empty logout", "DELETE", "/api/v1/auth/session", 204)
            request("logout budget", "DELETE", "/api/v1/auth/session", 429, jar=other_jar)
            for index in range(6):
                request("invalid login", "POST", "/api/v1/auth/login", 401,
                        {"email": f"unknown-{index}@example.com", "password": "wrong"}, spoof=f"198.51.100.{index+1}")
            request("spoofed IP cannot reset budget", "POST", "/api/v1/auth/login", 429, credentials,
                    spoof="203.0.113.7")
            compose("stop", "redis")
            for path in ("register", "login", "refresh"):
                request(f"Redis outage {path}", "POST", f"/api/v1/auth/{path}", 503,
                        None if path == "refresh" else credentials, jar=jar)
            request("Redis outage read", "GET", "/api/v1/auth/session", 200, jar=jar)
            request("Redis outage list", "GET", "/api/v1/auth/sessions", 200, jar=jar)
            request("Redis outage selected revocation", "DELETE", f"/api/v1/auth/sessions/{own_session}", 204, jar=jar)
            request("Redis outage all revocation", "DELETE", "/api/v1/auth/sessions", 204, jar=owners[2][1])
            request("Redis outage logout", "DELETE", "/api/v1/auth/session", 204, jar=other_jar)
            request("revoked session", "GET", "/api/v1/auth/session", 401, jar=jar)
            logs = compose("logs", "--no-color", "identity", "nginx")
            assert marker not in logs, "email leaked into HTTP logs"
            assert credentials["password"] not in logs, "password leaked into logs"
            compose("stop", "identity", "nginx")
            stopped = json.loads(compose("ps", "--all", "--format", "json", "identity"))
            assert stopped["ExitCode"] == 0
            print("HTTPS rate-limit, Redis failure, privacy and shutdown checks passed", flush=True)
        finally:
            compose("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
