#!/usr/bin/env python3
"""E2E: enable panel Xray, verify /sub + vless, run xray client in Docker."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

BASE = os.environ.get("PANEL_URL", "https://127.0.0.1")
CTX = ssl._create_unverified_context()
jar = CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=CTX),
)

CLIENT_NAME = "xray-e2e"
CLIENT_CTN = "amnezia-xray-client-e2e"
WORKDIR = Path("/tmp/xray-e2e")
WORKDIR.mkdir(parents=True, exist_ok=True)


def req(method, path, body=None, timeout=120, raw=False):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with opener.open(r, timeout=timeout) as resp:
            payload = resp.read()
            if raw:
                return resp.status, payload, dict(resp.headers)
            text = payload.decode()
            return resp.status, (json.loads(text) if text else None), dict(resp.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        if raw:
            return e.code, payload, dict(e.headers)
        try:
            parsed = json.loads(payload.decode()) if payload else None
        except Exception:
            parsed = payload.decode(errors="replace")
        return e.code, parsed, dict(e.headers)


def sh(cmd, check=True, timeout=120):
    print("+", cmd, flush=True)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if p.stdout:
        print(p.stdout.rstrip(), flush=True)
    if p.stderr:
        print(p.stderr.rstrip(), flush=True)
    if check and p.returncode != 0:
        raise SystemExit(f"cmd failed ({p.returncode}): {cmd}")
    return p


def login():
    for user, pw in (("admin", "admin1"), ("admin", "admin"), ("admin", os.environ.get("ADMIN_PASSWORD", ""))):
        if not pw:
            continue
        code, body, _ = req("POST", "/api/session", {"username": user, "password": pw})
        if code == 200:
            print("login ok", user, flush=True)
            return
    raise SystemExit(f"login failed: {body}")


def list_clients():
    code, body, _ = req("GET", "/api/wireguard/client")
    assert code == 200, body
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("clients"), list):
        return body["clients"]
    raise SystemExit(f"unexpected clients payload: {type(body)} {body!r}"[:300])


def ensure_client():
    clients = list_clients()
    for c in clients:
        if c.get("name") == CLIENT_NAME:
            print("client exists", c.get("id"), flush=True)
            return c
    code, created, _ = req("POST", "/api/wireguard/client", {"name": CLIENT_NAME})
    print("create client", code, created, flush=True)
    assert code in (200, 201), created
    clients = list_clients()
    for c in clients:
        if c.get("name") == CLIENT_NAME:
            return c
    raise SystemExit("client not found after create")


def wait_xray_running(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        code, st, _ = req("GET", "/api/amnezia-xray")
        print(
            "status",
            code,
            (st or {}).get("phase"),
            (st or {}).get("busy"),
            (st or {}).get("lastError"),
            flush=True,
        )
        if code == 200 and st and st.get("phase") == "running" and st.get("available"):
            return st
        if code == 200 and st and st.get("phase") == "error":
            raise SystemExit(f"xray error: {st}")
        time.sleep(2)
    raise SystemExit("timeout waiting for xray running")


def parse_vless(url: str):
    assert url.startswith("vless://"), url
    u = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(u.query)

    def one(k, default=""):
        return (q.get(k) or [default])[0]

    return {
        "uuid": u.username,
        "host": u.hostname,
        "port": u.port or 443,
        "sni": one("sni"),
        "pbk": one("pbk"),
        "sid": one("sid"),
        "fp": one("fp", "chrome"),
        "flow": one("flow", ""),
        "spx": one("spx", ""),
        "security": one("security"),
        "type": one("type", "tcp"),
    }


def write_client_config(v: dict, socks_port=10808):
    flow = v["flow"]
    user = {"id": v["uuid"], "encryption": "none"}
    if flow:
        user["flow"] = flow
    reality = {
        "show": False,
        "fingerprint": v["fp"] or "chrome",
        "serverName": v["sni"],
        "publicKey": v["pbk"],
        "shortId": v["sid"],
        "spiderX": v["spx"] or "",
    }
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks",
            "listen": "0.0.0.0",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": v["host"],
                        "port": int(v["port"]),
                        "users": [user],
                    }],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": reality,
                },
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
    }
    path = WORKDIR / "client.json"
    path.write_text(json.dumps(cfg, indent=2))
    print("wrote", path, flush=True)
    return path, socks_port


def main():
    login()

    address = os.environ.get("XRAY_CONNECT_HOST", "host.docker.internal")
    sni = os.environ.get("XRAY_SNI", "www.gov.uk")

    code, st, _ = req("GET", "/api/amnezia-xray")
    print(
        "initial",
        json.dumps(
            {k: st.get(k) for k in ("phase", "desired", "available", "address", "sni", "port")},
            indent=2,
        ),
        flush=True,
    )

    need_enable = not (st and st.get("phase") == "running" and st.get("available"))
    if st and st.get("address") in (None, "", "127.0.0.1", "localhost"):
        need_enable = True
        if st.get("phase") == "running":
            print("disable to rebind address for docker client", flush=True)
            req("POST", "/api/amnezia-xray/disable", {}, timeout=120)
            time.sleep(2)

    if need_enable:
        print("=== enable xray ===", flush=True)
        code, body, _ = req(
            "POST",
            "/api/amnezia-xray/enable",
            {
                "sni": sni,
                "fingerprint": "chrome",
                "flow": "xtls-rprx-vision",
                "port": 8443,
                "address": address,
            },
            timeout=240,
        )
        print("enable", code, body if code >= 400 else (body or {}).get("phase"), flush=True)
        st = wait_xray_running()

    print(
        "running",
        {k: st.get(k) for k in ("phase", "address", "sni", "port", "publicKey", "shortId", "smoke")},
        flush=True,
    )

    ensure_client()
    clients = list_clients()
    client = next(c for c in clients if c.get("name") == CLIENT_NAME)
    print("client uuid fields", {k: client.get(k) for k in client if "uuid" in k.lower() or "xray" in k.lower()}, flush=True)
    name_q = urllib.parse.quote(CLIENT_NAME, safe="")

    print("=== /sub ===", flush=True)
    code, raw, headers = req("GET", f"/sub/{name_q}", raw=True)
    print("sub code", code, "ctype", headers.get("Content-Type"), flush=True)
    assert code == 200, raw
    sub_json = json.loads(raw.decode())
    print("sub top-level keys", list(sub_json.keys()), flush=True)
    (WORKDIR / "sub.json").write_bytes(raw)

    print("=== /sub/vless ===", flush=True)
    code, raw, headers = req("GET", f"/sub/{name_q}/vless", raw=True)
    print("vless code", code, flush=True)
    assert code == 200, raw
    vless_url = raw.decode().strip()
    print("vless", vless_url[:160] + ("..." if len(vless_url) > 160 else ""), flush=True)
    assert vless_url.startswith("vless://")
    (WORKDIR / "vless.txt").write_text(vless_url + "\n")

    v = parse_vless(vless_url)
    print("parsed", {k: v[k] for k in ("host", "port", "sni", "uuid", "fp", "flow")}, flush=True)
    assert v["host"] in (address, st.get("address"))
    assert v["sni"]
    assert v["pbk"]

    cfg_path, socks_port = write_client_config(v)

    print("=== docker client ===", flush=True)
    sh(f"docker rm -f {CLIENT_CTN}", check=False)
    run = (
        f"docker run -d --name {CLIENT_CTN} "
        f"--add-host=host.docker.internal:host-gateway "
        f"-p 10808:{socks_port} "
        f"-v {cfg_path}:/etc/xray/config.json:ro "
        f"--entrypoint xray "
        f"amnezia-xray:latest -config /etc/xray/config.json"
    )
    sh(run)
    time.sleep(2)
    sh(f"docker logs {CLIENT_CTN} 2>&1 | tail -30", check=False)
    ps = sh(f"docker ps --filter name={CLIENT_CTN} --format '{{{{.Status}}}}'")
    if "Up" not in (ps.stdout or ""):
        raise SystemExit("client container not up")

    print("=== proxy fetch via client ===", flush=True)
    probes = [
        "curl -sS -m 25 --socks5-hostname 127.0.0.1:10808 https://1.1.1.1/cdn-cgi/trace",
        "curl -sS -m 25 --socks5-hostname 127.0.0.1:10808 https://example.com -o /dev/null -w '%{http_code}'",
        "curl -sS -m 25 --socks5-hostname 127.0.0.1:10808 https://www.gov.uk -o /dev/null -w '%{http_code}'",
    ]
    ok = False
    for cmd in probes:
        p = sh(cmd, check=False, timeout=40)
        if p.returncode == 0 and (p.stdout or "").strip():
            print("PROBE OK:", cmd, "->", (p.stdout or "")[:200], flush=True)
            ok = True
            break
        print("PROBE FAIL:", cmd, "rc=", p.returncode, flush=True)

    host = v["host"]
    port = v["port"]
    sh(
        f"docker exec {CLIENT_CTN} sh -c "
        f"'echo | nc -w 3 {host} {port} >/dev/null && echo TCP_OK || echo TCP_FAIL'",
        check=False,
    )

    if not ok:
        print("=== client logs ===", flush=True)
        sh(f"docker logs {CLIENT_CTN} 2>&1 | tail -80", check=False)
        print("=== server container ===", flush=True)
        sh("docker ps -a --filter name=amnezia-xray --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'", check=False)
        sh("docker logs amnezia-xray 2>&1 | tail -40", check=False)
        raise SystemExit("proxy probe failed — tunnel not working")

    print("=== E2E PASS ===", flush=True)


if __name__ == "__main__":
    main()
