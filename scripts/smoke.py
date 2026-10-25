#!/usr/bin/env python3
"""Exercise a cold, unregistered deployment without contacting the real Union Hub."""

import argparse
import json
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def smoke(image):
    version = subprocess.check_output(["docker", "run", "--rm", image, "version"], text=True).strip()
    name = "union-gateway-smoke-" + uuid.uuid4().hex[:10]
    volume = name + "-data"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="union-gateway-smoke-") as temporary:
        config = pathlib.Path(temporary) / "config.yaml"
        config.write_text(
            "listen: '0.0.0.0:8267'\npublic_root: 'https://union.example.org/member'\n"
            "elementskin_api_url: 'http://127.0.0.1:1'\nelementskin_site_url: 'https://skin.example.org'\n"
            "service_client_id: 'synthetic-client'\nstate_path: './data/gateway.db'\nsecret_dir: './data/secrets'\n",
            encoding="utf-8",
        )
        try:
            subprocess.run(
                ["docker", "run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges:true", "-p", "127.0.0.1::8267",
                 "--mount", "type=bind,src=" + str(config) + ",dst=/app/config.yaml,readonly",
                 "--mount", "type=volume,src=" + volume + ",dst=/app/data",
                 "-e", "UNION_GATEWAY_CLIENT_SECRET=synthetic-client-secret",
                 "-e", "UNION_GATEWAY_ADMIN_TOKEN=" + "a" * 64, image],
                check=True, capture_output=True,
            )

            def address():
                port = subprocess.check_output(["docker", "port", name, "8267/tcp"], text=True).strip().split(":")[-1]
                return "http://127.0.0.1:" + port + "/member"

            def fetch(base, path, authorized=False):
                headers = {"Authorization": "Bearer " + "a" * 64} if authorized else {}
                req = urllib.request.Request(base + path, headers=headers)
                try:
                    with opener.open(req, timeout=2) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    return error.code, json.load(error)

            def wait_live(base):
                for _ in range(40):
                    try:
                        if fetch(base, "/health/live") == (200, {"live": True, "version": version}):
                            return
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.25)
                raise RuntimeError("container liveness failed")

            base = address()
            wait_live(base)
            assert fetch(base, "/health/ready") == (503, {"ready": False})
            assert fetch(base, "/admin/status")[0] == 401
            status, state = fetch(base, "/admin/status", True)
            assert status == 200 and state["ready"] is False and state["active_key_version"] == 0
            assert state["member_key_configured"] is False
            subprocess.run(["docker", "exec", name, "/app/union-gateway", "healthcheck"], check=True)
            info = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
            assert info["Config"]["User"] == "10001:10001" and info["HostConfig"]["ReadonlyRootfs"]
            subprocess.run(["docker", "restart", name], check=True, capture_output=True)
            base = address()  # Docker may allocate a different ephemeral host port on restart.
            wait_live(base)
            after = fetch(base, "/admin/status", True)[1]
            assert after["active_key_version"] == 0 and after["pending_sync"] is True
            logs = subprocess.check_output(["docker", "logs", name], stderr=subprocess.STDOUT, text=True)
            assert "synthetic-client-secret" not in logs and "a" * 64 not in logs
            assert "http_request" in logs and "request_id" in logs
            print(json.dumps({"container_boot": True, "nonroot_readonly": True, "subpath": True,
                              "healthcheck": True, "admin_auth": True, "restart": True, "redacted_logs": True}))
        except Exception:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            print(logs.stdout + logs.stderr)
            raise
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            subprocess.run(["docker", "volume", "rm", volume], capture_output=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="element-skin-union-gateway:0.1.0")
    smoke(parser.parse_args().image)
