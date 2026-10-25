#!/usr/bin/env python3
"""Build an offline Docker delivery from a static Linux binary and the canonical runtime stage."""

import argparse
import gzip
import hashlib
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package(binary, output, version, ca_bundle=None):
    root = Path(__file__).resolve().parents[1]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?", version):
        raise ValueError("invalid version")
    header = binary.read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[18:20] != b"\x3e\x00":
        raise ValueError("expected a static Linux amd64 ELF binary")
    output.mkdir(parents=True, exist_ok=True)
    tag = "element-skin-union-gateway:" + version
    with tempfile.TemporaryDirectory(prefix="union-gateway-package-") as temporary:
        stage = Path(temporary)
        for folder in ("output/data", "output/secrets", "etc/ssl/certs"):
            (stage / folder).mkdir(parents=True)
        shutil.copyfile(binary, stage / "output/union-gateway")
        (stage / "output/union-gateway").chmod(0o755)
        certificate = stage / "etc/ssl/certs/ca-certificates.crt"
        if ca_bundle:
            shutil.copyfile(ca_bundle, certificate)
        else:
            for suffix in ("", ".sha256"):
                with urllib.request.urlopen("https://curl.se/ca/cacert.pem" + suffix, timeout=60) as response:
                    (stage / ("cacert.pem" + suffix)).write_bytes(response.read())
            expected = (stage / "cacert.pem.sha256").read_text().split()[0]
            if digest(stage / "cacert.pem") != expected:
                raise ValueError("CA bundle checksum mismatch")
            shutil.copyfile(stage / "cacert.pem", certificate)
        if b"-----BEGIN CERTIFICATE-----" not in certificate.read_bytes():
            raise ValueError("invalid CA bundle")
        runtime = (root / "Dockerfile").read_text(encoding="utf-8").split("FROM scratch AS runtime\n", 1)[1]
        (stage / "Dockerfile").write_text("FROM scratch AS runtime\n" + runtime.replace("COPY --from=build ", "COPY "), encoding="utf-8", newline="\n")
        subprocess.run(["docker", "build", "--network", "none", "--platform", "linux/amd64", "-t", tag, str(stage)], check=True)
        if subprocess.check_output(["docker", "run", "--rm", tag, "version"], text=True).strip() != version:
            raise ValueError("image version does not match package version")
        image = output / ("element-skin-union-gateway-" + version + "-linux-amd64.image.tar.gz")
        process = subprocess.Popen(["docker", "save", tag], stdout=subprocess.PIPE)
        with image.open("wb") as target, gzip.GzipFile(fileobj=target, mode="wb", mtime=0) as compressed:
            shutil.copyfileobj(process.stdout, compressed)
        process.stdout.close()
        if process.wait() != 0:
            raise RuntimeError("docker save failed")
        bundle = output / ("element-skin-union-gateway-" + version + "-docker.zip")
        compose = (root / "compose.yaml").read_text(encoding="utf-8").replace("    build: .\n", "").replace("${GATEWAY_VERSION:-0.1.0}", version)
        checksums = digest(image) + "  " + image.name + "\n"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(image, image.name, compress_type=zipfile.ZIP_STORED)
            archive.writestr("compose.yaml", compose)
            archive.writestr("SHA256SUMS", checksums)
            archive.writestr("secrets/", "")
            for relative in ("config.yaml.example", "deploy/nginx.conf.example", "doc/部署与运维.md", "scripts/smoke.py"):
                archive.write(root / relative, relative)
            archive.writestr("README.txt", "1. Verify SHA256SUMS.\n2. docker load -i " + image.name + "\n3. Follow doc/部署与运维.md to provision config.yaml, secrets and HTTPS.\n4. docker compose up -d\n")
        (output / (bundle.name + ".sha256")).write_text(digest(bundle) + "  " + bundle.name + "\n", encoding="utf-8")
        print(bundle)
        return bundle


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--ca-bundle", type=Path)
    options = parser.parse_args()
    package(options.binary, options.output, options.version, options.ca_bundle)
