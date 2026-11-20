"""Read the top-level digest of a public Hooray image directly from GHCR."""

import hashlib
import json
import re
import sys
from urllib.request import Request, urlopen

REPOSITORY = "openhoo/hooray"
MEDIA_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
MAX_BYTES = 4 * 1024 * 1024


def verified_digest(response):
    if response.headers.get_content_type() not in MEDIA_TYPES:
        raise ValueError("registry returned an unexpected manifest type")
    raw = response.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("empty or oversized registry manifest")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if digest != response.headers.get("Docker-Content-Digest"):
        raise ValueError("registry digest does not match the manifest bytes")
    return digest


def registry_digest(ref):
    if not re.fullmatch(
        r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|sha256:[0-9a-f]{64})", ref
    ):
        raise ValueError("expected a tag or sha256 digest")
    token_url = (
        f"https://ghcr.io/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull"
    )
    with urlopen(token_url, timeout=30) as auth:
        token = json.loads(auth.read(65536))["token"]
    request = Request(
        f"https://ghcr.io/v2/{REPOSITORY}/manifests/{ref}",
        headers={"Accept": ", ".join(MEDIA_TYPES), "Authorization": f"Bearer {token}"},
    )
    with urlopen(request, timeout=30) as response:
        digest = verified_digest(response)
    if ref.startswith("sha256:") and ref != digest:
        raise ValueError("registry returned a different digest than requested")
    return digest


if __name__ == "__main__":
    print(registry_digest(sys.argv[1]))
