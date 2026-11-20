import hashlib
import io
import json
import unittest
from email.message import Message

from registry_digest import MEDIA_TYPES, verified_digest


def response(doc, declared=None):
    raw = json.dumps(doc, indent=2).encode()
    stream = io.BytesIO(raw)
    stream.headers = Message()
    stream.headers["Content-Type"] = doc["mediaType"]
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    stream.headers["Docker-Content-Digest"] = declared or digest
    return stream, digest


class RegistryDigestTests(unittest.TestCase):
    def test_hashes_top_level_bytes_for_images_and_indexes(self):
        child = {"digest": "sha256:" + "a" * 64}
        for media in MEDIA_TYPES:
            with self.subTest(media=media):
                doc = {"schemaVersion": 2, "mediaType": media}
                if "index" in media or "list" in media:
                    doc["manifests"] = [child, {"digest": "sha256:" + "b" * 64}]
                else:
                    doc.update(config=child, layers=[])
                raw, expected = response(doc)
                self.assertNotEqual(expected, child["digest"])
                self.assertEqual(verified_digest(raw), expected)

    def test_rejects_child_digest_as_header_for_index(self):
        child = "sha256:" + "a" * 64
        stream, _ = response(
            {"mediaType": MEDIA_TYPES[0], "manifests": [{"digest": child}]}, child
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            verified_digest(stream)

    def test_rejects_error_pages(self):
        stream, _ = response({"mediaType": "text/html"})
        with self.assertRaisesRegex(ValueError, "unexpected manifest type"):
            verified_digest(stream)
