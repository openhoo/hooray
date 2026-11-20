#!/usr/bin/env python3
"""Check digest-bound promotion into a real local Git repository. Prints a JSON receipt."""

import argparse
import io
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from contextlib import closing
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlsplit

from git_repository import (
    create_public_repo,
    git,
    isolated_env,
    publish_verified_bytes,
    read_only_http,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = "0361fda09da6d49d477b127a64624e52aef3969e"
FIXED = "9ab514a590002bbb0b8990d60c97d5d9e71c7d8d"


def digest(data):
    return sha256(data).hexdigest()


def check(ok, message):
    if not ok:
        raise ValueError(message)


def public_file(commit, name):
    return git(ROOT, "show", f"{commit}:{name}").stdout


def sample(commit):
    files = {name: public_file(commit, name) for name in ("Cargo.lock", "Cargo.toml")}
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in files.items():
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, data)
    return out.getvalue(), {k: digest(v) for k, v in files.items()}


def stage(private, data):
    path = private / f"{digest(data)}.zip"
    with path.open("xb") as out:
        out.write(data)
    path.chmod(0o400)
    return path


class Promoter:
    """Trusted local actor. Reader HTTP requests cannot call any of its methods."""

    def __init__(self, binary, private, public_repo):
        self.binary = binary
        self.private = private
        self.public_repo = public_repo
        self.database = private / "decisions.db"
        self.calls = {}

    def gate(self, op, control, archive, policy):
        # No user-supplied receipt, source revision or decision hash is accepted.
        # Each invocation receives fresh, private files containing the exact input
        # byte strings; promotion retains those strings instead of reopening an upload.
        with tempfile.TemporaryDirectory(dir=self.private) as temp:
            here = Path(temp)
            staged, rules = here / "artifact.zip", here / "policy.yaml"
            staged.write_bytes(archive)
            rules.write_bytes(policy)
            env = {**isolated_env(), "HOORAY_DATABASE_PATH": str(self.database), "HOORAY_OFFLINE": "true"}
            proc = subprocess.run(
                [self.binary, "gate", op, staged, "--policy", rules],
                env=env,
                cwd=here,
                capture_output=True,
                check=False,
                timeout=60,
            )
        if proc.returncode not in (0, 1):
            self.calls[control] = {"exit": proc.returncode, "command": op}
            raise subprocess.CalledProcessError(
                proc.returncode, ["hooray", "gate", op], output=proc.stdout, stderr=proc.stderr
            )
        result = json.loads(proc.stdout)
        check(result.get("artifact_sha256") == digest(archive), "gate returned the wrong artifact hash")
        check(result.get("policy_sha256") == digest(policy), "gate returned the wrong policy hash")
        check(
            (proc.returncode, result.get("outcome")) in {(0, "allow"), (1, "unknown"), (1, "deny")},
            f"gate {op} exit and outcome disagree",
        )
        self.calls[control] = {"exit": proc.returncode, "command": op, "receipt": result}
        return result["outcome"]

    def promote(self, control, archive, policy):
        outcome = self.gate("require", control, archive, policy)
        if outcome == "allow":
            publish_verified_bytes(self.public_repo, digest(archive), archive)
        return outcome


def endpoint_status(base, method, path, data=None):
    url = urlsplit(base)
    with closing(HTTPConnection(url.hostname, url.port, timeout=10)) as connection:
        connection.request(method, path, body=data)
        response = connection.getresponse()
        response.read()
        return response.status


def public_refs(cwd, remote):
    return git(cwd, "ls-remote", "--heads", remote).stdout


def blob_id(repo, archive):
    # Without -w this is a pure hash calculation. It never imports staged bytes.
    return git(repo, "hash-object", "--stdin", data=archive).stdout.decode().strip()


def absent(repo, blob):
    return git(repo, "cat-file", "-e", blob, check=False).returncode != 0


def check_evidence(calls, evaluation, consumption, coordinate, matches):
    evaluated = calls[evaluation]["receipt"]
    check(evaluated == calls[consumption]["receipt"], "require returned a different decision from evaluate")
    check(
        evaluated.get("component_purl") == f"pkg:cargo/zip@{coordinate}"
        and evaluated.get("matched_advisories") == matches,
        "unexpected publisher matches",
    )
    check(
        evaluated.get("publisher_sha256")
        == digest((ROOT / "docs/verification/zip-maintainer-coordinates.tsv").read_bytes())
        and evaluated.get("publisher_source")
        and evaluated.get("publisher_revision")
        and evaluated.get("run_id"),
        "missing or wrong publisher/scan provenance",
    )


def verify(binary, root):
    private, public = root / "staging", root / "public"
    private.mkdir(mode=0o700)
    # A concurrent rebuild must not mix different scanners in one receipt.
    binary = Path(shutil.copyfile(binary, private / "hooray"))
    binary.chmod(0o500)
    repo = create_public_repo(public)
    gated = Promoter(binary, private, repo)
    old, old_files = sample(BASE)
    fixed, fixed_files = sample(FIXED)
    old_path, fixed_path = stage(private, old), stage(private, fixed)
    old, fixed = old_path.read_bytes(), fixed_path.read_bytes()
    rules = public_file(BASE, "hooray-policy.yaml")
    check(rules == public_file(FIXED, "hooray-policy.yaml"), "original policies differ")
    old_blob, fixed_blob = blob_id(repo, old), blob_id(repo, fixed)
    with read_only_http(public) as base:
        remote = base + "/release.git"
        empty = public_refs(root, remote)
        check(empty == b"", "repository must start empty")

        def withheld(name, data, policy, expected):
            check(gated.promote(name, data, policy) == expected, f"{name}: expected {expected}")
            check(public_refs(root, remote) == empty, f"{name}: reader observed a ref change")
            check(absent(repo, blob_id(repo, data)), f"{name}: archive is in public object storage")

        withheld("unscanned", fixed, rules, "unknown")
        check(gated.gate("evaluate", "evaluate_old", old, rules) == "deny", "old control was not denied")
        withheld("denied", old, rules, "deny")
        check(
            gated.gate("evaluate", "evaluate_fixed", fixed, rules) == "allow", "fixed control was not allowed"
        )
        # Change only ZIP metadata. The unpacked lockfile and manifest stay identical.
        other = io.BytesIO(fixed)
        with zipfile.ZipFile(other, "a") as archive:
            archive.comment = b"same files, distinct artifact"
        withheld("changed_artifact", other.getvalue(), rules, "unknown")
        withheld("changed_policy", fixed, rules + b"\n# New policy revision\n", "unknown")
        db = gated.database
        gated.database = private  # SQLite cannot open a directory as a database.
        try:
            gated.promote("unavailable_decision_store", fixed, rules)
        except subprocess.CalledProcessError as exc:
            check(exc.returncode == 2, "store failure must be operational exit 2")
        else:
            raise ValueError("gate accepted an unavailable decision store")
        finally:
            gated.database = db
        check(
            public_refs(root, remote) == empty and absent(repo, fixed_blob),
            "store failure exposed the staged artifact",
        )

        forged = json.dumps(
            {"outcome": "allow", "artifact_sha256": digest(old), "policy_sha256": digest(rules)}
        ).encode()
        statuses = {
            "reader_promotion_with_client_receipt": endpoint_status(base, "POST", "/promote", forged),
            "staging_route": endpoint_status(base, "GET", "/staging/" + old_path.name),
            "public_object_url_for_denied_blob": endpoint_status(
                base, "GET", f"/release.git/objects/{old_blob[:2]}/{old_blob[2:]}"
            ),
            "anonymous_receive_pack": endpoint_status(base, "POST", "/release.git/git-receive-pack"),
        }
        check(
            statuses["anonymous_receive_pack"] == 403
            and all(code == 404 for key, code in statuses.items() if key != "anonymous_receive_pack"),
            f"unexpected HTTP results: {statuses}",
        )
        check(public_refs(root, remote) == empty, "reader moved public refs")
        check(gated.promote("promote_fixed", fixed, rules) == "allow", "publication refused")
        public_branch = "sha256/" + digest(fixed)
        reader = root / "recipient"
        git(root, "clone", "--depth=1", "--single-branch", "--branch", public_branch, remote, str(reader))
        retrieved = (reader / "artifact.zip").read_bytes()
        check(retrieved == fixed, "recipient bytes differ")
        commit = git(reader, "rev-parse", "HEAD").stdout.decode().strip()
        refs = public_refs(root, remote)
        check(refs == f"{commit}\trefs/heads/{public_branch}\n".encode(), "unexpected published ref")
        denied_branch = git(
            reader, "ls-remote", "--exit-code", "--heads", remote, "sha256/" + digest(old), check=False
        )
        check(denied_branch.returncode == 2, "denied ref was visible or lookup failed")
        denied_fetch = git(reader, "fetch", remote, old_blob, check=False)
        check(
            denied_fetch.returncode != 0 and b"not our ref " + old_blob.encode() in denied_fetch.stderr,
            "Git did not explicitly reject the denied object's ID",
        )
        check(absent(repo, old_blob) and absent(reader, old_blob), "denied bytes reached public storage")
        check(not absent(repo, fixed_blob), "allowed blob missing from public storage")
        push = git(reader, "push", remote, "HEAD:refs/heads/reader-write", check=False)
        check(push.returncode != 0 and b"403" in push.stderr, "reader push was not rejected by the server")
        check(public_refs(root, remote) == refs, "failed push changed public refs")
    check_evidence(gated.calls, "evaluate_old", "denied", "8.6.0", 32)
    check_evidence(gated.calls, "evaluate_fixed", "promote_fixed", "9.8.1", 0)
    version = subprocess.check_output([binary, "--version"], text=True).strip()
    return {
        "binary_version": version,
        "binary_sha256": digest(binary.read_bytes()),
        "git_version": git(ROOT, "--version").stdout.decode().strip(),
        "policy_sha256": digest(rules),
        "archives": {
            k: {"commit": c, "files": f, "sha256": digest(a)}
            for k, c, f, a in [("old", BASE, old_files, old), ("fixed", FIXED, fixed_files, fixed)]
        },
        "gate_calls": gated.calls,
        "http_status": statuses,
        "denied_ref_ls_remote_exit": denied_branch.returncode,
        "denied_blob_fetch_exit": denied_fetch.returncode,
        "denied_blob_absent_from_public_and_recipient": True,
        "reader_push_exit": push.returncode,
        "published_commit": commit,
        "recipient_sha256": digest(retrieved),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", required=True, type=Path, help="absolute or relative path to the gate-enabled Hooray CLI"
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hooray-repository-gate-") as temp:
        receipt = verify(args.binary.resolve(strict=True), Path(temp))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(
            f"repository gate verification failed: {exc}; {(exc.stderr or b'').decode(errors='replace')}"
        )
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError) as exc:
        sys.exit(f"repository gate verification failed: {exc}")
