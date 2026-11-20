"""Run the actual YAML Bash step with isolated, stateful stand-ins for external APIs."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE = "ghcr.io/openhoo/hooray"
DIGEST = "sha256:" + "a" * 64
REF = IMAGE + "@" + DIGEST
OLD = "b" * 40
CURRENT = "c" * 40
REPO = "openhoo/hooray"
SIGNER = REPO + "/.github/workflows/release.yml"


def fake(tool, args):
    cfg = json.loads(Path("fixture.json").read_text())
    version, sha = cfg["version"], cfg["sha"]
    attempt = f"{IMAGE}:release-{version}-{sha}"
    auth = None
    if tool == "docker" and args[:1] == ["--config"]:
        auth, args = args[1], args[2:]

    def event(*fields):
        with Path("events").open("a") as log:
            print(" ".join(fields), file=log)

    if tool == "git" and args == ["rev-parse", "HEAD"]:
        print(sha)
    elif tool == "git" and args == [
        "show",
        CURRENT + ":.github/scripts/registry_digest.py",
    ]:
        # Stand in for registry reads. An unpushed promotion is not readable.
        print(
            "from pathlib import Path\nimport sys\nr=sys.argv[1]\nassert r in Path('registry').read_text().splitlines()\n"
            f"print({DIGEST!r})"
        )
    elif tool == "gh" and args == ["api", f"repos/{REPO}/releases/tags/v{version}"]:
        print(json.dumps({"draft": False, "id": 100, "body": cfg["body"]}))
    elif tool == "gh" and args == [
        "api",
        f"repos/{REPO}/releases/latest",
        "--jq",
        ".id",
    ]:
        event("latest-id")
        print(cfg["latest"])
    elif tool == "gh" and args == [
        "api",
        "--method",
        "PATCH",
        f"repos/{REPO}/releases/100",
        "--input",
        "patch.json",
    ]:
        assert json.loads(Path("patch.json").read_text()) == {
            "body": "Release notes\nHooray-OCI-Digest: " + REF + "\n"
        }
        event("patch")
    elif tool == "gh" and args[:2] == ["attestation", "verify"]:
        assert args == [
            "attestation",
            "verify",
            "oci://" + REF,
            "--repo",
            REPO,
            "--signer-workflow",
            SIGNER,
            "--source-digest",
            OLD,
        ]
        event("verify-provenance")
        return int(cfg["reject"] == "provenance")
    elif tool == "cosign" and args[:1] == ["verify"]:
        assert args == [
            "verify",
            "--certificate-identity",
            "https://github.com/" + SIGNER + "@refs/heads/main",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            REF,
        ]
        event("verify-signature")
        return int(cfg["reject"] == "signature")
    elif tool == "curl" and args[-1].startswith("https://ghcr.io/token?"):
        print(json.dumps({"token": "dummy"}))
    elif tool == "curl" and args[-1].endswith("/manifests/" + attempt.split(":")[1]):
        Path("attempt-manifest.json").write_text("{}")
        print(404)
    elif tool == "docker" and args[:1] == ["build"]:
        assert args[-3:] == ["--tag", attempt, "."]
        event("build")
    elif tool == "docker" and args[:1] == ["run"]:
        assert args[-2] in (attempt, REF)
        if args[-1] == "--version":
            print(
                ("hooray-parity" if "hooray-parity" in args else "hooray")
                + " "
                + version
            )
        elif args[-1] == "-u" and "/usr/bin/id" in args:
            print(1000)
        else:
            assert args[-1] == "--help"
    elif tool == "docker" and args[:2] == ["image", "inspect"]:
        assert args[2] in (REF, attempt)
        formats = {"{{index .RepoDigests 0}}": REF}
        for key, val in [
            ("version", version),
            ("revision", sha),
            ("source", "https://github.com/" + REPO),
            ("licenses", "Apache-2.0"),
        ]:
            formats[
                '{{index .Config.Labels "org.opencontainers.image.' + key + '"}}'
            ] = val
        print(formats[args[-1]])
    elif tool == "docker" and args == [
        "login",
        "ghcr.io",
        "--username",
        "fixture",
        "--password-stdin",
    ]:
        assert auth and sys.stdin.read() == "dummy"
        event("login")
    elif tool == "docker" and args == ["logout", "ghcr.io"]:
        assert auth
    elif tool == "docker" and (
        args == ["pull", REF] or args == ["image", "rm", attempt]
    ):
        pass
    elif tool == "docker" and args[:1] == ["tag"]:
        assert args[1] == REF and args[2] in (f"{IMAGE}:{version}", IMAGE + ":latest")
        event("tag", args[2])
    elif tool == "docker" and args[:1] == ["push"]:
        assert auth and args[1] in (f"{IMAGE}:{version}", IMAGE + ":latest", attempt)
        event("push", args[1])
        with Path("registry").open("a") as out:
            print(args[1].split(":")[1], file=out)
    else:
        raise AssertionError(f"unexpected external invocation: {tool} {args}")
    return 0


def scenario(script, root, tools, name, historical, reject="", marker=False):
    wd = root / name
    wd.mkdir()
    sha = OLD if historical else CURRENT
    version = "0.9.0" if historical else "0.10.0"
    attempt = f"release-{version}-{sha}"
    body = "Release notes" + ("\nHooray-OCI-Digest: " + REF + "\n" if marker else "")
    (wd / "fixture.json").write_text(
        json.dumps(
            {
                "version": version,
                "sha": sha,
                "latest": 200 if historical else 100,
                "reject": reject,
                "body": body,
            }
        )
    )
    (wd / "Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')
    (wd / "registry").write_text(attempt + "\n" if historical else "")
    for file in ["events", "outputs"]:
        (wd / file).touch()
    # No real gh, docker, cosign, git or HTTP client in PATH; no user credentials.
    env = {
        "PATH": str(tools),
        "HOME": str(wd),
        "TMPDIR": str(wd),
        "RUNNER_TEMP": str(wd),
        "LC_ALL": "C",
        "GITHUB_WORKFLOW_SHA": CURRENT,
        "GITHUB_SHA": CURRENT,
        "GITHUB_OUTPUT": str(wd / "outputs"),
        "REPOSITORY": REPO,
        "REGISTRY_USER": "fixture",
        "REGISTRY_TOKEN": "dummy",
        "RECOVERY": str(historical).lower(),
        "RECOVERY_TAG": "v" + version if historical else "",
        "RECOVERY_VERSION": version if historical else "",
        "RELEASE_TAG": "" if historical else "v" + version,
        "RELEASE_VERSION": "" if historical else version,
    }
    result = subprocess.run(
        [shutil.which("bash"), str(script)],
        cwd=wd,
        check=False,
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
    )
    events = (wd / "events").read_text().splitlines()
    outputs = (wd / "outputs").read_text().splitlines()
    gates = ["verify-signature", "verify-provenance"] if historical else []
    if reject:
        expected = gates[:1] if reject == "signature" else gates
        assert result.returncode != 0 and events == expected and not outputs, (
            name,
            result,
            events,
            outputs,
        )
        return
    assert result.returncode == 0, (name, result.stderr, events)
    expected = (
        gates if historical else ["build", "login", "push " + IMAGE + ":" + attempt]
    )
    if not marker:
        expected = expected + ["patch"]
    expected += [
        "login",
        "tag " + IMAGE + ":" + version,
        "push " + IMAGE + ":" + version,
        "latest-id",
    ]
    if not historical:
        expected += ["tag " + IMAGE + ":latest", "push " + IMAGE + ":latest"]
    assert events == expected, (name, events, expected)
    assert outputs == (["reuse_provenance=true"] if historical else []) + [
        "digest=" + DIGEST
    ], (name, outputs)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "fake":
        return fake(sys.argv[2], sys.argv[3:])
    script = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        tools = root / "bin"
        tools.mkdir()
        for name in ["mktemp", "rm", "sed", "grep", "jq", "cat"]:
            target = shutil.which(name)
            if not target:
                raise RuntimeError("missing local test dependency: " + name)
            (tools / name).symlink_to(target)
        (tools / "python3").symlink_to(sys.executable)
        import shlex

        for name in ["curl", "git", "gh", "docker", "cosign"]:
            wrapper = tools / name
            wrapper.write_text(
                "#!/bin/sh\nexec "
                + shlex.quote(sys.executable)
                + " -I "
                + shlex.quote(str(Path(__file__).resolve()))
                + " fake "
                + name
                + ' "$@"\n'
            )
            wrapper.chmod(0o755)
        scenario(script, root, tools, "current-release", False)
        scenario(script, root, tools, "old-no-marker", True)
        scenario(script, root, tools, "old-with-marker", True, marker=True)
        scenario(script, root, tools, "old-bad-signature", True, reject="signature")
        scenario(script, root, tools, "old-bad-provenance", True, reject="provenance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
