"""A disposable smart HTTP Git repository for the Hooray qualification pilot."""

import os
import subprocess
import threading
from contextlib import contextmanager
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def isolated_env():
    return {
        "PATH": os.environ["PATH"],
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "NO_PROXY": "127.0.0.1",
    }


def git(cwd, *args, data=None, check=True):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=isolated_env(),
        input=data,
        capture_output=True,
        check=check,
        timeout=30,
    )


def create_public_repo(public_root):
    public_root.mkdir(mode=0o700)
    git(public_root, "init", "--bare", "--initial-branch=empty", "release.git")
    repo = public_root / "release.git"
    git(repo, "config", "http.receivepack", "false")
    (repo / "git-daemon-export-ok").touch()
    return repo


def publish_verified_bytes(repo, digest, archive):
    """Caller authorizes these exact bytes first. The digest is also the ref name."""
    blob = git(repo, "hash-object", "-w", "--stdin", data=archive).stdout.strip()
    if git(repo, "cat-file", "blob", blob).stdout != archive:
        raise RuntimeError("published Git blob differs from authorized bytes")
    tree = git(repo, "mktree", data=b"100644 blob " + blob + b"\tartifact.zip\n").stdout.strip()
    commit = git(
        repo,
        "-c",
        "user.name=Hooray pilot",
        "-c",
        "user.email=pilot@localhost",
        "commit-tree",
        tree,
        "-m",
        f"Publish SHA-256 {digest}",
    ).stdout.strip()
    # Empty old value requires a new ref. Published refs are never overwritten.
    git(repo, "update-ref", f"refs/heads/sha256/{digest}", commit, "")
    return commit.decode()


@contextmanager
def read_only_http(public_root):
    backend = Path(git(public_root, "--exec-path").stdout.decode().strip()) / "git-http-backend"
    if not backend.is_file():
        raise FileNotFoundError(backend)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.serve()

        def do_POST(self):
            self.serve()

        def serve(self):
            # Match the entire raw request target; no filesystem paths, queries or
            # unauthenticated request headers are used to choose a repo or CGI command.
            if (self.command, self.path) in (
                ("GET", "/release.git/info/refs?service=git-receive-pack"),
                ("POST", "/release.git/git-receive-pack"),
            ):
                self.send_error(403)
                return
            if (self.command, self.path) not in (
                ("GET", "/release.git/info/refs?service=git-upload-pack"),
                ("POST", "/release.git/git-upload-pack"),
            ):
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= length <= 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            if (
                self.command == "POST"
                and self.headers.get("Content-Type") != "application/x-git-upload-pack-request"
            ):
                self.send_error(415)
                return
            path, _, query = self.path.partition("?")
            env = {
                **isolated_env(),
                "GIT_PROJECT_ROOT": str(public_root),
                "PATH_INFO": path,
                "QUERY_STRING": query,
                "REQUEST_METHOD": self.command,
                "CONTENT_LENGTH": str(length),
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            }
            if self.headers.get("Git-Protocol") == "version=2":
                env["HTTP_GIT_PROTOCOL"] = "version=2"
            self.connection.settimeout(10)
            response = subprocess.run(
                [backend],
                input=self.rfile.read(length),
                capture_output=True,
                env=env,
                cwd=public_root,
                timeout=30,
                # upload-pack can emit a valid Git protocol ERR packet and
                # exit nonzero (for example, an unknown object identifier).
                check=False,
            ).stdout
            headers, sep, body = response.partition(b"\r\n\r\n")
            if not sep:
                self.send_error(502)
                return
            fields = BytesParser().parsebytes(headers + b"\r\n\r\n")
            self.send_response(int(fields.get("Status", "200").split()[0]))
            for name in ("Content-Type", "Cache-Control"):
                if name in fields:
                    self.send_header(name, fields[name])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()
