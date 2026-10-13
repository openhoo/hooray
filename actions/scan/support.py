#!/usr/bin/env python3
"""Local composite-action support. Uses only Python's standard library."""

import json
import os
from pathlib import Path
import shutil
import stat
import sys


FORMATS = {
    "json", "yaml", "table", "sarif", "gitlab-sarif", "junit", "html",
    "cyclonedx-vex", "cyclone-dx-vex", "gitlab-cyclonedx", "spdx",
    "gitlab-code-quality", "json-lines", "csv", "gitlab-artifacts", "markdown",
}
MAX_HISTORY_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_SUMMARY_DETAIL_BYTES = 900 * 1024


def safe_text(value):
    return isinstance(value, str) and value and len(value) <= 4096 and all(
        ord(character) >= 32 and ord(character) != 127 for character in value
    )


def parent_fd(path):
    """Anchor each existing directory through O_NOFOLLOW, including ancestors."""
    absolute = Path(path)
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            following = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = following
        return descriptor, absolute.name
    except BaseException:
        os.close(descriptor)
        raise


def target_kind(path):
    descriptor, name = parent_fd(path)
    try:
        try:
            mode = os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return None
        if stat.S_ISREG(mode):
            return "file"
        raise ValueError("output must be a regular file or a new bundle directory")
    finally:
        os.close(descriptor)


def validate():
    output = os.environ["INPUT_OUTPUT"]
    if os.environ["INPUT_FORMAT"] == "gitlab-artifacts" and not output:
        raise ValueError("gitlab-artifacts requires an output directory")
    if output:
        if not safe_text(output):
            raise ValueError("output contains control characters or is too long")
        kind = target_kind(output)
        if os.environ["INPUT_FORMAT"] == "gitlab-artifacts" and kind is not None:
            raise ValueError("gitlab-artifacts requires a new directory")
    formats = os.environ["INPUT_ADDITIONAL_FORMATS"]
    if formats:
        values = formats.split(",")
        if len(values) > len(FORMATS) or len(set(values)) != len(values):
            raise ValueError("additional-formats must be unique")
        if any(value not in FORMATS for value in values):
            raise ValueError("additional-formats contains an unsupported format")
    # Runner-generated paths enter single-line action outputs as well.
    if not safe_text(os.environ["RUNNER_TEMP"]):
        raise ValueError("RUNNER_TEMP contains unsupported characters")


def load(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def save(path, value):
    with open(path, "w", encoding="utf-8") as destination:
        json.dump(value, destination, sort_keys=True, separators=(",", ":"))


def metadata(history, destination, scan_exit):
    information = os.stat(history, follow_symlinks=False)
    if not stat.S_ISREG(information.st_mode) or not 0 < information.st_size <= MAX_HISTORY_BYTES:
        raise ValueError("history must be a nonempty, bounded regular file")
    runs = load(history)
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("expected exactly one persisted scan run")
    report = runs[0]
    run_id = report["run"]["id"]
    if not safe_text(run_id) or run_id.startswith("-"):
        raise ValueError("invalid persisted run identifier")
    summary = report["policy_summary"]
    counts = {key: summary[key] for key in ("allowed", "warned", "denied")}
    if any(type(value) is not int or not 0 <= value <= 2**64 - 1 for value in counts.values()):
        raise ValueError("invalid policy counts")
    if (counts["denied"] > 0) != (scan_exit == "1"):
        raise ValueError("persisted policy outcome disagrees with scanner exit status")
    if not isinstance(report["findings"], dict):
        raise ValueError("invalid finding collection")
    counts["finding-count"] = len(report["findings"])
    counts["run-id"] = run_id
    counts["reports"] = {}
    counts["report"] = ""
    counts["artifacts-directory"] = ""
    save(destination, counts)
    Path(destination).with_name("run-id").write_text(run_id, encoding="utf-8")


def regular_report(path):
    information = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(information.st_mode) or not 0 < information.st_size <= MAX_REPORT_BYTES:
        raise ValueError("report must be a nonempty, bounded regular file")


def copy_file(source, parent, name):
    regular_report(source)
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        destination_fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600, dir_fd=parent,
        )
        try:
            if not stat.S_ISREG(os.fstat(destination_fd).st_mode):
                raise ValueError("report destination is not a regular file")
            os.ftruncate(destination_fd, 0)
            with os.fdopen(source_fd, "rb", closefd=False) as reader:
                with os.fdopen(destination_fd, "wb", closefd=False) as writer:
                    shutil.copyfileobj(reader, writer)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def register(metadata_path, path, report_format, primary=False):
    path = os.path.abspath(path)
    if report_format == "gitlab-artifacts":
        if not stat.S_ISDIR(os.stat(path, follow_symlinks=False).st_mode):
            raise ValueError("missing report bundle")
        entries = list(Path(path).iterdir())
        if not entries:
            raise ValueError("empty report bundle")
        for entry in entries:
            regular_report(entry)
    else:
        regular_report(path)
    state = load(metadata_path)
    # If the primary format is repeated, point the manifest to the caller's
    # configured primary path and retain the extra report in its directory.
    state["reports"].setdefault(report_format, path)
    if primary:
        state["report"] = path
    else:
        state["artifacts-directory"] = str(Path(path).parent)
    save(metadata_path, state)


def publish(metadata_path, source, target, report_format):
    parent, name = parent_fd(target)
    try:
        copy_file(source, parent, name)
    finally:
        os.close(parent)
    register(metadata_path, target, report_format, primary=True)


def finish(metadata_path, policy_status, exit_code, scan_exit):
    state = load(metadata_path)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as outputs:
        for key, value in state.items():
            if key == "reports":
                value = json.dumps(value, sort_keys=True, separators=(",", ":"))
            outputs.write(f"{key}={value}\n")
    if os.environ["INPUT_SUMMARY"] == "true":
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write("## Hooray scan\n\n")
            summary.write(f"Policy: **{policy_status}**. Action exit: **{exit_code}**. Scanner exit: **{scan_exit}**.\n\n")
            summary.write("| Findings | Allow | Warn | Deny |\n| ---: | ---: | ---: | ---: |\n")
            summary.write(f"| {state['finding-count']} | {state['allowed']} | {state['warned']} | {state['denied']} |\n\n")
            summary.write("Counts describe the persisted run. Offline analysis excludes OSV queries.\n")
            markdown = state["reports"].get("markdown")
            if markdown:
                with open(markdown, "rb") as detailed_report:
                    content = detailed_report.read(MAX_SUMMARY_DETAIL_BYTES + 1)
                truncated = len(content) > MAX_SUMMARY_DETAIL_BYTES
                summary.write("\n### Detailed report\n\n")
                summary.write(content[:MAX_SUMMARY_DETAIL_BYTES].decode("utf-8", errors="replace"))
                if truncated:
                    summary.write("\n\nSummary truncated. Download the Markdown report for all details.\n")


COMMANDS = {
    "validate": validate, "metadata": metadata, "publish": publish,
    "register": register, "finish": finish,
}

if __name__ == "__main__":
    try:
        COMMANDS[sys.argv[1]](*sys.argv[2:])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        # Paths and JSON values may be repository controlled. Never echo them
        # into workflow commands or leak report contents on parse failures.
        print(f"::error::Hooray action {sys.argv[1]} failed; check report paths, CLI compatibility and persisted run metadata.", file=sys.stderr)
        sys.exit(2)
