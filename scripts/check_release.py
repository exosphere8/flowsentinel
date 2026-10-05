#!/usr/bin/env python3
"""Checks that a release is consistent, and extracts its notes.

    python3 scripts/check_release.py [--tag vX.Y.Z] [--notes OUT.md]

Needs Python 3.11 or later. Checks that these agree with the workspace
version in Cargo.toml:

- the dashboard's version in frontend/package.json and package-lock.json;
- every workspace crate's version in Cargo.lock;
- the API version in docs/openapi.json;
- the versions in the examples of README.md, docs/, .env.example and
  docker-compose.yml (image tags, archive names, `--branch vX.Y.Z`);
- a CHANGELOG.md section "## [X.Y.Z] - YYYY-MM-DD" with a valid date and
  content.

With --tag, the tag must be "v" plus that version. With --notes, the
changelog section is written to OUT.md for the release page, with wrapped
lines joined (GitHub shows each line break in release notes). Exits non-zero,
saying what to fix, if anything disagrees.
"""

import argparse
import datetime
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
# Version mentions in examples: (description, pattern whose group 1 is a version).
MENTIONS = [
    ("image tag", re.compile(r"ghcr\.io/exosphere8/flowsentinel:([0-9][0-9A-Za-z.-]*[0-9A-Za-z])")),
    ("archive name", re.compile(r"flowsentinel-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)-(?:x86_64|aarch64)")),
    ("git tag", re.compile(r"--branch v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)")),
    ("--version output", re.compile(r"^# flowsentinel (\S+)$", re.M)),
]
MENTION_FILES = ["README.md", ".env.example", "docker-compose.yml", "docs/*.md"]
LINK_DEFINITION = re.compile(r"^\[[^\]]+\]: \S+$")


def workspace_version():
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return manifest["workspace"]["package"]["version"], manifest["workspace"]["members"]


def crate_names(members):
    names = set()
    for member in members:
        for path in sorted(ROOT.glob(f"{member}/Cargo.toml")):
            names.add(tomllib.loads(path.read_text(encoding="utf-8"))["package"]["name"])
    return names


def changelog_section(version):
    """The section's date and body, or (None, None)."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"^## \[{re.escape(version)}\] - (\S+)[ \t]*$", re.M)
    match = heading.search(text)
    if not match:
        return None, None
    rest = text[match.end():]
    end = re.search(r"^## ", rest, re.M)
    lines = rest[: end.start() if end else len(rest)].strip().splitlines()
    # The link definitions at the end of the file belong to no section.
    while lines and (not lines[-1].strip() or LINK_DEFINITION.match(lines[-1])):
        lines.pop()
    return match.group(1), "\n".join(lines).strip()


def unwrap(markdown):
    """Joins hard-wrapped lines of paragraphs and list items."""
    out = []
    fenced = False
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            out.append(line)
            continue
        starts_block = (
            fenced
            or not stripped
            or stripped.startswith(("#", "|", ">"))
            or re.match(r"^\s*([-*+]|\d+\.)\s", line)
        )
        previous = out[-1].strip() if out else ""
        continues = previous and not previous.startswith(("#", "|", "```"))
        if starts_block or not continues:
            out.append(line)
        else:
            out[-1] = out[-1].rstrip() + " " + stripped
    return "\n".join(out)


def version_mentions(version):
    problems = []
    minor = ".".join(version.split("-")[0].split(".")[:2])
    files = []
    for pattern in MENTION_FILES:
        files += sorted(ROOT.glob(pattern))
    for path in files:
        text = path.read_text(encoding="utf-8")
        name = path.relative_to(ROOT)
        for what, pattern in MENTIONS:
            for match in pattern.finditer(text):
                found = match.group(1)
                if found not in (version, minor):
                    line = text.count("\n", 0, match.start()) + 1
                    problems.append(f"{name}:{line}: {what} {found!r}, expected {version!r}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", help="the release tag, for example v0.1.0")
    parser.add_argument("--notes", type=Path, help="write the release notes to this file")
    args = parser.parse_args()

    problems = []
    version, members = workspace_version()
    if not SEMVER.match(version):
        problems.append(f"Cargo.toml: workspace version {version!r} is not X.Y.Z")

    package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))
    for name, found in [
        ("frontend/package.json", package.get("version")),
        ("frontend/package-lock.json", lock.get("version")),
        ("frontend/package-lock.json (root package)", lock.get("packages", {}).get("", {}).get("version")),
    ]:
        if found != version:
            problems.append(f"{name}: version {found!r}, expected {version!r} (npm version {version})")

    cargo_lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    locked = {p["name"]: p["version"] for p in cargo_lock["package"] if "source" not in p}
    for name in sorted(crate_names(members)):
        if locked.get(name) != version:
            problems.append(
                f"Cargo.lock: {name} is {locked.get(name)!r}, expected {version!r} (run cargo update -w)"
            )

    openapi = json.loads((ROOT / "docs/openapi.json").read_text(encoding="utf-8"))
    if openapi.get("info", {}).get("version") != version:
        problems.append(
            "docs/openapi.json: info.version is "
            f"{openapi.get('info', {}).get('version')!r}, expected {version!r} "
            "(FLOWSENTINEL_UPDATE_OPENAPI=1 cargo test -p api-server --test openapi)"
        )

    problems += version_mentions(version)

    date, notes = changelog_section(version)
    if not notes:
        problems.append(f"CHANGELOG.md: no '## [{version}] - YYYY-MM-DD' section with content")
    else:
        try:
            datetime.date.fromisoformat(date)
        except ValueError:
            problems.append(f"CHANGELOG.md: {date!r} in the {version} heading is not a YYYY-MM-DD date")

    if args.tag is not None and args.tag != f"v{version}":
        problems.append(f"tag {args.tag!r} does not match the version: expected 'v{version}'")

    if problems:
        print("release check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if args.notes:
        args.notes.write_text(unwrap(notes) + "\n", encoding="utf-8")
    print(f"release {version} ({date}) is consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
