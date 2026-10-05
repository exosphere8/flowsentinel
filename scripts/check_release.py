#!/usr/bin/env python3
"""Checks that a release is consistent, and extracts its notes.

    python3 scripts/check_release.py [--tag vX.Y.Z] [--notes OUT.md]

Checks:

- the workspace version in Cargo.toml;
- the dashboard's version in frontend/package.json and package-lock.json;
- every workspace crate's version in Cargo.lock;
- a dated CHANGELOG.md section for the version.

With --tag, the tag must be "v" plus that version. With --notes, the changelog section is
written to OUT.md for the release page. Exits non-zero, saying what to fix, if anything
disagrees.
"""

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


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
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})$", re.M)
    match = heading.search(text)
    if not match:
        return None, None
    rest = text[match.end():]
    end = re.search(r"^## \[|^\[[^\]]+\]: ", rest, re.M)
    return match.group(1), rest[: end.start() if end else len(rest)].strip()


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

    date, notes = changelog_section(version)
    if not notes:
        problems.append(f"CHANGELOG.md: no '## [{version}] - YYYY-MM-DD' section with content")

    if args.tag is not None and args.tag != f"v{version}":
        problems.append(f"tag {args.tag!r} does not match the version: expected 'v{version}'")

    if problems:
        print("release check failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if args.notes:
        args.notes.write_text(notes + "\n", encoding="utf-8")
    print(f"release {version} ({date}) is consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
