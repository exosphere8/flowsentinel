#!/usr/bin/env python3
"""Writes the license notices of the third-party code FlowSentinel ships.

    python3 scripts/third_party_licenses.py [OUT.md]

The binaries and the container image contain compiled Rust crates, and the
dashboard bundle contains npm packages. Their licenses (MIT, Apache-2.0 and
others) require their notices to accompany copies, so release archives and
the image include the file this script writes (THIRD_PARTY_LICENSES.md by
default).

Covered:

- every crate the `flowsentinel` and `api-server` binaries depend on at run
  time, with every optional feature (`cargo metadata --all-features`);
- every production npm package of the dashboard (frontend/package-lock.json).

Each notice is the license files the package itself ships (LICENSE*,
LICENCE*, COPYING*, NOTICE*). Identical texts are printed once, with the
packages that use them. Needs Python 3.11+, cargo, and installed
frontend/node_modules (npm ci).
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY_CRATES = {"api-server", "cli"}
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE)([-._].*)?$", re.I)


def license_files(directory):
    found = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and LICENSE_FILE.match(path.name):
            found.append(path.read_text(encoding="utf-8", errors="replace").strip())
    return found


def rust_packages():
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    packages = {p["id"]: p for p in metadata["packages"]}
    members = set(metadata["workspace_members"])
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    # Walk run-time (normal) dependencies from the two binaries.
    todo = [i for i in members if packages[i]["name"] in BINARY_CRATES]
    seen = set()
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                todo.append(dep["pkg"])
    result = []
    for package_id in seen - members:
        package = packages[package_id]
        result.append(
            {
                "name": package["name"],
                "version": package["version"],
                "license": package.get("license") or "see the license file",
                "url": package.get("repository") or package.get("homepage") or "",
                "texts": license_files(Path(package["manifest_path"]).parent),
            }
        )
    return result


def npm_packages():
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))
    result = []
    for path, entry in lock["packages"].items():
        if not path or entry.get("dev") or entry.get("devOptional"):
            continue
        directory = ROOT / "frontend" / path
        if not directory.is_dir():
            sys.exit(f"{directory} is missing: run npm ci in frontend/ first")
        manifest = json.loads((directory / "package.json").read_text(encoding="utf-8"))
        repository = manifest.get("repository") or ""
        if isinstance(repository, dict):
            repository = repository.get("url", "")
        result.append(
            {
                "name": manifest["name"],
                "version": manifest["version"],
                "license": manifest.get("license") or entry.get("license") or "see the license file",
                "url": repository,
                "texts": license_files(directory),
            }
        )
    return result


def section(title, packages):
    lines = [f"## {title}", ""]
    lines += [
        f"- {p['name']} {p['version']} ({p['license']}){' ' + p['url'] if p['url'] else ''}"
        for p in packages
    ]
    lines.append("")
    by_text = defaultdict(list)
    without = []
    for p in packages:
        if not p["texts"]:
            without.append(p)
        for text in p["texts"]:
            by_text[" ".join(text.split())].append((p, text))
    for users in sorted(by_text.values(), key=lambda u: (u[0][0]["name"], u[0][0]["version"])):
        names = ", ".join(sorted({f"{p['name']} {p['version']}" for p, _ in users}))
        lines += [f"### {names}", "", "```text", users[0][1], "```", ""]
    if without:
        lines += [
            "### Packages without a license file",
            "",
            "These packages declare their license in their manifest only; the license's standard "
            "text applies:",
            "",
        ]
        lines += [f"- {p['name']} {p['version']}: {p['license']}" for p in without]
        lines.append("")
    return lines


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "THIRD_PARTY_LICENSES.md"
    rust = sorted(rust_packages(), key=lambda p: (p["name"], p["version"]))
    npm = sorted(npm_packages(), key=lambda p: (p["name"], p["version"]))
    lines = [
        "# Third-party licenses",
        "",
        "FlowSentinel's binaries, container image and dashboard include the following third-party "
        "code. Each package's license notice is reproduced below. FlowSentinel itself is under the "
        "MIT license (LICENSE).",
        "",
        "This file is generated by `scripts/third_party_licenses.py`.",
        "",
    ]
    lines += section(f"Rust crates ({len(rust)})", rust)
    lines += section(f"Dashboard npm packages ({len(npm)})", npm)
    out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {out}: {len(rust)} crates, {len(npm)} npm packages")


if __name__ == "__main__":
    main()
