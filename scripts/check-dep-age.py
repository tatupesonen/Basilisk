#!/usr/bin/env python3
"""Check the two-week rule for new dependencies (docs/LOOP.md, Dependencies).

Usage: scripts/check-dep-age.py [base-ref]      (default base: HEAD)

Compares the working tree's Cargo.lock with the base ref's, asks crates.io
for the publish date of every registry package (name and version) that the
base does not have, and fails if any was published less than 14 days ago.
Run it on a merge result before committing, with HEAD as the base, or in a
worktree with `master` as the base.

Needs the network, so it is not part of scripts/gate.sh. One request per
second, as crates.io asks; a few hundred new packages take a few minutes.
Exit status: 0 all old enough, 1 a package is too young, 2 a lookup failed.
"""
import datetime
import json
import re
import subprocess
import sys
import time
import urllib.request

MIN_AGE_DAYS = 14
PACKAGE = re.compile(
    r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\nsource = "registry'
)


def packages(text):
    return set(PACKAGE.findall(text))


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    old = subprocess.run(
        ["git", "show", f"{base}:Cargo.lock"],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout
    with open("Cargo.lock", encoding="utf-8") as f:
        new = sorted(packages(f.read()) - packages(old))
    now = datetime.datetime.now(datetime.timezone.utc)
    young, failed = [], []
    for name, version in new:
        url = f"https://crates.io/api/v1/crates/{name}/{version}"
        request = urllib.request.Request(
            url, headers={"User-Agent": "basilisk-dep-age-check"}
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                created = json.load(response)["version"]["created_at"]
            published = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = (now - published).days
            if age < MIN_AGE_DAYS:
                young.append((name, version, published.date().isoformat(), age))
        except Exception as error:  # report and continue with the rest
            failed.append((name, version, type(error).__name__))
        time.sleep(1.05)
    print(f"{len(new)} new registry packages against {base}; "
          f"{len(young)} younger than {MIN_AGE_DAYS} days; {len(failed)} lookups failed")
    for name, version, date, age in young:
        print(f"TOO YOUNG  {name} {version}  published {date} ({age} days ago)")
    for name, version, error in failed:
        print(f"LOOKUP FAILED  {name} {version}  {error}")
    if young:
        print("Pin each to an older version: cargo update -p <name> --precise <version>")
        return 1
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
