"""Choose one stable release per tested commit without writing to main."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def stable_version(tag: str) -> tuple[int, int, int] | None:
    if re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        return tuple(int(part) for part in tag[1:].split("."))
    return None


def prepare(ref: str) -> dict[str, str]:
    head = git("rev-parse", "HEAD")
    tags = {tag: stable_version(tag) for tag in git("tag", "--list").splitlines()}
    stable = {tag: version for tag, version in tags.items() if version is not None}
    latest = max(stable.values(), default=(0, 0, 0))

    if ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
        if tag not in stable or git("rev-parse", f"{tag}^{{}}") != head:
            raise ValueError("release tag must be vMAJOR.MINOR.PATCH at the tested commit")
    elif ref == "refs/heads/main":
        existing = [tag for tag in git("tag", "--points-at", head).splitlines() if tag in stable]
        if existing:
            tag = max(existing, key=lambda name: stable[name])
        else:
            # An old workflow must not publish older code as a newer version.
            for name in stable:
                result = subprocess.run(
                    ["git", "merge-base", "--is-ancestor", name, head], check=False
                )
                if result.returncode != 0:
                    raise ValueError(f"{name} is not an ancestor of this commit; release current main")
            major, minor, patch = latest
            tag = f"v{major}.{minor}.{patch + 1}"
            git(
                "-c", "user.name=github-actions[bot]",
                "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                "tag", "-a", tag, "-m", f"Release {tag}", head,
            )
    else:
        raise ValueError("releases require main or an explicit stable version tag")

    return {
        "tag": tag,
        "version": tag[1:],
        "latest": str(stable_version(tag) >= latest).lower(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    for key, value in prepare(args.ref).items():
        print(f"{key}={value}")
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
