"""Exercise release selection with real Git history, without contacting GitHub."""

import importlib.util
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/release_version.py"
SPEC = importlib.util.spec_from_file_location("release_version", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    def git(*args):
        return subprocess.check_output(["git", *args], text=True).strip()
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Release Test")
    git("config", "user.email", "test@example.invalid")
    git("config", "commit.gpgsign", "false")
    git("config", "tag.gpgsign", "false")
    git("config", "core.hooksPath", "/dev/null")
    git("commit", "--allow-empty", "-qm", "Initial")
    git("tag", "v0.1.4")
    return git


def test_main_gets_next_patch_and_retries_reuse_it(repo):
    repo("commit", "--allow-empty", "-qm", "Merged change")
    head = repo("rev-parse", "HEAD")
    result = release.prepare("refs/heads/main")
    assert result == {"tag": "v0.1.5", "version": "0.1.5", "latest": "true"}
    assert repo("rev-parse", "v0.1.5^{}") == head
    assert repo("rev-parse", "main") == head
    assert release.prepare("refs/heads/main") == result
    repo("commit", "--allow-empty", "-qm", "Another merge")
    assert release.prepare("refs/heads/main")["tag"] == "v0.1.6"


def test_patch_selection_uses_numeric_versions_and_ignores_prereleases(repo):
    repo("tag", "v0.2.9")
    repo("tag", "v0.2.10")
    repo("tag", "v1.0.0rc1")
    repo("tag", "unrelated")
    repo("commit", "--allow-empty", "-qm", "Merged change")
    assert release.prepare("refs/heads/main")["tag"] == "v0.2.11"


def test_explicit_tag_must_point_to_tested_commit(repo):
    repo("commit", "--allow-empty", "-qm", "Merged change")
    with pytest.raises(ValueError, match="tested commit"):
        release.prepare("refs/tags/v0.1.4")
    repo("tag", "v0.2.0")
    assert release.prepare("refs/tags/v0.2.0")["version"] == "0.2.0"


def test_old_release_retry_does_not_become_latest(repo):
    old_head = repo("rev-parse", "HEAD")
    repo("commit", "--allow-empty", "-qm", "Merged change")
    release.prepare("refs/heads/main")
    repo("checkout", "--detach", old_head)
    assert release.prepare("refs/tags/v0.1.4")["latest"] == "false"


def test_unreleased_old_commit_cannot_replace_newer_release(repo):
    repo("commit", "--allow-empty", "-qm", "Earlier merge")
    old_head = repo("rev-parse", "HEAD")
    repo("commit", "--allow-empty", "-qm", "Later merge")
    release.prepare("refs/heads/main")
    repo("checkout", "--detach", old_head)
    with pytest.raises(ValueError, match="not an ancestor"):
        release.prepare("refs/heads/main")


def test_feature_branches_cannot_publish(repo):
    with pytest.raises(ValueError, match="require main"):
        release.prepare("refs/heads/feature")
