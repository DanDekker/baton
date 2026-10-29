"""Scrub secret material out of anything an agent can see.

Every byte returned over MCP or printed by `baton run` passes through here.
Without this the whole broker design is decorative: `baton run -- env` would
hand the model its own credentials.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Provider token shapes worth catching even when we did not mint them.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-akid", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    ("openai-proj", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{48,}\b")),
    ("openai", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic-api", re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{86}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("google-api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("stripe", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
]

MIN_LEN = 8


def collect_values(obj: object) -> list[str]:
    """Every string in a nested secret payload, longest first."""
    out: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            if len(node) >= MIN_LEN:
                out.append(node)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, Iterable):
            for v in node:
                walk(v)

    walk(obj)
    return sorted(set(out), key=len, reverse=True)


class Redactor:
    """Replaces known secrets, then provider-shaped tokens."""

    def __init__(self, secrets: Iterable[str] = (), marker: str = "«baton:redacted»"):
        values = [s for s in set(secrets) if len(s) >= MIN_LEN]
        values.sort(key=len, reverse=True)
        self._values = values
        self._marker = marker
        if values:
            self._literal_pattern = re.compile("|".join(re.escape(v) for v in values))
        else:
            self._literal_pattern = None

    def __call__(self, text: str) -> str:
        return self.redact(text)

    def redact(self, text: str) -> str:
        return self.redact_counted(text)[0]

    def redact_counted(self, text: str) -> tuple[str, int]:
        """Redact and report how many substitutions were made."""
        if not isinstance(text, str):
            return text, 0
        out = text
        hits = 0
        if self._literal_pattern is not None:
            out, n = self._literal_pattern.subn(self._marker, out)
            hits += n
        for name, pat in _PATTERNS:
            out, n = pat.subn(f"{self._marker}[{name}]", out)
            hits += n
        return out, hits

    def redact_obj(self, obj: object) -> object:
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {k: self.redact_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact_obj(v) for v in obj]
        return obj
