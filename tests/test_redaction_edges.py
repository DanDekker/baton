import base64
import json
import re
from urllib.parse import quote, quote_plus

import pytest

from baton_auth.redact import Redactor


@pytest.mark.parametrize(
    "secret", ["eightkey", "ninekeys9", "tenkeys123", "elevenkeys1", "🔑" * 8]
)
def test_short_secrets_are_redacted_in_base64_variants(secret):
    redactor = Redactor([secret])
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encode(secret.encode()).decode()
        for value in (encoded, encoded.rstrip("=")):
            clean, count = redactor.redact_counted(f"token={value}")
            assert value not in clean
            assert clean == "token=«baton:redacted»" and count == 1


@pytest.mark.parametrize(
    "secret", ['private"key123', r"private\key123", "private\tkey\n123", "clé-privée🔑123"]
)
@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_json_escaped_secrets_are_redacted(secret, ensure_ascii):
    encoded = json.dumps(secret, ensure_ascii=ensure_ascii)[1:-1]
    clean, count = Redactor([secret]).redact_counted(f'{{"token":"{encoded}"}}')
    assert clean == '{"token":"«baton:redacted»"}'
    assert count == 1


@pytest.mark.parametrize("encode", [quote, quote_plus])
@pytest.mark.parametrize("mode", ["lower", "mixed"])
def test_percent_escape_hex_is_case_insensitive(encode, mode):
    secret = "Private Key+/=42"
    encoded = encode(secret, safe="")
    encoded = re.sub(
        r"%[0-9A-F]{2}",
        lambda match: match[0].lower() if mode == "lower" or match[0] == "%2F" else match[0],
        encoded,
    )
    clean, count = Redactor([secret]).redact_counted(f"token={encoded}")
    assert clean == "token=«baton:redacted»"
    assert count == 1


def test_percent_escape_matching_keeps_literal_letters_case_sensitive():
    secret = "Private+Key/42"
    encoded = quote(secret, safe="").replace("Private", "private")
    assert Redactor([secret]).redact(encoded) == encoded
