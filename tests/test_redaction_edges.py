import base64
import json

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
