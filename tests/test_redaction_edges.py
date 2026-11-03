import base64

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
