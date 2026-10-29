"""baton: pass auth context between agents as leases, never as secrets."""

from .crypto import CryptoError
from .models import (
    BatonError,
    Context,
    Credential,
    Lease,
    LeaseError,
    UnknownContext,
    UnknownCredential,
    VaultLocked,
)

__version__ = "0.1.0"

__all__ = [
    "BatonError",
    "Context",
    "Credential",
    "CryptoError",
    "Lease",
    "LeaseError",
    "UnknownContext",
    "UnknownCredential",
    "VaultLocked",
    "Vault",
    "__version__",
]


def __getattr__(name: str):
    if name == "Vault":
        from .vault import Vault

        return Vault
    raise AttributeError(name)
