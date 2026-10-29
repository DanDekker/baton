"""baton: pass auth context between agents as leases, never as secrets."""

from importlib.metadata import PackageNotFoundError, version

from .crypto import CryptoError, zeroize
from .models import (
    BatonError,
    Context,
    Credential,
    Lease,
    LeaseError,
    RefreshError,
    UnknownContext,
    UnknownCredential,
    VaultLocked,
)

try:
    __version__ = version("baton-auth")
except PackageNotFoundError:  # running from an unpackaged source tree
    __version__ = "0+local"

__all__ = [
    "BatonError",
    "Context",
    "Credential",
    "CryptoError",
    "Lease",
    "LeaseError",
    "RefreshError",
    "UnknownContext",
    "UnknownCredential",
    "VaultLocked",
    "Vault",
    "zeroize",
    "__version__",
]


def __getattr__(name: str):
    if name == "Vault":
        from .vault import Vault

        return Vault
    raise AttributeError(name)
