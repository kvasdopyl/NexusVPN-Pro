"""TLS context = Windows certificate store + certifi bundle.

Windows installs root certificates on demand (when a browser first meets them), so a fresh PC may lack
the root GitHub or a subscription panel uses; Python then fails with CERTIFICATE_VERIFY_FAILED.
"""
from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def _cafile() -> str | None:
    try:
        import certifi
        return certifi.where()
    except ImportError:
        return None


def context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ca = _cafile()
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
        except (OSError, ssl.SSLError):
            pass
    return ctx
