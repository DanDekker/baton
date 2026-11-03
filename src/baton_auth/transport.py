"""HTTP connections pinned to addresses already checked by the caller."""

from contextlib import contextmanager
import time

import httpx


@contextmanager
def pinned_stream(method, url, addresses, *, headers, timeout, content=None, data=None):
    origin = httpx.URL(url)
    headers = {k: v for k, v in headers.items() if k.lower() != "host"}
    headers["Host"] = origin.netloc.decode("ascii")
    deadline = time.monotonic() + timeout
    with httpx.Client(
        timeout=min(timeout, 10.0), follow_redirects=False, trust_env=False
    ) as client:
        for index, address in enumerate(addresses):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.ConnectTimeout("connection deadline exceeded")
            request = client.build_request(
                method,
                origin.copy_with(host=address),
                headers=headers,
                content=content,
                data=data,
                timeout=min(remaining, 10.0),
                extensions={"sni_hostname": origin.host},
            )
            try:
                response = client.send(request, stream=True)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if index == len(addresses) - 1:
                    raise
                continue
            # Only connection failures may retry another validated address.
            # Once headers arrive, a POST may already have taken effect.
            try:
                yield response
            finally:
                response.close()
            return
    raise httpx.ConnectError("no validated address available")
