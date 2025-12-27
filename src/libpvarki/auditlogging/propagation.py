"""
Service-to-service audit context propagation.

When one PVARKI service calls another (e.g., rmapi -> takrmapi),
the original initiator information must be passed along so audit
logs in downstream services correctly attribute actions.

This module provides helpers to:
1. Get headers to include in outgoing HTTP requests
2. Inject context into aiohttp client sessions

Example usage with aiohttp (already a libpvarki dependency)::

    from libpvarki.auditlogging import get_propagation_headers
    import aiohttp

    async def call_product_api(url: str, data: dict):
        headers = get_propagation_headers()
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=data, headers=headers)
"""

from __future__ import annotations

from typing import Dict, Optional, TYPE_CHECKING

from .context import get_audit_context

if TYPE_CHECKING:
    import aiohttp

# Header names for propagation (must match middleware.py)
HEADER_REQUEST_ID = "X-Request-ID"
HEADER_INITIATOR_USER = "X-Initiator-User"
HEADER_INITIATOR_IP = "X-Initiator-IP"
HEADER_INITIATOR_ROLE = "X-Initiator-Role"
HEADER_INITIATOR_CERT_SERIAL = "X-Initiator-Cert-Serial"
HEADER_INITIATOR_SESSION = "X-Initiator-Session"


def get_propagation_headers() -> Dict[str, str]:
    """
    Get HTTP headers to propagate audit context to downstream services.

    Include these headers when making HTTP requests to other PVARKI
    services to preserve the initiator chain for audit logging.

    Returns:
        Dict of header name -> value. Only non-empty values included.

    Example with aiohttp::

        from libpvarki.auditlogging import get_propagation_headers
        import aiohttp

        async with aiohttp.ClientSession() as session:
            headers = get_propagation_headers()
            await session.post(url, json=data, headers=headers)

    Example with libpvarki.mtlshelp.session::

        from libpvarki.mtlshelp.session import get_session
        from libpvarki.auditlogging import get_propagation_headers

        session = await get_session(client_cert, client_key, ca_cert)
        headers = get_propagation_headers()
        async with session.post(url, json=data, headers=headers) as resp:
            ...
    """
    ctx = get_audit_context()
    headers: Dict[str, str] = {}

    # Always include trace ID for correlation
    if ctx.trace_id:
        headers[HEADER_REQUEST_ID] = ctx.trace_id

    # Include initiator info if available
    if ctx.initiator_user:
        headers[HEADER_INITIATOR_USER] = ctx.initiator_user
    if ctx.initiator_ip:
        headers[HEADER_INITIATOR_IP] = ctx.initiator_ip
    if ctx.initiator_role:
        headers[HEADER_INITIATOR_ROLE] = ctx.initiator_role
    if ctx.initiator_cert_serial:
        headers[HEADER_INITIATOR_CERT_SERIAL] = ctx.initiator_cert_serial
    if ctx.initiator_session:
        headers[HEADER_INITIATOR_SESSION] = ctx.initiator_session

    return headers


def inject_audit_context(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Inject audit context into an existing headers dict.

    Convenience function that merges propagation headers with
    existing headers. Existing headers are NOT overwritten.

    Args:
        headers: Existing headers dict, or None to create new one.

    Returns:
        Headers dict with audit context added.

    Example::

        headers = {"Content-Type": "application/json"}
        headers = inject_audit_context(headers)
        await session.post(url, headers=headers, json=data)
    """
    result = dict(headers) if headers else {}
    propagation = get_propagation_headers()

    # Add propagation headers, don't overwrite existing
    for key, value in propagation.items():
        if key not in result:
            result[key] = value

    return result


class AuditContextClientMixin:
    """
    Mixin for HTTP clients that automatically propagates audit context.

    Can be used as a mixin for custom client classes.

    Example::

        class ProductClient(AuditContextClientMixin):
            def __init__(self, base_url: str):
                self.base_url = base_url

            async def notify_enrollment(self, callsign: str):
                headers = self.get_audit_headers()
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        f"{self.base_url}/api/v1/enrolled",
                        json={"callsign": callsign},
                        headers=headers,
                    )
    """

    def get_audit_headers(self) -> Dict[str, str]:
        """Get headers with audit context for HTTP requests."""
        return get_propagation_headers()

    def merge_audit_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Merge audit headers with existing headers."""
        return inject_audit_context(headers)


def create_audit_trace_config() -> "aiohttp.TraceConfig":
    """
    Create aiohttp TraceConfig that adds audit headers to all requests.

    This automatically injects propagation headers into every request
    made by the ClientSession.

    Returns:
        aiohttp.TraceConfig instance.

    Example::

        import aiohttp
        from libpvarki.auditlogging import create_audit_trace_config

        trace_config = create_audit_trace_config()
        async with aiohttp.ClientSession(trace_configs=[trace_config]) as session:
            # All requests automatically include audit headers
            await session.get("http://other-service/api/v1/status")
    """
    try:
        import aiohttp  # pylint: disable=import-outside-toplevel

        async def on_request_start(
            _session: aiohttp.ClientSession,
            _trace_config_ctx: object,
            params: aiohttp.TraceRequestStartParams,
        ) -> None:
            headers = get_propagation_headers()
            for key, value in headers.items():
                if key not in params.headers:
                    params.headers[key] = value

        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(on_request_start)
        return trace_config

    except ImportError as exc:
        raise ImportError(
            "aiohttp is required for create_audit_trace_config(). "
            "This should already be installed as a libpvarki dependency."
        ) from exc
