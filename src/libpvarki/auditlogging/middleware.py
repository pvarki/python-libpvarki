"""
FastAPI/Starlette middleware for automatic audit context setup.

Extracts initiator information from incoming requests:
1. nginx headers (X-ClientCert-*, X-Real-IP) for direct mTLS requests
2. Propagation headers (X-Initiator-*) for service-to-service calls

Sets ContextVars that are automatically read by audit_log() helper.
"""

import logging
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .context import set_audit_context, clear_audit_context

LOGGER = logging.getLogger(__name__)


# Header names for nginx mTLS info
HEADER_REQUEST_ID = "X-Request-ID"
HEADER_REAL_IP = "X-Real-IP"
HEADER_FORWARDED_FOR = "X-Forwarded-For"
HEADER_CLIENT_CERT_DN = "X-ClientCert-DN"
HEADER_CLIENT_CERT_SERIAL = "X-ClientCert-Serial"

# Header names for service-to-service propagation
HEADER_INITIATOR_USER = "X-Initiator-User"
HEADER_INITIATOR_IP = "X-Initiator-IP"
HEADER_INITIATOR_ROLE = "X-Initiator-Role"
HEADER_INITIATOR_CERT_SERIAL = "X-Initiator-Cert-Serial"
HEADER_INITIATOR_SESSION = "X-Initiator-Session"


def _parse_cn_from_dn(distinguished_name: str) -> str:
    """
    Extract Common Name from Distinguished Name string.

    Args:
        distinguished_name: Distinguished Name, e.g., "CN=NORPPA11,O=PVARKI,C=FI"

    Returns:
        The CN value, or empty string if not found.
    """
    if not distinguished_name:
        return ""

    for part in distinguished_name.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return ""


class AuditMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """
    Middleware to extract and set audit context for each request.

    Handles two scenarios:

    1. Direct requests via nginx with mTLS:
       - Reads X-ClientCert-DN, X-ClientCert-Serial from nginx
       - Reads X-Real-IP or X-Forwarded-For for source IP

    2. Service-to-service calls with propagated context:
       - Reads X-Initiator-* headers set by upstream service
       - Preserves original initiator identity through the chain

    Priority: Direct mTLS headers take precedence over propagated headers,
    as they represent verified identity from nginx.

    nginx configuration example::

        proxy_set_header X-Request-ID $request_id;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-ClientCert-DN $ssl_client_s_dn;
        proxy_set_header X-ClientCert-Serial $ssl_client_serial;
    """

    async def dispatch(  # pylint: disable=too-many-locals
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Extract context from headers and process request."""

        # === Trace ID (correlation) ===
        trace_id = request.headers.get(HEADER_REQUEST_ID, "")
        if not trace_id:
            trace_id = str(uuid.uuid4())

        # === Source IP ===
        source_ip = self._extract_source_ip(request)

        # === Initiator Identity ===
        # Try direct mTLS first (nginx headers)
        cert_dn = request.headers.get(HEADER_CLIENT_CERT_DN, "")
        cert_serial = request.headers.get(HEADER_CLIENT_CERT_SERIAL, "")
        cert_cn = _parse_cn_from_dn(cert_dn)

        # Check for propagated context (service-to-service)
        prop_user = request.headers.get(HEADER_INITIATOR_USER, "")
        prop_ip = request.headers.get(HEADER_INITIATOR_IP, "")
        prop_role = request.headers.get(HEADER_INITIATOR_ROLE, "")
        prop_cert_serial = request.headers.get(HEADER_INITIATOR_CERT_SERIAL, "")
        prop_session = request.headers.get(HEADER_INITIATOR_SESSION, "")

        # Determine final values (direct mTLS takes precedence)
        is_propagated = False
        if cert_cn:
            # Direct mTLS request - use cert info
            initiator_user = cert_cn
            initiator_cert_serial = cert_serial
            initiator_ip = source_ip
            initiator_role = ""
            initiator_session = ""
        elif prop_user:
            # Service-to-service with propagated context
            is_propagated = True
            initiator_user = prop_user
            initiator_ip = prop_ip or source_ip
            initiator_role = prop_role
            initiator_cert_serial = prop_cert_serial
            initiator_session = prop_session
        else:
            # No identity info - just IP
            initiator_user = ""
            initiator_ip = source_ip
            initiator_role = ""
            initiator_cert_serial = ""
            initiator_session = ""

        # Set context for this request
        set_audit_context(
            trace_id=trace_id,
            initiator_ip=initiator_ip,
            initiator_user=initiator_user,
            initiator_role=initiator_role,
            initiator_cert_serial=initiator_cert_serial,
            initiator_cert_cn=cert_cn,
            initiator_session=initiator_session,
            is_propagated=is_propagated,
        )

        try:
            response = await call_next(request)
            # Add trace ID to response for debugging/correlation
            response.headers[HEADER_REQUEST_ID] = trace_id
            return response
        finally:
            # Always clear context to prevent leakage
            clear_audit_context()

    def _extract_source_ip(self, request: Request) -> str:
        """
        Extract client IP from request headers.

        Priority:
        1. X-Real-IP (set by nginx)
        2. X-Forwarded-For (first IP in chain)
        3. Direct client IP from connection

        Args:
            request: The incoming Starlette request.

        Returns:
            Client IP address, or empty string if not available.
        """
        # Prefer X-Real-IP (typically set by nginx to actual client)
        real_ip = request.headers.get(HEADER_REAL_IP, "")
        if real_ip:
            return real_ip.strip()

        # Fall back to X-Forwarded-For (take first/leftmost = original client)
        forwarded_for = request.headers.get(HEADER_FORWARDED_FOR, "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Last resort: direct connection IP
        if request.client:
            return request.client.host

        return ""


def update_audit_user(user: str, role: str = "", session: str = "") -> None:
    """
    Update audit context with user info after authentication.

    Call this after JWT validation or other auth mechanism in your
    FastAPI dependency to enrich the audit context with user identity.

    Args:
        user: Username or callsign.
        role: User role (admin, user, operator, etc.).
        session: Session identifier if applicable.

    Example::

        async def get_current_user(token: str = Depends(oauth2_scheme)):
            payload = decode_jwt(token)
            update_audit_user(
                user=payload["sub"],
                role=payload.get("role", ""),
            )
            return payload
    """
    set_audit_context(
        initiator_user=user,
        initiator_role=role,
        initiator_session=session,
    )
