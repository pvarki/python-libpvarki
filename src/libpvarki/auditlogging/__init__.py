"""
PVARKI Audit Logging Module.

Add-on to libpvarki.logging that provides structured audit logging with:

- **AUDIT log level** - Above CRITICAL, always visible
- **Request context propagation** - via ContextVars (async-safe)
- **Service-to-service propagation** - via HTTP headers
- **ECS-compliant fields** - works with existing ecs-logging formatter

This module builds on:

- libadvian.logging (provides AUDIT level via add_trace_and_audit())
- libpvarki.logging (ECS formatting via ecs-logging)

Quick Start
-----------
1. Initialize logging in your FastAPI app::

    from fastapi import FastAPI
    from libpvarki.auditlogging import init_audit, AuditMiddleware
    import logging

    app = FastAPI()
    app.add_middleware(AuditMiddleware)

    @app.on_event("startup")
    async def startup():
        init_audit(logging.INFO)

2. Log audit events in your code::

    import logging
    from libpvarki.auditlogging import audit_log, AUDIT

    LOGGER = logging.getLogger(__name__)

    LOGGER.log(
        AUDIT,
        "Certificate issued for user",
        extra=audit_log(
            category="iam",
            action="cert_issue",
            outcome="success",
            target_user="NORPPA11",
            target_resource="DEADBEEF",
        )
    )

3. Propagate context to downstream services::

    from libpvarki.auditlogging import get_propagation_headers
    from libpvarki.mtlshelp.session import get_session

    session = await get_session(...)
    headers = get_propagation_headers()
    await session.post(url, json=data, headers=headers)


Environment Variables
---------------------
LOG_CONSOLE_FORMATTER : str
    "ecs" (default) for JSON, "local" for human-readable.
    (Inherited from libpvarki.logging)
SERVICE_NAME : str
    Service identifier for logs (defaults to HOSTNAME).
RELEASE_TAG : str
    Service version for logs.

Header Conventions
------------------
nginx -> service::

    X-Request-ID: Trace correlation ID
    X-Real-IP: Client IP
    X-ClientCert-DN: mTLS certificate DN
    X-ClientCert-Serial: mTLS certificate serial

service -> service::

    X-Request-ID: Trace correlation ID
    X-Initiator-User: Original user/callsign
    X-Initiator-IP: Original client IP
    X-Initiator-Role: User role
    X-Initiator-Cert-Serial: Original cert serial
    X-Initiator-Session: Session ID
"""

import logging

# Import existing libpvarki logging (which builds on libadvian)
from libpvarki.logging import init_logging

# Import AUDIT level from libadvian
# libadvian.logging.add_trace_and_audit() registers AUDIT = CRITICAL + 5 = 55
AUDIT: int = logging.CRITICAL + 5  # 55

try:
    from libadvian.logging import add_trace_and_audit

    # Register TRACE and AUDIT levels (side-effect: adds names into stdlib logging)
    add_trace_and_audit()

except ImportError:
    # Fallback: if libadvian doesn't have add_trace_and_audit yet
    logging.addLevelName(AUDIT, "AUDIT")
    setattr(logging, "AUDIT", AUDIT)
else:
    # In case libadvian registered it, still ensure stdlib has the attribute at runtime.
    # (mypy won't care; this is runtime ergonomics only)
    if not hasattr(logging, "AUDIT"):
        setattr(logging, "AUDIT", AUDIT)


# Context management
from .context import (
    AuditContext,
    get_audit_context,
    set_audit_context,
    clear_audit_context,
)

# FastAPI middleware
from .middleware import (
    AuditMiddleware,
    update_audit_user,
)

# Logging helpers
from .helpers import (
    audit_log,
    audit_extra,
    audit_authentication,
    audit_iam,
    audit_authorization,
    audit_configuration,
    audit_session,
    audit_anomaly,
    code_fingerprint,
)

# Service-to-service propagation
from .propagation import (
    get_propagation_headers,
    inject_audit_context,
    AuditContextClientMixin,
    create_audit_trace_config,
)


def init_audit(level: int = logging.INFO) -> None:
    """
    Initialize logging with AUDIT level support.

    Call this instead of ``init_logging()`` in services that need audit logging.
    The AUDIT level (55, above CRITICAL) is always visible regardless of the
    level parameter - it cannot be accidentally silenced.

    Args:
        level: Minimum log level for non-audit messages. Default INFO (20).
               Use logging.DEBUG (10) for verbose output.
               AUDIT events (level 55) are always logged regardless of this setting.

    Example::

        from libpvarki.auditlogging import init_audit
        import logging

        # In your app startup:
        init_audit(logging.INFO)

        # Or for debugging:
        init_audit(logging.DEBUG)
    """
    init_logging(level)


__all__ = [
    # Initialization
    "init_audit",
    "AUDIT",
    # Context management
    "AuditContext",
    "get_audit_context",
    "set_audit_context",
    "clear_audit_context",
    # Middleware
    "AuditMiddleware",
    "update_audit_user",
    # Logging helpers
    "audit_log",
    "audit_extra",
    "audit_authentication",
    "audit_iam",
    "audit_authorization",
    "audit_configuration",
    "audit_session",
    "audit_anomaly",
    "code_fingerprint",
    # Propagation
    "get_propagation_headers",
    "inject_audit_context",
    "AuditContextClientMixin",
    "create_audit_trace_config",
]
