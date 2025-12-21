"""
PVARKI Audit Logging Module.

Add-on to libpvarki.logging that provides structured audit logging with:

- **AUDIT log level (25)** - Between INFO and WARNING
- **Request context propagation** - via ContextVars (async-safe)
- **Service-to-service propagation** - via HTTP headers
- **ECS-compliant fields** - works with existing ecs-logging formatter

This module builds on:

- libadvian.logging (base logging, MR #15 adds AUDIT level)
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
    from libpvarki.auditlogging import audit_log

    LOGGER = logging.getLogger(__name__)

    LOGGER.audit(
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
from typing import Any

# Import existing libpvarki logging (which builds on libadvian)
from libpvarki.logging import init_logging

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
)

# Service-to-service propagation
from .propagation import (
    get_propagation_headers,
    inject_audit_context,
    AuditContextClientMixin,
    create_audit_trace_config,
)


# =============================================================================
# AUDIT Level Setup
# =============================================================================

# AUDIT log level: between INFO (20) and WARNING (30)
AUDIT = 25


def _ensure_audit_level() -> None:
    """
    Ensure AUDIT log level is registered with Python logging.

    This provides a fallback for libadvian versions before MR #15 is merged.
    Once MR #15 is merged and released, libadvian will handle this natively.

    Safe to call multiple times - will not duplicate registration.

    The AUDIT level (25) sits between INFO (20) and WARNING (30),
    making it visible at INFO level but filterable separately.
    """
    if hasattr(logging, "AUDIT"):
        return  # Already registered by libadvian or previous call

    logging.addLevelName(AUDIT, "AUDIT")
    setattr(logging, "AUDIT", AUDIT)

    def audit(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
        """
        Log an audit message at level 25.

        Usage::

            LOGGER.audit("Event description", extra=audit_log(...))
        """
        if self.isEnabledFor(AUDIT):
            self._log(AUDIT, message, args, **kwargs)

    logging.Logger.audit = audit  # type: ignore[attr-defined]


def init_audit(level: int = logging.INFO) -> None:
    """
    Initialize logging with AUDIT level support.

    Call this instead of ``init_logging()`` in services that need audit logging.
    Sets up the AUDIT level and configures formatters via libpvarki.logging.

    Args:
        level: Minimum log level. Default INFO (20) shows AUDIT (25) events.
               Use logging.DEBUG (10) for verbose output.
               Use logging.WARNING (30) to suppress AUDIT events.

    Example::

        from libpvarki.auditlogging import init_audit
        import logging

        # In your app startup:
        init_audit(logging.INFO)

        # Or for debugging:
        init_audit(logging.DEBUG)
    """
    _ensure_audit_level()
    init_logging(level)


# Ensure AUDIT level exists on module import
# This allows LOGGER.audit() to work even before init_audit() is called
_ensure_audit_level()


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
    # Propagation
    "get_propagation_headers",
    "inject_audit_context",
    "AuditContextClientMixin",
    "create_audit_trace_config",
]
