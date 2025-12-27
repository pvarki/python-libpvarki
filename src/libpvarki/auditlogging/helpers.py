"""
Convenience functions for audit logging.

These helpers format the 'extra' dict for LOGGER.audit() calls with
proper ECS field mapping and automatic context injection from ContextVars.

The extra fields will be properly formatted by ecs-logging inlibpvarki.logging into ECS-compliant JSON output.

Usage::

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
            target_resource_type="certificate",
        )
    )
"""

import os
from typing import Optional, Dict, Any

from .context import get_audit_context


# Service identification from environment
# These match what's typically set in PVARKI docker-compose files
SERVICE_NAME = os.getenv("SERVICE_NAME", os.getenv("HOSTNAME", "pvarki"))
SERVICE_VERSION = os.getenv("RELEASE_TAG", os.getenv("SERVICE_VERSION", "unknown"))


def audit_log(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches
    category: str,
    action: str,
    outcome: str = "success",
    # Initiator overrides (normally from context)
    initiator_user: Optional[str] = None,
    initiator_role: Optional[str] = None,
    initiator_ip: Optional[str] = None,
    initiator_cert_serial: Optional[str] = None,
    # Target fields
    target_user: Optional[str] = None,
    target_resource: Optional[str] = None,
    target_resource_type: Optional[str] = None,
    # Error information
    error_message: Optional[str] = None,
    error_code: Optional[str] = None,
    # Additional fields
    **extra_fields: Any,
) -> Dict[str, Any]:
    """
    Build an ECS-compliant extra dict for audit logging.

    Automatically injects initiator context from AuditMiddleware.
    Use with ``LOGGER.audit("message", extra=audit_log(...))``.

    Args:
        category: Event category per ECS. Common values:

            - ``authentication``: Login, logout, token exchange
            - ``authorization``: Permission checks
            - ``iam``: Identity management, cert issuance
            - ``configuration``: Settings changes
            - ``session``: Session lifecycle
            - ``network``: Connection events
            - ``intrusion_detection``: Security anomalies

        action: Specific action identifier. Examples:

            - ``otp_exchange``, ``jwt_validate``, ``mtls_auth``
            - ``cert_issue``, ``cert_revoke``, ``user_enroll``
            - ``config_update``, ``permission_grant``

        outcome: Result of the action:

            - ``success``: Action completed successfully
            - ``failure``: Action failed
            - ``unknown``: Outcome not determined

        initiator_user: Override context initiator user.
        initiator_role: Override context initiator role.
        initiator_ip: Override context initiator IP.
        initiator_cert_serial: Override context cert serial.
        target_user: User affected by the action.
        target_resource: Resource identifier (cert serial, endpoint, etc.).
        target_resource_type: Type of resource (certificate, user, endpoint).
        error_message: Human-readable error description for failures.
        error_code: Machine-readable error code for failures.
        **extra_fields: Additional fields added under ``pvarki.*`` namespace.

    Returns:
        Dict suitable for logging extra parameter.

    Example::

        LOGGER.audit(
            "OTP exchange successful",
            extra=audit_log(
                category="authentication",
                action="otp_exchange",
                outcome="success",
                target_user="NORPPA11",
            )
        )
    """
    ctx = get_audit_context()

    # Build ECS-compliant extra dict
    result: Dict[str, Any] = {
        # Event classification (ECS)
        "event.category": category,
        "event.action": action,
        "event.outcome": outcome,
        # Service identification
        "service.name": SERVICE_NAME,
        "service.version": SERVICE_VERSION,
        # Correlation
        "trace.id": ctx.trace_id,
    }

    # Initiator fields (explicit params override context)
    _initiator_user = initiator_user or ctx.initiator_user
    _initiator_role = initiator_role or ctx.initiator_role
    _initiator_ip = initiator_ip or ctx.initiator_ip
    _initiator_cert_serial = initiator_cert_serial or ctx.initiator_cert_serial

    if _initiator_ip:
        result["source.ip"] = _initiator_ip
    if _initiator_user:
        result["source.user.name"] = _initiator_user
    if _initiator_role:
        result["source.user.roles"] = [_initiator_role]
    if _initiator_cert_serial:
        result["tls.client.x509.serial_number"] = _initiator_cert_serial
    if ctx.initiator_cert_cn:
        result["tls.client.x509.subject.common_name"] = ctx.initiator_cert_cn
    if ctx.initiator_session:
        result["session.id"] = ctx.initiator_session

    # Target fields (ECS user.target.* for affected user)
    if target_user:
        result["user.target.name"] = target_user
    if target_resource:
        result["pvarki.target.resource"] = target_resource
    if target_resource_type:
        result["pvarki.target.resource_type"] = target_resource_type

    # Error information (ECS error.*)
    if error_message:
        result["error.message"] = error_message
    if error_code:
        result["error.code"] = error_code

    # Additional fields under pvarki.* namespace
    for key, value in extra_fields.items():
        if value is not None:
            result[f"pvarki.{key}"] = value

    return result


def audit_extra(**fields: Any) -> Dict[str, Any]:
    """
    Simple wrapper to add trace context to any log call.

    For non-audit logs that still need trace correlation.
    Less structured than audit_log(), just adds trace.id and extra fields.

    Args:
        **fields: Fields to include in the extra dict.

    Returns:
        Dict with trace.id and provided fields.

    Example::

        LOGGER.info("Processing request", extra=audit_extra(
            endpoint="/api/v1/users",
            method="POST",
        ))
    """
    ctx = get_audit_context()
    result: Dict[str, Any] = {
        "trace.id": ctx.trace_id,
        "service.name": SERVICE_NAME,
    }
    result.update(fields)
    return result


# =============================================================================
# Convenience wrappers for common event categories
# =============================================================================


def audit_authentication(
    action: str,
    outcome: str = "success",
    target_user: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for authentication events."""
    return audit_log(
        category="authentication",
        action=action,
        outcome=outcome,
        target_user=target_user,
        **kwargs,
    )


def audit_iam(
    action: str,
    outcome: str = "success",
    target_user: Optional[str] = None,
    target_resource: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for identity/access management events."""
    return audit_log(
        category="iam",
        action=action,
        outcome=outcome,
        target_user=target_user,
        target_resource=target_resource,
        **kwargs,
    )


def audit_authorization(
    action: str,
    outcome: str = "success",
    target_user: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for authorization events."""
    return audit_log(
        category="authorization",
        action=action,
        outcome=outcome,
        target_user=target_user,
        **kwargs,
    )


def audit_configuration(
    action: str,
    outcome: str = "success",
    target_resource: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for configuration change events."""
    return audit_log(
        category="configuration",
        action=action,
        outcome=outcome,
        target_resource=target_resource,
        **kwargs,
    )


def audit_session(
    action: str,
    outcome: str = "success",
    target_user: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for session lifecycle events."""
    return audit_log(
        category="session",
        action=action,
        outcome=outcome,
        target_user=target_user,
        **kwargs,
    )


def audit_anomaly(
    action: str,
    error_message: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build audit log extra for security anomalies (always failure)."""
    return audit_log(
        category="intrusion_detection",
        action=action,
        outcome="failure",
        error_message=error_message,
        **kwargs,
    )
