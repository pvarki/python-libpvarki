"""
Request context management using ContextVars.

ContextVars provide task-local storage that works correctly with asyncio.
Each concurrent request gets its own isolated context automatically.

Usage:
    The AuditMiddleware sets context at request start.
    The audit_log() helper reads it when logging.
    Context is cleared at request end to prevent leakage.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import uuid


@dataclass
class AuditContext:  # pylint: disable=too-many-instance-attributes
    """
    Container for request-scoped audit context.

    Holds initiator information extracted from incoming requests,
    either from nginx headers (direct mTLS) or propagation headers
    (service-to-service calls).

    Attributes:
        trace_id: Correlation ID for the entire request chain.
        initiator_ip: Source IP address of the original requester.
        initiator_user: Username/callsign of the initiator.
        initiator_role: Role of the initiator (admin, user, etc.).
        initiator_cert_serial: mTLS certificate serial number.
        initiator_cert_cn: mTLS certificate Common Name.
        initiator_session: Session ID if applicable.
        is_propagated: True if context came from upstream service headers.
    """

    # Correlation ID for request chain tracing
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Initiator information (who caused this action)
    initiator_ip: str = ""
    initiator_user: str = ""
    initiator_role: str = ""
    initiator_cert_serial: str = ""
    initiator_cert_cn: str = ""
    initiator_session: str = ""

    # Metadata
    is_propagated: bool = False

    def to_ecs_fields(self) -> Dict[str, Any]:
        """
        Convert context to ECS-compliant field dictionary.

        Returns:
            Dict with ECS field names. Empty values are excluded.
        """
        result: Dict[str, Any] = {
            "trace.id": self.trace_id,
        }

        if self.initiator_ip:
            result["source.ip"] = self.initiator_ip
        if self.initiator_user:
            result["source.user.name"] = self.initiator_user
        if self.initiator_role:
            result["source.user.roles"] = [self.initiator_role]
        if self.initiator_cert_serial:
            result["tls.client.x509.serial_number"] = self.initiator_cert_serial
        if self.initiator_cert_cn:
            result["tls.client.x509.subject.common_name"] = self.initiator_cert_cn
        if self.initiator_session:
            result["session.id"] = self.initiator_session

        return result


# Module-level ContextVar instance
# Each async task automatically gets isolated storage
_audit_context: ContextVar[AuditContext] = ContextVar("audit_context", default=AuditContext())


def get_audit_context() -> AuditContext:
    """
    Get the current request's audit context.

    Safe to call from anywhere. Returns empty context if called
    outside of a request scope (e.g., during startup).

    Returns:
        Current AuditContext for this async task.
    """
    return _audit_context.get()


# pylint: disable=too-many-arguments
def set_audit_context(
    trace_id: Optional[str] = None,
    initiator_ip: Optional[str] = None,
    initiator_user: Optional[str] = None,
    initiator_role: Optional[str] = None,
    initiator_cert_serial: Optional[str] = None,
    initiator_cert_cn: Optional[str] = None,
    initiator_session: Optional[str] = None,
    is_propagated: Optional[bool] = None,
) -> AuditContext:  # pylint: disable=too-many-arguments
    """
    Set or update the audit context for the current request.

    Only provided (non-None) fields are updated. Other fields retain
    their current values. This allows incremental updates, e.g.,
    setting user info after JWT validation.

    Typically called by:
    - AuditMiddleware at request start
    - Auth dependencies after JWT validation
    - Service code when additional context is available

    Args:
        trace_id: Correlation ID (from X-Request-ID or generated).
        initiator_ip: Source IP address.
        initiator_user: Username/callsign.
        initiator_role: User role (admin, user, service, etc.).
        initiator_cert_serial: mTLS certificate serial number.
        initiator_cert_cn: mTLS certificate Common Name.
        initiator_session: Session identifier.
        is_propagated: True if context came from upstream service.

    Returns:
        The updated AuditContext.
    """
    current = _audit_context.get()

    new_context = AuditContext(
        trace_id=trace_id if trace_id is not None else current.trace_id,
        initiator_ip=initiator_ip if initiator_ip is not None else current.initiator_ip,
        initiator_user=initiator_user if initiator_user is not None else current.initiator_user,
        initiator_role=initiator_role if initiator_role is not None else current.initiator_role,
        initiator_cert_serial=(
            initiator_cert_serial if initiator_cert_serial is not None else current.initiator_cert_serial
        ),
        initiator_cert_cn=initiator_cert_cn if initiator_cert_cn is not None else current.initiator_cert_cn,
        initiator_session=initiator_session if initiator_session is not None else current.initiator_session,
        is_propagated=is_propagated if is_propagated is not None else current.is_propagated,
    )

    _audit_context.set(new_context)
    return new_context


def clear_audit_context() -> None:
    """
    Reset context to empty defaults.

    Must be called at request end to prevent context leakage between
    requests. The AuditMiddleware handles this automatically in its
    finally block.
    """
    _audit_context.set(AuditContext())
