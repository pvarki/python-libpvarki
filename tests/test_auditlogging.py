"""
Tests for libpvarki.auditlogging module.

Run with: pytest tests/test_auditlogging.py -v

These tests are designed to work within the libpvarki test infrastructure.
"""
# pylint: disable=redefined-outer-name

import logging
from typing import Generator, Dict, Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from libpvarki.auditlogging import (
    AUDIT,
    AuditMiddleware,
    audit_log,
    audit_authentication,
    audit_iam,
    get_audit_context,
    set_audit_context,
    clear_audit_context,
    get_propagation_headers,
    inject_audit_context,
    update_audit_user,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_context() -> Generator[None, None, None]:
    """Clear audit context before and after each test."""
    clear_audit_context()
    yield
    clear_audit_context()


@pytest.fixture
def app() -> FastAPI:
    """Create a test FastAPI app with AuditMiddleware."""
    app = FastAPI()
    app.add_middleware(AuditMiddleware)

    @app.get("/test")
    async def test_endpoint() -> Dict[str, Any]:
        ctx = get_audit_context()
        return {
            "trace_id": ctx.trace_id,
            "initiator_user": ctx.initiator_user,
            "initiator_ip": ctx.initiator_ip,
            "is_propagated": ctx.is_propagated,
        }

    @app.post("/enroll")
    async def enroll_endpoint() -> Dict[str, str]:
        ctx = get_audit_context()
        return {"enrolled": ctx.initiator_user}

    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Test client for the app."""
    return TestClient(app)


# =============================================================================
# AUDIT Level Tests
# =============================================================================


class TestAuditLevel:
    """Tests for AUDIT log level setup."""

    def test_audit_level_constant(self) -> None:
        """AUDIT level should be CRITICAL + 5 (55)."""
        assert AUDIT == logging.CRITICAL + 5

    def test_audit_level_registered(self) -> None:
        """AUDIT level should be registered with logging module."""
        assert hasattr(logging, "AUDIT")
        audit_val = getattr(logging, "AUDIT")
        assert isinstance(audit_val, int)
        assert audit_val == AUDIT

    def test_logger_has_audit_method(self) -> None:
        """Logger instances should have audit() method."""
        logger = logging.getLogger("test.audit_level")
        assert hasattr(logger, "audit")
        assert callable(logger.audit)

    def test_audit_level_name(self) -> None:
        """AUDIT level should have correct name."""
        assert logging.getLevelName(25) == "AUDIT"
        assert logging.getLevelName("AUDIT") == 25


# =============================================================================
# Context Tests
# =============================================================================


class TestAuditContext:
    """Tests for ContextVar-based audit context."""

    def test_default_context(self) -> None:
        """Default context should have generated trace_id."""
        ctx = get_audit_context()
        assert ctx.trace_id  # Should be non-empty UUID
        assert ctx.initiator_user == ""
        assert ctx.initiator_ip == ""
        assert ctx.is_propagated is False

    def test_set_context(self) -> None:
        """set_audit_context should update fields."""
        set_audit_context(
            trace_id="test-trace-123",
            initiator_user="NORPPA11",
            initiator_ip="192.168.1.100",
        )
        ctx = get_audit_context()
        assert ctx.trace_id == "test-trace-123"
        assert ctx.initiator_user == "NORPPA11"
        assert ctx.initiator_ip == "192.168.1.100"

    def test_partial_update(self) -> None:
        """set_audit_context should only update provided fields."""
        set_audit_context(initiator_user="KOTKA1")
        set_audit_context(initiator_role="admin")

        ctx = get_audit_context()
        assert ctx.initiator_user == "KOTKA1"
        assert ctx.initiator_role == "admin"

    def test_clear_context(self) -> None:
        """clear_audit_context should reset to defaults."""
        set_audit_context(initiator_user="NORPPA11")
        clear_audit_context()

        ctx = get_audit_context()
        assert ctx.initiator_user == ""

    def test_to_ecs_fields(self) -> None:
        """Context should convert to ECS field dict."""
        set_audit_context(
            trace_id="abc-123",
            initiator_user="NORPPA11",
            initiator_ip="10.0.0.1",
            initiator_role="operator",
            initiator_cert_serial="DEADBEEF",
        )
        ctx = get_audit_context()
        fields = ctx.to_ecs_fields()

        assert fields["trace.id"] == "abc-123"
        assert fields["source.user.name"] == "NORPPA11"
        assert fields["source.ip"] == "10.0.0.1"
        assert fields["source.user.roles"] == ["operator"]
        assert fields["tls.client.x509.serial_number"] == "DEADBEEF"


# =============================================================================
# Middleware Tests
# =============================================================================


class TestAuditMiddleware:
    """Tests for FastAPI middleware."""

    def test_extracts_request_id(self, client: TestClient) -> None:
        """Middleware should extract X-Request-ID."""
        response = client.get("/test", headers={"X-Request-ID": "my-trace-id"})
        assert response.status_code == 200
        assert response.json()["trace_id"] == "my-trace-id"

    def test_generates_request_id(self, client: TestClient) -> None:
        """Middleware should generate trace ID if not provided."""
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json()["trace_id"]  # Non-empty

    def test_returns_request_id_header(self, client: TestClient) -> None:
        """Response should include X-Request-ID header."""
        response = client.get("/test", headers={"X-Request-ID": "echo-me"})
        assert response.headers["X-Request-ID"] == "echo-me"

    def test_extracts_real_ip(self, client: TestClient) -> None:
        """Middleware should extract X-Real-IP."""
        response = client.get("/test", headers={"X-Real-IP": "203.0.113.50"})
        assert response.json()["initiator_ip"] == "203.0.113.50"

    def test_extracts_forwarded_for(self, client: TestClient) -> None:
        """Middleware should extract X-Forwarded-For if no X-Real-IP."""
        response = client.get("/test", headers={"X-Forwarded-For": "203.0.113.50, 10.0.0.1"})
        assert response.json()["initiator_ip"] == "203.0.113.50"

    def test_extracts_cert_dn(self, client: TestClient) -> None:
        """Middleware should extract CN from X-ClientCert-DN."""
        response = client.get(
            "/test",
            headers={"X-ClientCert-DN": "CN=NORPPA11,O=PVARKI,C=FI"},
        )
        assert response.json()["initiator_user"] == "NORPPA11"

    def test_propagated_headers(self, client: TestClient) -> None:
        """Middleware should extract X-Initiator-* headers."""
        response = client.get(
            "/test",
            headers={
                "X-Initiator-User": "KOTKA1",
                "X-Initiator-IP": "192.168.1.50",
            },
        )
        data = response.json()
        assert data["initiator_user"] == "KOTKA1"
        assert data["initiator_ip"] == "192.168.1.50"
        assert data["is_propagated"] is True

    def test_direct_mtls_takes_precedence(self, client: TestClient) -> None:
        """Direct mTLS cert should override propagated headers."""
        response = client.get(
            "/test",
            headers={
                "X-ClientCert-DN": "CN=DIRECT_USER,O=TEST",
                "X-Initiator-User": "PROPAGATED_USER",
            },
        )
        # Direct mTLS wins
        assert response.json()["initiator_user"] == "DIRECT_USER"
        assert response.json()["is_propagated"] is False


# =============================================================================
# Helper Tests
# =============================================================================


class TestAuditLogHelper:
    """Tests for audit_log() helper function."""

    def test_basic_audit_log(self) -> None:
        """audit_log should create ECS-compliant dict."""
        set_audit_context(trace_id="test-123")

        extra = audit_log(
            category="authentication",
            action="otp_exchange",
            outcome="success",
        )

        assert extra["event.category"] == "authentication"
        assert extra["event.action"] == "otp_exchange"
        assert extra["event.outcome"] == "success"
        assert extra["trace.id"] == "test-123"
        assert "service.name" in extra

    def test_audit_log_with_target(self) -> None:
        """audit_log should include target fields."""
        extra = audit_log(
            category="iam",
            action="cert_issue",
            outcome="success",
            target_user="NORPPA11",
            target_resource="DEADBEEF",
            target_resource_type="certificate",
        )

        assert extra["user.target.name"] == "NORPPA11"
        assert extra["pvarki.target.resource"] == "DEADBEEF"
        assert extra["pvarki.target.resource_type"] == "certificate"

    def test_audit_log_with_error(self) -> None:
        """audit_log should include error fields."""
        extra = audit_log(
            category="authentication",
            action="jwt_validate",
            outcome="failure",
            error_message="Token expired",
            error_code="TOKEN_EXPIRED",
        )

        assert extra["event.outcome"] == "failure"
        assert extra["error.message"] == "Token expired"
        assert extra["error.code"] == "TOKEN_EXPIRED"

    def test_audit_log_uses_context(self) -> None:
        """audit_log should include context initiator."""
        set_audit_context(
            initiator_user="CONTEXT_USER",
            initiator_ip="10.0.0.1",
        )

        extra = audit_log(category="test", action="test")

        assert extra["source.user.name"] == "CONTEXT_USER"
        assert extra["source.ip"] == "10.0.0.1"

    def test_audit_log_override_context(self) -> None:
        """Explicit params should override context."""
        set_audit_context(initiator_user="CONTEXT_USER")

        extra = audit_log(
            category="test",
            action="test",
            initiator_user="OVERRIDE_USER",
        )

        assert extra["source.user.name"] == "OVERRIDE_USER"

    def test_audit_log_extra_fields(self) -> None:
        """Extra fields should go under pvarki namespace."""
        extra = audit_log(
            category="test",
            action="test",
            custom_field="custom_value",
            another_field=123,
        )

        assert extra["pvarki.custom_field"] == "custom_value"
        assert extra["pvarki.another_field"] == 123

    def test_convenience_wrappers(self) -> None:
        """Category convenience functions should work."""
        auth = audit_authentication("login", outcome="success")
        assert auth["event.category"] == "authentication"

        iam = audit_iam("cert_issue", target_user="NORPPA11")
        assert iam["event.category"] == "iam"
        assert iam["user.target.name"] == "NORPPA11"


# =============================================================================
# Propagation Tests
# =============================================================================


class TestPropagation:
    """Tests for service-to-service propagation."""

    def test_get_propagation_headers(self) -> None:
        """get_propagation_headers should return context as headers."""
        set_audit_context(
            trace_id="prop-trace-123",
            initiator_user="NORPPA11",
            initiator_ip="192.168.1.100",
            initiator_role="admin",
            initiator_cert_serial="DEADBEEF",
        )

        headers = get_propagation_headers()

        assert headers["X-Request-ID"] == "prop-trace-123"
        assert headers["X-Initiator-User"] == "NORPPA11"
        assert headers["X-Initiator-IP"] == "192.168.1.100"
        assert headers["X-Initiator-Role"] == "admin"
        assert headers["X-Initiator-Cert-Serial"] == "DEADBEEF"

    def test_propagation_empty_context(self) -> None:
        """Propagation headers should exclude empty values."""
        clear_audit_context()

        headers = get_propagation_headers()

        assert "X-Request-ID" in headers
        assert "X-Initiator-User" not in headers
        assert "X-Initiator-IP" not in headers

    def test_inject_audit_context(self) -> None:
        """inject_audit_context should merge with existing headers."""
        set_audit_context(trace_id="inject-test")

        existing = {"Content-Type": "application/json"}
        result = inject_audit_context(existing)

        assert result["Content-Type"] == "application/json"
        assert result["X-Request-ID"] == "inject-test"

    def test_inject_no_overwrite(self) -> None:
        """inject_audit_context should not overwrite existing headers."""
        set_audit_context(trace_id="new-value")

        existing = {"X-Request-ID": "existing-value"}
        result = inject_audit_context(existing)

        assert result["X-Request-ID"] == "existing-value"


# =============================================================================
# Update User Tests
# =============================================================================


class TestUpdateAuditUser:
    """Tests for update_audit_user helper."""

    def test_update_user(self) -> None:
        """update_audit_user should update context."""
        update_audit_user(user="NORPPA11", role="operator")

        ctx = get_audit_context()
        assert ctx.initiator_user == "NORPPA11"
        assert ctx.initiator_role == "operator"

    def test_update_preserves_other_fields(self) -> None:
        """update_audit_user should preserve other context fields."""
        set_audit_context(trace_id="keep-me", initiator_ip="10.0.0.1")
        update_audit_user(user="NORPPA11")

        ctx = get_audit_context()
        assert ctx.trace_id == "keep-me"
        assert ctx.initiator_ip == "10.0.0.1"
        assert ctx.initiator_user == "NORPPA11"


# =============================================================================
# Integration Test
# =============================================================================


class TestIntegration:
    """Integration test simulating real usage."""

    def test_full_flow(self, client: TestClient) -> None:
        """Test complete audit logging flow."""
        # Simulate mTLS request through nginx
        response = client.post(
            "/enroll",
            headers={
                "X-Request-ID": "integration-test-123",
                "X-ClientCert-DN": "CN=NORPPA11,O=PVARKI,C=FI",
                "X-ClientCert-Serial": "DEADBEEF",
                "X-Real-IP": "203.0.113.50",
            },
        )

        assert response.status_code == 200
        assert response.json()["enrolled"] == "NORPPA11"
        assert response.headers["X-Request-ID"] == "integration-test-123"

    def test_service_chain(self, client: TestClient) -> None:
        """Test context propagation through service chain."""
        # First service receives from nginx
        response1 = client.get(
            "/test",
            headers={
                "X-Request-ID": "chain-trace-456",
                "X-ClientCert-DN": "CN=ORIGINAL_USER,O=TEST",
            },
        )
        assert response1.json()["initiator_user"] == "ORIGINAL_USER"

        # Second service receives propagated context
        response2 = client.get(
            "/test",
            headers={
                "X-Request-ID": "chain-trace-456",
                "X-Initiator-User": "ORIGINAL_USER",
                "X-Initiator-IP": "10.0.0.1",
            },
        )
        assert response2.json()["initiator_user"] == "ORIGINAL_USER"
        assert response2.json()["is_propagated"] is True


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
