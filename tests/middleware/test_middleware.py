"""Test the middleware"""

from typing import Dict, Optional

import pytest
from fastapi.testclient import TestClient

from .app import APP

TRUSTED_INGRESS = "traefik.traefik-system.serviceaccount.identity.linkerd.cluster.local"
LATERAL_SERVICE = "tak.app-tak.serviceaccount.identity.linkerd.cluster.local"
USER_CERT_DN = "CN=harjoitus1.pvarki.fi,O=harjoitus1.pvarki.fi,L=KeskiSuomi,ST=Jyvaskyla,C=FI"
USER_CN = "harjoitus1.pvarki.fi"
SPOOF_DN = "CN=admin,O=admin,C=FI"

# l5d trusted (Traefik registered as an ingress); STRICT additionally requires an l5d header.
L5D = {"MTLS_TRUST_L5D": "true", "MTLS_TRUSTED_INGRESS_IDENTITIES": TRUSTED_INGRESS}
STRICT = {**L5D, "MTLS_REQUIRE_L5D": "true"}
MTLS_ENV_VARS = ("MTLS_TRUST_L5D", "MTLS_REQUIRE_L5D", "MTLS_TRUSTED_INGRESS_IDENTITIES")


def test_hello() -> None:
    """Unauthenticated endpoint is reachable."""
    resp = TestClient(APP).get("/api/v1")
    assert resp.status_code == 200
    assert resp.json()["message"] == "Hello World"


@pytest.mark.parametrize(
    "env, headers, status, cn",
    [
        pytest.param({}, {}, 403, None, id="legacy-noauth"),
        pytest.param({}, {"X-ClientCert-DN": USER_CERT_DN}, 200, USER_CN, id="legacy-cert"),
        pytest.param(L5D, {"l5d-client-id": LATERAL_SERVICE}, 200, LATERAL_SERVICE, id="lateral-service"),
        pytest.param(
            L5D,
            {"l5d-client-id": TRUSTED_INGRESS, "X-ClientCert-DN": USER_CERT_DN},
            200,
            USER_CN,
            id="ingress-cert",
        ),
        pytest.param(L5D, {"l5d-client-id": TRUSTED_INGRESS}, 403, None, id="ingress-nocert"),
        pytest.param(
            L5D,
            {"l5d-client-id": LATERAL_SERVICE, "X-ClientCert-DN": SPOOF_DN},
            200,
            LATERAL_SERVICE,
            id="spoofed-cert-ignored",
        ),
        pytest.param(L5D, {"X-ClientCert-DN": USER_CERT_DN}, 200, USER_CN, id="migration-unmeshed-cert"),
        pytest.param(
            {"MTLS_TRUST_L5D": "false"},
            {"l5d-client-id": LATERAL_SERVICE, "X-ClientCert-DN": USER_CERT_DN},
            200,
            USER_CN,
            id="l5d-disabled-uses-cert",
        ),
        pytest.param(
            STRICT,
            {"l5d-client-id": TRUSTED_INGRESS, "X-ClientCert-DN": USER_CERT_DN},
            200,
            USER_CN,
            id="strict-ingress-cert",
        ),
        pytest.param(STRICT, {"X-ClientCert-DN": SPOOF_DN}, 403, None, id="strict-no-l5d-fails"),
    ],
)
def test_mtls_identity(
    monkeypatch: pytest.MonkeyPatch,
    env: Dict[str, str],
    headers: Dict[str, str],
    status: int,
    cn: Optional[str],
) -> None:
    """Resolve the authenticated identity across auth modes: cert header, l5d service, ingress, strict."""
    for var in MTLS_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    resp = TestClient(APP, headers=headers).get("/api/v1/check_auth")

    assert resp.status_code == status
    if cn is not None:
        assert resp.json()["cert"]["CN"] == cn
