"""Test the middleware"""
from typing import Generator
import logging

import pytest
from fastapi.testclient import TestClient

from .app import APP

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.fixture
def mtlsclient() -> Generator[TestClient, None, None]:
    """Fake the Nginx header"""
    client = TestClient(
        APP,
        headers={
            "X-ClientCert-DN": "CN=harjoitus1.pvarki.fi,O=harjoitus1.pvarki.fi,L=KeskiSuomi,ST=Jyvaskyla,C=FI",
        },
    )
    yield client


def test_hello() -> None:
    """Check the hello endpoint"""
    client = TestClient(APP)
    resp = client.get("/api/v1")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["message"] == "Hello World"


def test_unauth() -> None:
    """Check that unauth call to auth endpoint fails"""
    client = TestClient(APP)
    resp = client.get("/api/v1/check_auth")
    assert resp.status_code == 403


def test_auth(mtlsclient: TestClient) -> None:
    """Test that the fake header works"""
    resp = mtlsclient.get("/api/v1/check_auth")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"]
    assert "cert" in payload
    assert "CN" in payload["cert"]
    assert payload["cert"]["CN"] == "harjoitus1.pvarki.fi"
