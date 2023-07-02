"""Test product schema endpoints"""
from typing import Dict
import uuid

import pytest
from fastapi.testclient import TestClient

from .test_middleware import mtlsclient  # pylint: disable=W0611


# pylint: disable=W0621


def create_user_dict(callsign: str) -> Dict[str, str]:
    """return valid user dict for crud operations"""
    return {"uuid": str(uuid.uuid4()), "callsign": callsign, "x509cert": "FIXME: insert dummy cert in CFSSL encoding"}


@pytest.fixture(scope="session")
def norppa11() -> Dict[str, str]:
    """Session scoped user dict (to keep same UUID)"""
    return create_user_dict("NORPPA11a")


def test_get_fragment(norppa11: Dict[str, str], mtlsclient: TestClient) -> None:
    """Check that getting fragment works"""
    resp = mtlsclient.post("/api/product/clients/fragment", json=norppa11)
    assert resp.status_code == 200
    payload = resp.json()
    assert "html" in payload
    assert payload["html"] == "<p>Hello NORPPA11a!</p>"


def test_create(norppa11: Dict[str, str], mtlsclient: TestClient) -> None:
    """Check that adding user works"""
    resp = mtlsclient.post("/api/product/user/created", json=norppa11)
    assert resp.status_code == 200
    payload = resp.json()
    assert "success" in payload
    assert payload["success"]
