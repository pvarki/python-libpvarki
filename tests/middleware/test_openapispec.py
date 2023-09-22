"""Test that we can generate the openapi spec"""
from typing import Dict, Any
import logging

from fastapi.testclient import TestClient

from .app import APP

LOGGER = logging.getLogger(__name__)


def check_schema(payload: Dict[str, Any]) -> None:
    """Check the payload"""
    # TODO: Add expected schemas etc
    assert payload


def test_rest() -> None:
    """Check openapi.json endpoint"""
    client = TestClient(APP)
    resp = client.get("/middleware/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    check_schema(schema)


def test_openapi_docs() -> None:
    """Check that we can fetch the dcos"""
    client = TestClient(APP)
    resp = client.get("/middleware/docs")
    assert resp.status_code == 200


def test_python() -> None:
    """Check that we can get the schema via python API"""
    schema = APP.openapi()
    check_schema(schema)
