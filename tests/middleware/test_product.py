"""Test product schema endpoints"""
from typing import Dict
import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from libpvarki.schemas.product import UserCRUDRequest, OperationResultResponse, UserInstructionFragment
from .test_middleware import mtlsclient  # pylint: disable=W0611


# pylint: disable=W0621


def create_user_dict(callsign: str) -> Dict[str, str]:
    """return valid user dict for crud operations"""
    return {"uuid": str(uuid.uuid4()), "callsign": callsign, "x509cert": "FIXME: insert dummy cert in CFSSL encoding"}


def test_operresult_validationfail() -> None:
    """Test that OperationResultResponse can be encoded and decoded"""
    with pytest.raises(ValidationError):
        _pcresp = OperationResultResponse.parse_obj(
            {
                "success": "dummy",
                "error": False,
            }
        )


def test_usercrud_encdec() -> None:
    """Test that UserCRUDRequest can be encoded and decoded"""
    pdcrud = UserCRUDRequest.parse_obj(create_user_dict("KETTU11b"))
    encoded = pdcrud.json()
    decoded = UserCRUDRequest.parse_raw(encoded)
    assert decoded.uuid == pdcrud.uuid


def test_operresult_encdec() -> None:
    """Test that OperationResultResponse can be encoded and decoded"""
    pcresp = OperationResultResponse.parse_obj(
        {
            "success": False,
            "error": "Dummy",
        }
    )
    encoded = pcresp.json()
    decoded = OperationResultResponse.parse_raw(encoded)
    assert decoded.error == pcresp.error


def test_instruction_encdec() -> None:
    """Test that UserInstructionFragment can be encoded and decoded"""
    pdinstr = UserInstructionFragment.parse_obj(
        {
            "html": "<p>Hello world!</p>",
        }
    )
    encoded = pdinstr.json()
    decoded = UserInstructionFragment.parse_raw(encoded)
    assert decoded.html == pdinstr.html


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


def test_openapijson(mtlsclient: TestClient) -> None:
    """Check that we can fetch the JSON"""
    resp = mtlsclient.get("/middleware/openapi.json")
    assert resp.status_code == 200


def test_openapi_docs(mtlsclient: TestClient) -> None:
    """Check that we can fetch the dcos"""
    resp = mtlsclient.get("/middleware/docs")
    assert resp.status_code == 200
