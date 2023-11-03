"""Test product schemas"""
from libpvarki.schemas.product import UserInstructionFragment, UserCRUDRequest, ProductHealthCheckResponse


def test_fragment() -> None:
    """Test constructing UserInstructionFragment"""
    res = UserInstructionFragment(html="<p>Hello world!</p>")
    assert res.dict()["html"]


def test_crud() -> None:
    """Test constructing UserCRUDRequest"""
    res = UserCRUDRequest(callsign="KISSA23a", uuid="not really an uuid", x509cert="not really a cert")
    assert res.dict()["callsign"] == "KISSA23a"


def test_health() -> None:
    """Test constructing ProductHealthCheckResponse"""
    res = ProductHealthCheckResponse(healthy=True)
    assert res.dict()["healthy"] is True
