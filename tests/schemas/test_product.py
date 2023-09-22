"""Test product schemas"""
from libpvarki.schemas.product import UserInstructionFragment, UserCRUDRequest


def test_fragment() -> None:
    """Test constructing UserInstructionFragment"""
    res = UserInstructionFragment(html="<p>Hello world!</p>")
    assert res.model_dump()["html"]


def test_crud() -> None:
    """Test constructing UserCRUDRequest"""
    res = UserCRUDRequest(callsign="KISSA23a", uuid="not really an uuid", x509cert="not really a cert")
    assert res.model_dump()["callsign"] == "KISSA23a"
