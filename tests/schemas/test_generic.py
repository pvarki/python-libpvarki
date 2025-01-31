"""test generic schemas"""
import pytest
from pydantic import ValidationError
from libpvarki.schemas.generic import OperationResultResponse


def test_result() -> None:
    """Test constructing OperationResultResponse"""
    res = OperationResultResponse(success=True)
    assert res.model_dump()["success"]


def test_result_extra() -> None:
    """Test that extra field forbid works"""
    with pytest.raises(ValidationError):
        OperationResultResponse(success=True, nosuchfield="Trololooo")  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        OperationResultResponse.model_validate({"success": True, "nosuchfield": "Trololooo"})
