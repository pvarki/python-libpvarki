"""test generic schemas"""
from libpvarki.schemas.generic import OperationResultResponse


def test_result() -> None:
    """Test constructing OperationResultResponse"""
    res = OperationResultResponse(success=True)
    assert res.model_dump()["success"]
