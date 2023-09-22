"""Generic schemas"""
from typing import Optional

from pydantic import Field, Extra
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive


class OperationResultResponse(BaseModel):  # pylint: disable=too-few-public-methods
    """Communicate result of operation"""

    success: bool = Field(description="Was the operation a success, used in addition to http status code")
    extra: Optional[str] = Field(description="Extra information", default=None, json_schema_extra={"nullable": True})
    error: Optional[str] = Field(
        description="Error message if any",
        default=None,
        json_schema_extra={"nullable": True},
    )

    class Config:  # pylint: disable=too-few-public-methods
        """Example values for schema"""

        extra = Extra.forbid
        schema_extra = {
            "examples": [
                {"success": True},
                {"success": False, "error": "Things went wrong"},
                {"success": True, "extra": "Tell the user they're awesome"},
            ]
        }
