"""Pydantic schemas for product integration APIs"""
from typing import Optional

from pydantic import Field
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive

# pylint: disable=too-few-public-methods


class OperationResultResponse(BaseModel, extra="forbid"):
    """Communicate result of operation"""

    success: bool = Field(description="Was the operation a success, used in addition to http status code")
    extra: Optional[str] = Field(description="Extra information", default=None, nullable=True)
    error: Optional[str] = Field(description="Error message if any", default=None, nullable=True)


class UserCRUDRequest(BaseModel, extra="forbid"):
    """Request to create user"""

    uuid: str = Field(description="RASENMAEHER UUID for this user")
    callsign: str = Field(description="Callsign of the user")
    x509cert: str = Field(description="Certificate encoded with CFSSL conventions (newlines escaped)")


class UserInstructionFragment(BaseModel, extra="forbid"):
    """Product instructions for user"""

    html: str = Field(description="The HTML content will be shown for this products instructions")
    inject_css: Optional[str] = Field(
        description="If extra stylesheet is needed, set the fully qualified URI", default=None, nullable=True
    )
