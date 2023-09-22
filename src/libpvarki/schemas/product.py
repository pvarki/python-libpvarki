"""Pydantic schemas for product integration APIs"""
from typing import Optional

from pydantic import Field
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive

# pylint: disable=too-few-public-methods
from .generic import OperationResultResponse  # pylint: disable=W0611 # For backwards compatibility


class UserCRUDRequest(BaseModel, extra="forbid"):
    """Request to create user"""

    uuid: str = Field(description="RASENMAEHER UUID for this user")
    callsign: str = Field(description="Callsign of the user")
    x509cert: str = Field(description="Certificate encoded with CFSSL conventions (newlines escaped)")


class UserInstructionFragment(BaseModel, extra="forbid"):
    """Product instructions for user"""

    html: str = Field(description="The HTML content will be shown for this products instructions")
    inject_css: Optional[str] = Field(
        description="If extra stylesheet is needed, set the fully qualified URI",
        default=None,
        json_schema_extra={"nullable": True},
    )


class ReadyRequest(BaseModel):  # pylint: disable=too-few-public-methods
    """Indicate product API readiness"""

    product: str = Field(description="Product name")
    apiurl: str = Field(description="Product API URL")
    url: str = Field(description="Product UI URL")
