"""Pydantic schemas for product integration APIs"""
from typing import Optional

from pydantic import Field, Extra
from pydantic.main import BaseModel  # pylint: disable=E0611 # false positive

# pylint: disable=too-few-public-methods
from .generic import OperationResultResponse  # pylint: disable=W0611 # For backwards compatibility


class UserCRUDRequest(BaseModel):
    """Request to create user"""

    uuid: str = Field(description="RASENMAEHER UUID for this user")
    callsign: str = Field(description="Callsign of the user")
    x509cert: str = Field(description="Certificate encoded with CFSSL conventions (newlines escaped)")

    class Config:  # pylint: disable=too-few-public-methods
        """Example values for schema"""

        extra = Extra.forbid
        schema_extra = {
            "examples": [
                {
                    "uuid": "3ede23ae-eff2-4aa8-b7ef-7fac68c39988",
                    "callsign": "ROTTA01a",
                    "x509cert": "-----BEGIN CERTIFICATE-----\\nMIIEwjCC...\\n-----END CERTIFICATE-----\\n",
                },
            ]
        }


# FIXME: The spec for these will be changed
class UserInstructionFragment(BaseModel):
    """Product instructions for user"""

    html: str = Field(description="The HTML content will be shown for this products instructions")
    inject_css: Optional[str] = Field(
        description="If extra stylesheet is needed, set the fully qualified URI",
        default=None,
        json_schema_extra={"nullable": True},
    )

    class Config:  # pylint: disable=too-few-public-methods
        """Example values for schema"""

        extra = Extra.forbid
        schema_extra = {
            "examples": [
                {"html": "<p>Hello World!</p>"},
                {
                    "html": """<p class="hello">Hello World!</p>""",
                    "inject_css": "http://example.com/mystyle.css",
                },
            ]
        }


class ReadyRequest(BaseModel):  # pylint: disable=too-few-public-methods
    """Indicate product API readiness"""

    product: str = Field(description="Product name")
    apiurl: str = Field(description="Product API URL")
    url: str = Field(description="Product UI URL")

    class Config:  # pylint: disable=too-few-public-methods
        """Example values for schema"""

        extra = Extra.forbid
        schema_extra = {
            "examples": [
                {
                    "product": "tak",
                    "apiurl": "https://tak.sleepy-sloth.pvarki.fi:4625/",
                    "url": "https://tak.sleepy-sloth.pvarki.fi:8443/",
                },
            ]
        }


class ProductHealthCheckResponse(BaseModel):
    """Healthcheck response for product integration apis

    The extra info might be used by a human to debug things but RASENMAEHER will not use it"""

    healthy: bool = Field(description="Everything is good, ready to serve")
    extra: Optional[str] = Field(description="Extra information", default=None, json_schema_extra={"nullable": True})

    class Config:  # pylint: disable=too-few-public-methods
        """Example values for schema"""

        extra = Extra.forbid
        schema_extra = {
            "examples": [
                {"healthy": True},
                {"healthy": False, "extra": "Things went wrong"},
            ]
        }
