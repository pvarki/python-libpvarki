"""Quick and dirty fastapi test app"""
from typing import Mapping, Any
import logging

from fastapi import FastAPI, Depends

from libpvarki.middleware import MTLSHeader, DNDict
from libpvarki.schemas.product import UserCRUDRequest, UserInstructionFragment
from libpvarki.schemas.generic import OperationResultResponse

LOGGER = logging.getLogger(__name__)
APP = FastAPI(docs_url="/middleware/docs", openapi_url="/middleware/openapi.json")


@APP.get("/api/v1/check_auth")
async def check_auth(certdn: DNDict = Depends(MTLSHeader(auto_error=True))) -> Mapping[str, Any]:
    """Check auth"""
    ret = {"ok": True, "cert": certdn}
    return ret


@APP.get("/api/v1")
async def hello() -> Mapping[str, str]:
    """Say hello"""
    return {"message": "Hello World"}


@APP.post("/api/product/user/created")
async def user_created(
    user: UserCRUDRequest, certdn: DNDict = Depends(MTLSHeader(auto_error=True))
) -> OperationResultResponse:
    """New device cert was created"""
    _ = user  # TODO: should we validate the cert at this point ??
    _ = certdn
    result = OperationResultResponse(success=True)
    return result


@APP.post("/api/product/clients/fragment")
async def client_instruction_fragment(
    user: UserCRUDRequest, certdn: DNDict = Depends(MTLSHeader(auto_error=True))
) -> UserInstructionFragment:
    """Return user instructions"""
    _ = certdn
    result = UserInstructionFragment(html=f"<p>Hello {user.callsign}!</p>")
    return result
