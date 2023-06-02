"""Quick and dirty fastapi test app"""
from typing import Mapping, Any
import logging

from fastapi import FastAPI, Depends

from libpvarki.middleware import MTLSHeader, DNDict

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
