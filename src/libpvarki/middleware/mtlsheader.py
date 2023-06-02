"""FastAPI auth middleware for mTLS proxy-hearer auth"""
from typing import Optional
import logging

from fastapi import Request, HTTPException
from fastapi.security.http import HTTPBase
from starlette.config import Config
from cryptography import x509


LOGGER = logging.getLogger(__name__)
CONFIG = Config(".env")


class MTLSHeader(HTTPBase):  # pylint: disable=R0903
    """Check NGinx injected mTLS header"""

    def __init__(
        self,
        *,
        scheme: str,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        """initializer"""
        super().__init__(scheme=scheme, scheme_name=scheme_name, description=description, auto_error=auto_error)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[x509.Name]:  # type: ignore[override]
        """actual work"""
        header_name = CONFIG("MTLS_HEADER_NAME", default="X-ClientCert-DN")
        if header_value := request.headers.get(header_name):
            try:
                payload = x509.Name.from_rfc4514_string(header_value)
            except Exception as exc:
                raise HTTPException(status_code=403, detail="Invalid authentication") from exc
        else:
            if self.auto_error:
                raise HTTPException(status_code=403, detail="Not authenticated")
            return None

        # Inject into request state to avoid Repeating Myself
        request.state.mtlsdn = payload
        return payload
