"""FastAPI auth middleware for mTLS proxy-header auth"""

from typing import Optional, Mapping
import logging

from fastapi import Request, HTTPException
from fastapi.security.http import HTTPBase
from starlette.config import Config
from cryptography import x509


LOGGER = logging.getLogger(__name__)
CONFIG = Config()  # not supporting .env files anymore because https://github.com/encode/starlette/discussions/2446
DNDict = Mapping[str, str]


class MTLSHeader(HTTPBase):  # pylint: disable=R0903
    """Check Nginx/Linkerd injected mTLS header"""

    def __init__(
        self,
        *,
        scheme: str = "header",
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        """initializer"""
        self.scheme_name = scheme_name or self.__class__.__name__
        super().__init__(scheme=scheme, scheme_name=scheme_name, description=description, auto_error=auto_error)
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[DNDict]:  # type: ignore[override]
        """actual work"""
        header_name = CONFIG("MTLS_HEADER_NAME", default="X-ClientCert-DN").lower()
        l5d_header = CONFIG("MTLS_L5D_HEADER_NAME", default="l5d-client-id").lower()
        trust_l5d = CONFIG("MTLS_TRUST_L5D", cast=bool, default=False)
        # Ingress identities - verify MTLS_HEADER instead of L5D
        mtls_trusted_ingress_identities = {
            ident.strip() for ident in CONFIG("MTLS_TRUSTED_INGRESS_IDENTITIES", default="").split(",") if ident.strip()
        }

        payload: Optional[DNDict] = None
        if (
            trust_l5d
            and (l5d_value := request.headers.get(l5d_header))
            and l5d_value not in mtls_trusted_ingress_identities
        ):
            # Linkerd identity is a bare SPIFFE-style name, not an RFC4514 DN
            payload = {"CN": l5d_value}
        elif header_value := request.headers.get(header_name):
            try:
                payload = x509name2dict(x509.Name.from_rfc4514_string(header_value))
            except Exception as exc:
                raise HTTPException(status_code=403, detail="Invalid authentication") from exc

        if payload is None:
            if self.auto_error:
                raise HTTPException(status_code=403, detail="Not authenticated")
            return None

        # Inject into request state to avoid Repeating Myself
        request.state.mtlsdn = payload
        return payload


def x509name2dict(attrs: x509.Name) -> DNDict:
    """Take the Sequence of NameAttributes and make a dict"""
    return {attr.rfc4514_attribute_name: attr.value for attr in attrs if isinstance(attr.value, str)}
