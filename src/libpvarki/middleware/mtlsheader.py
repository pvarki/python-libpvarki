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

        if trust_l5d:
            payload = self._meshed_payload(request, l5d_header, header_name)
        else:
            payload = self._cert_payload(request, header_name)

        if payload is None:
            if self.auto_error:
                raise HTTPException(status_code=403, detail="Not authenticated")
            return None

        # Inject into request state to avoid Repeating Myself
        request.state.mtlsdn = payload
        return payload

    def _meshed_payload(self, request: Request, l5d_header: str, header_name: str) -> Optional[DNDict]:
        """l5d is trusted when present. MTLS_REQUIRE_L5D makes it mandatory (fully-meshed hardening)."""
        trusted_ingress = {
            ident.strip() for ident in CONFIG("MTLS_TRUSTED_INGRESS_IDENTITIES", default="").split(",") if ident.strip()
        }
        require_l5d = CONFIG("MTLS_REQUIRE_L5D", cast=bool, default=False)
        l5d_value = request.headers.get(l5d_header)
        if not l5d_value:
            # No verified mesh peer. Fail closed only when the mesh is complete (require_l5d);
            # otherwise honor the cert header so not-yet-meshed callers still authenticate.
            if require_l5d:
                return None
            return self._cert_payload(request, header_name)
        if l5d_value in trusted_ingress:
            # Via a trusted ingress: real identity is the forwarded client cert (else None -> JWT).
            return self._cert_payload(request, header_name)
        # Lateral in-mesh service call: the peer identity is the client.
        # Linkerd identity is a bare SPIFFE-style name, not an RFC4514 DN.
        return {"CN": l5d_value}

    def _cert_payload(self, request: Request, header_name: str) -> Optional[DNDict]:
        """Parse the proxy-injected client-cert DN header (RFC4514), if present."""
        header_value = request.headers.get(header_name)
        if not header_value:
            return None
        try:
            return x509name2dict(x509.Name.from_rfc4514_string(header_value))
        except Exception as exc:
            raise HTTPException(status_code=403, detail="Invalid authentication") from exc


def x509name2dict(attrs: x509.Name) -> DNDict:
    """Take the Sequence of NameAttributes and make a dict"""
    return {attr.rfc4514_attribute_name: attr.value for attr in attrs if isinstance(attr.value, str)}
