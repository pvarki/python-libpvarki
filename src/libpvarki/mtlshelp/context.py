"""SSL/TLS context helpers"""
from typing import Optional, Tuple
import ssl
from pathlib import Path
import logging

from starlette.config import Config


LOGGER = logging.getLogger(__name__)
CONFIG = Config()  # not supporting .env files anymore because https://github.com/encode/starlette/discussions/2446

# https://github.com/miguelgrinberg/python-socketio/discussions/1040 was very helpful


def get_ca_context(
    purpose: ssl.Purpose,
    extra_ca_certs_path: Optional[Path] = None,
) -> ssl.SSLContext:
    """Get SSL/TLS context with our local CA certs"""
    LOGGER.debug("ssl.create_default_context(purpose={})".format(purpose))
    ssl_ctx = ssl.create_default_context(purpose=purpose)
    if not extra_ca_certs_path:
        extra_ca_certs_path = Path(CONFIG("LOCAL_CA_CERTS_PATH", default="/ca_public"))
    LOGGER.info("Loading local CA certs from {}".format(extra_ca_certs_path))
    for cafile in extra_ca_certs_path.glob(CONFIG("LOCAL_CA_CERTS_GLOB", default="*ca*.pem")):
        if not cafile.is_file():
            continue
        LOGGER.debug("Adding cert {}".format(cafile))
        ssl_ctx.load_verify_locations(str(cafile))
    return ssl_ctx


def get_ssl_context(
    purpose: ssl.Purpose,
    client_cert_paths: Optional[Tuple[Path, Path]] = None,
    extra_ca_certs_path: Optional[Path] = None,
) -> ssl.SSLContext:
    """Get SSL/TLS context with our local CA certs and client auth,
    if the cert paths are not set ENV or defaults will be used

    You can use this to create a server context too, put server cert and key to client paths"""
    ssl_ctx = get_ca_context(purpose, extra_ca_certs_path)
    dataroot = Path(CONFIG("PERSISTENT_DATA_PATH", default="/data/persistent"))
    if client_cert_paths:
        client_cert_path = client_cert_paths[0]
        client_key_path = client_cert_paths[1]
    else:
        client_cert_path = Path(CONFIG("CLIENT_CERT_PATH", default=f"{dataroot}/public/mtlsclient.pem"))
        client_key_path = Path(CONFIG("CLIENT_KEY_PATH", default=f"{dataroot}/private/mtlsclient.key"))
    LOGGER.info("Loading client/server cert from {} and {}".format(client_cert_path, client_key_path))
    ssl_ctx.load_cert_chain(client_cert_path, client_key_path)
    return ssl_ctx
