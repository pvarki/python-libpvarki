"""Wrapper to create a ClientSession with the correct SSL/TLS context things set up"""
from typing import Optional, Tuple
from pathlib import Path
import ssl
import logging

from starlette.config import Config
import aiohttp

LOGGER = logging.getLogger(__name__)
CONFIG = Config(".env")


# https://github.com/miguelgrinberg/python-socketio/discussions/1040 was very helpful
def get_session(
    client_cert_paths: Optional[Tuple[Path, Path]] = None, extra_ca_certs_path: Optional[Path] = None
) -> aiohttp.ClientSession:
    """Get a session with correct SSL/TLS contexts set,
    if the cert paths are not set ENV or defaults will be used"""
    ssl_ctx = ssl.create_default_context()
    dataroot = Path(CONFIG("PERSISTENT_DATA_PATH", default="/data/persistent"))
    if client_cert_paths:
        client_cert_path = client_cert_paths[0]
        client_key_path = client_cert_paths[1]
    else:
        client_cert_path = Path(CONFIG("CLIENT_CERT_PATH", default=f"{dataroot}/public/mtlsclient.pem"))
        client_key_path = Path(CONFIG("CLIENT_KEY_PATH", default=f"{dataroot}/private/mtlsclient.key"))
    if not extra_ca_certs_path:
        extra_ca_certs_path = Path(CONFIG("LOCAL_CA_CERTS_PATH", default="/ca_public"))
    LOGGER.info("Loading client cert from {} and {}".format(client_cert_path, client_key_path))
    ssl_ctx.load_cert_chain(client_cert_path, client_key_path)
    LOGGER.info("Loading local CA certs from {}".format(extra_ca_certs_path))
    for cafile in extra_ca_certs_path.iterdir():
        if not cafile.is_file():
            continue
        LOGGER.debug("Adding cert {}".format(cafile))
        ssl_ctx.load_verify_locations(str(cafile))

    conn = aiohttp.TCPConnector(ssl=ssl_ctx)
    session = aiohttp.ClientSession(connector=conn)
    return session
