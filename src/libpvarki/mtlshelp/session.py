"""Wrapper to create a ClientSession with the correct SSL/TLS context things set up"""
from typing import Optional, Tuple
from pathlib import Path
import logging
import ssl

import aiohttp

from .context import get_ssl_context

LOGGER = logging.getLogger(__name__)


def get_session(
    client_cert_paths: Optional[Tuple[Path, Path]] = None, extra_ca_certs_path: Optional[Path] = None
) -> aiohttp.ClientSession:
    """Get a session with correct SSL/TLS contexts set,
    if the cert paths are not set ENV or defaults will be used

    This can be used as context manager just like aiohttp.ClientSession:

    async with get_session() as session:
        async with session.get(uri) as resp:
            resp.raise_for_status()"""
    # server auth is used to authenticate servers, ie to create client sockets
    ctx = get_ssl_context(ssl.Purpose.SERVER_AUTH, client_cert_paths, extra_ca_certs_path)
    conn = aiohttp.TCPConnector(ssl=ctx)
    session = aiohttp.ClientSession(connector=conn)
    return session
