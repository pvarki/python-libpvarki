"""Wrapper to create a ClientSession with the correct SSL/TLS context things set up"""
from typing import Optional, Tuple
from pathlib import Path
import logging

import aiohttp

from .context import get_ssl_context

LOGGER = logging.getLogger(__name__)


def get_session(
    client_cert_paths: Optional[Tuple[Path, Path]] = None, extra_ca_certs_path: Optional[Path] = None
) -> aiohttp.ClientSession:
    """Get a session with correct SSL/TLS contexts set,
    if the cert paths are not set ENV or defaults will be used"""
    conn = aiohttp.TCPConnector(ssl=get_ssl_context(client_cert_paths, extra_ca_certs_path))
    session = aiohttp.ClientSession(connector=conn)
    return session
