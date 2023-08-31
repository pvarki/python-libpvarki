"""Test session init"""
from pathlib import Path
import logging
import sys

import pytest

from libpvarki.mtlshelp import get_session

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.mark.skipif(sys.version_info >= (3, 10), reason="Python 3.10 & 3.11 have weird problem here")
@pytest.mark.asyncio
async def test_session_getter_defaults(test_server: str) -> None:
    """Test that we can get a session with ENV based defaults"""
    session = get_session()
    assert session
    uri = f"{test_server}/defaults"

    LOGGER.debug("requesting {}".format(uri))
    async with session.get(uri) as resp:
        LOGGER.debug("got response {}".format(resp))
        resp.raise_for_status()

    await session.close()


@pytest.mark.skipif(sys.version_info >= (3, 10), reason="Python 3.10 & 3.11 have weird problem here")
@pytest.mark.asyncio
async def test_session_getter_manual(datadir: Path, test_server: str) -> None:
    """Test that we can get a session with manually set paths"""
    persistentdir = datadir / "persistent"
    client_cert = (persistentdir / "public" / "mtlsclient.pem", persistentdir / "private" / "mtlsclient.key")
    capath = datadir / "ca_public"
    session = get_session(client_cert, capath)
    uri = f"{test_server}/manual"

    LOGGER.debug("requesting {}".format(uri))
    async with session.get(uri) as resp:
        LOGGER.debug("got response {}".format(resp))
        resp.raise_for_status()

    await session.close()


@pytest.mark.skipif(sys.version_info >= (3, 10), reason="Python 3.10 & 3.11 have weird problem here")
@pytest.mark.asyncio
async def test_session_getter_context_defaults(test_server: str) -> None:
    """Test that use the getter as context manager"""
    async with get_session() as session:
        assert session
        uri = f"{test_server}/context_defaults"

        LOGGER.debug("requesting {}".format(uri))
        async with session.get(uri) as resp:
            LOGGER.debug("got response {}".format(resp))
            resp.raise_for_status()

    assert session.closed
