"""Test session init"""
from pathlib import Path

import pytest

from libpvarki.mtlshelp import get_session


@pytest.mark.asyncio
async def test_session_getter_defaults() -> None:
    """Test that we can get a session with ENV based defaults"""
    session = get_session()
    assert session


@pytest.mark.asyncio
async def test_session_getter_manual(datadir: Path) -> None:
    """Test that we can get a session with manually set paths"""
    persistentdir = datadir / "persistent"
    client_cert = (persistentdir / "public" / "mtlsclient.pem", persistentdir / "private" / "mtlsclient.key")
    capath = datadir / "ca_public"
    session = get_session(client_cert, capath)
    assert session
