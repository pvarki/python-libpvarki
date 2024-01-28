"""Test shell helpers"""
import logging
import asyncio

import pytest

from libpvarki.shell import call_cmd

LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_true() -> None:
    """Test that true exists with code 0"""
    code, stdout, stderr = await call_cmd("true")
    assert code == 0
    assert stdout == ""
    assert stderr == ""


@pytest.mark.asyncio
async def test_false() -> None:
    """Test that false exists with nonzero code"""
    code, stdout, stderr = await call_cmd("false")
    assert code != 0
    assert stdout == ""
    assert stderr == ""


@pytest.mark.asyncio
async def test_stdout() -> None:
    """Test that echo exists with code 0 and ouputs what we expect to stdout"""
    code, stdout, stderr = await call_cmd("echo 'hello world'")
    assert code == 0
    assert stdout == "hello world\n"
    assert stderr == ""


@pytest.mark.asyncio
async def test_stderr() -> None:
    """Test that echo exists with code 0 and ouputs what we expect to stderr"""
    code, stdout, stderr = await call_cmd("echo 'goodbye world' >&2")
    assert code == 0
    assert stdout == ""
    assert stderr == "goodbye world\n"


@pytest.mark.asyncio
async def test_timeout() -> None:
    """Test that long sleeps are aborted on timeout"""
    with pytest.raises(asyncio.TimeoutError):
        await call_cmd("sleep 5", timeout=1.0)
