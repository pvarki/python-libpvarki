"""Test the helper functions"""
from typing import Any, Tuple
from pathlib import Path
import logging
import stat

import pytest
from libpvarki.mtlshelp.csr import create_keypair, async_create_keypair

LOGGER = logging.getLogger(__name__)


def check_keypair(ckp: Any, privpath: Path, pubpath: Path) -> None:
    """Do the checks"""
    assert ckp
    assert privpath.exists()
    assert pubpath.exists()
    pstat = privpath.stat()
    assert not pstat.st_mode & stat.S_IRGRP
    assert not pstat.st_mode & stat.S_IROTH


def create_subdirs(datadir: Path) -> Tuple[Path, Path]:
    """Create the test subdirs"""
    privdir = datadir / "private"
    privpath = privdir / "mycert.key"
    pubdir = datadir / "public"
    pubpath = pubdir / "mycert.pub"
    privdir.mkdir(parents=True)
    pubdir.mkdir(parents=True)
    return privpath, pubpath


def test_keypair_create(nice_tmpdir: str) -> None:
    """Test normal create case"""
    privpath, pubpath = create_subdirs(Path(nice_tmpdir))
    ckp = create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    check_keypair(ckp, privpath, pubpath)


@pytest.mark.asyncio
async def test_keypair_create_async(nice_tmpdir: str) -> None:
    """Test the async wrapper"""
    privpath, pubpath = create_subdirs(Path(nice_tmpdir))
    ckp = await async_create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    check_keypair(ckp, privpath, pubpath)
