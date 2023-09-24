"""Test the helper functions"""
from pathlib import Path
import logging
import stat

from libpvarki.mtlshelp.csr import create_keypair

LOGGER = logging.getLogger(__name__)


def test_keypair_create(nice_tmpdir: str) -> None:
    """Test normal create case"""
    datadir = Path(nice_tmpdir)
    privdir = datadir / "private"
    privpath = privdir / "mycert.key"
    pubdir = datadir / "public"
    pubpath = pubdir / "mycert.pub"
    privdir.mkdir(parents=True)
    pubdir.mkdir(parents=True)
    ckp = create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    assert ckp
    assert privpath.exists()
    assert pubpath.exists()
    pstat = privpath.stat()
    assert not pstat.st_mode & stat.S_IRGRP
    assert not pstat.st_mode & stat.S_IROTH
