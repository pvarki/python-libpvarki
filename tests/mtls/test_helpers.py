"""Test the helper functions"""
from typing import Tuple, AsyncGenerator
from pathlib import Path
import logging
import stat

import cryptography.x509
import pytest
import pytest_asyncio
from libpvarki.mtlshelp.csr import (
    create_keypair,
    async_create_keypair,
    KPTYPE,
    async_create_client_csr,
    create_client_csr,
    async_create_server_csr,
    create_server_csr,
    resolve_filepaths,
)

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


def test_resolve_filepaths(tmp_path: Path) -> None:
    """Test the helper"""
    privpath, pubpath, csrpath = resolve_filepaths(tmp_path, "mytest")
    assert privpath.name == "mytest.key"
    assert pubpath.name == "mytest.pub"
    assert csrpath.name == "mytest.csr"

    pubdir = pubpath.parent
    assert pubdir.exists()
    pubstat = pubdir.stat()
    LOGGER.debug("{} has mode {}".format(pubdir, stat.filemode(pubstat.st_mode)))
    assert not pubstat.st_mode & stat.S_IWGRP
    assert not pubstat.st_mode & stat.S_IWOTH
    assert pubstat.st_mode & (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    privdir = privpath.parent
    assert privdir.exists()
    privstat = privdir.stat()
    LOGGER.debug("{} has mode {}".format(privdir, stat.filemode(privstat.st_mode)))
    assert privstat.st_mode & stat.S_IRWXU
    assert not privstat.st_mode & (stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def check_keypair(ckp: KPTYPE, privpath: Path, pubpath: Path) -> None:
    """Do the checks"""
    assert ckp
    assert privpath.exists()
    assert pubpath.exists()
    pstat = privpath.stat()
    assert not pstat.st_mode & stat.S_IRGRP
    assert not pstat.st_mode & stat.S_IROTH


def create_subdirs(datadir: Path) -> Tuple[Path, Path]:
    """Create the test subdirs"""
    privpath, pubpath, _ = resolve_filepaths(datadir, "mycert")
    return privpath, pubpath


def test_keypair_create(tmp_path: Path) -> None:
    """Test normal create case"""
    privpath, pubpath = create_subdirs(tmp_path)
    ckp = create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    check_keypair(ckp, privpath, pubpath)


@pytest.mark.asyncio
async def test_keypair_create_async(tmp_path: Path) -> None:
    """Test the async wrapper"""
    privpath, pubpath = create_subdirs(tmp_path)
    ckp = await async_create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    check_keypair(ckp, privpath, pubpath)


@pytest_asyncio.fixture
async def keypair(tmp_path: Path) -> AsyncGenerator[Tuple[KPTYPE, Path, Path], None]:
    """Fixture to create keypair"""
    privpath, pubpath = create_subdirs(tmp_path)
    ckp = await async_create_keypair(privpath, pubpath, ksize=1024)  # small key to save time
    check_keypair(ckp, privpath, pubpath)
    yield ckp, privpath, pubpath


def check_csr(pemdata: str, expct_cn: str) -> None:
    """Check the CSR"""
    assert pemdata.startswith("-----BEGIN CERTIFICATE REQUEST-----\nMII")
    parsed = cryptography.x509.load_pem_x509_csr(pemdata.encode("utf-8"))
    dname = parsed.subject.rfc4514_string()
    LOGGER.debug("dname: {}".format(dname))
    assert f"CN={expct_cn}" in dname


@pytest.mark.asyncio
async def test_create_client_csr_async(keypair: Tuple[KPTYPE, Path, Path]) -> None:
    """Test client CSR creation"""
    ckp, _privpath, pubpath = keypair
    csrpath = pubpath.parent / "myname.csr"
    pemdata = await async_create_client_csr(ckp, csrpath, {"CN": "ROTTA03b"})
    check_csr(pemdata, expct_cn="ROTTA03b")


@pytest.mark.asyncio
async def test_create_client_csr_sync(keypair: Tuple[KPTYPE, Path, Path]) -> None:
    """Test client CSR creation with sync method (the fixture is async so this must be too)"""
    ckp, _privpath, pubpath = keypair
    csrpath = pubpath.parent / "myname.csr"
    pemdata = create_client_csr(ckp, csrpath, {"CN": "ROTTA03b"})
    check_csr(pemdata, expct_cn="ROTTA03b")


@pytest.mark.asyncio
async def test_create_server_csr_async(keypair: Tuple[KPTYPE, Path, Path]) -> None:
    """Test server CSR creation"""
    ckp, _privpath, pubpath = keypair
    csrpath = pubpath.parent / "myname.csr"
    pemdata = await async_create_server_csr(ckp, csrpath, ["localmaeher.pvarki.fi", "IP:127.0.0.1"])
    check_csr(pemdata, expct_cn="localmaeher.pvarki.fi")


@pytest.mark.asyncio
async def test_create_sever_csr_sync(keypair: Tuple[KPTYPE, Path, Path]) -> None:
    """Test server CSR creation (the fixture is async so this must be too)"""
    ckp, _privpath, pubpath = keypair
    csrpath = pubpath.parent / "myname.csr"
    pemdata = create_server_csr(ckp, csrpath, ["localmaeher.pvarki.fi", "IP:127.0.0.1"])
    check_csr(pemdata, expct_cn="localmaeher.pvarki.fi")
