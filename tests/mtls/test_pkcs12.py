"""Test the pkcs12 helper"""
from typing import Tuple
import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

from libpvarki.mtlshelp import pkcs12

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.fixture
def perdir() -> Path:
    """Get the persistent data dir"""
    return Path(__file__).parent.parent / "data" / "persistent"


@pytest.fixture
def single_cert_paths(perdir: Path) -> Tuple[Path, Path]:
    """Paths to the cert and key for single cert (not a chain) PEM"""
    return (perdir / "public" / "mtlsclient.pem"), (perdir / "private" / "mtlsclient.key")


def check_single_cert(pfxbytes: bytes, p12password: bytes, expect_key: bool = True) -> None:
    """Parse and check"""
    key, cert, cas = load_key_and_certificates(pfxbytes, p12password)
    LOGGER.debug("Got key={} cer={} cas={}".format(key, cert, cas))
    if expect_key:
        assert key
        assert cert
        assert not cas
    else:
        assert key is None
        # Cert without key seems to go to the "other certs" aka "CAs" section
        assert len(cas) == 1


def test_encode_pem_simple_paths(single_cert_paths: Tuple[Path, Path]) -> None:
    """Single cert and key (Paths)"""
    cert, key = single_cert_paths
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert, key, b"1337", None, "mtlsclient")
    check_single_cert(pfxbytes, b"1337")


def test_encode_pem_simple_pathstr(single_cert_paths: Tuple[Path, Path]) -> None:
    """Single cert and key (str paths)"""
    cert, key = single_cert_paths
    pfxbytes = pkcs12.convert_pem_to_pkcs12(str(cert), str(key), b"1337", None, "mtlsclient")
    check_single_cert(pfxbytes, b"1337")


def test_encode_pem_simple_bytes(single_cert_paths: Tuple[Path, Path]) -> None:
    """Single cert and key as bytes"""
    cert, key = single_cert_paths
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert.read_bytes(), key.read_bytes(), b"1337", None, "mtlsclient")
    check_single_cert(pfxbytes, b"1337")


def test_encode_pem_simple_strs(single_cert_paths: Tuple[Path, Path]) -> None:
    """Single cert and key as strings"""
    cert, key = single_cert_paths
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert.read_text(), key.read_text(), b"1337", None, "mtlsclient")
    check_single_cert(pfxbytes, b"1337")


def test_encode_pem_simple_nokey(single_cert_paths: Tuple[Path, Path]) -> None:
    """Single cert and key (Paths)"""
    cert, _key = single_cert_paths
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert, None, b"1337", None, "mtlsclient")
    check_single_cert(pfxbytes, b"1337", expect_key=False)


def test_encode_pem_chain_nokey(perdir: Path) -> None:
    """Cert chain without key"""
    cert_orig = perdir / "public" / "tlsserver_chain.pem"
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert_orig, None, b"1337", None, "server")
    key, cert, cas = load_key_and_certificates(pfxbytes, b"1337")
    LOGGER.debug("Got key={} cer={} cas={}".format(key, cert, cas))
    # Cert without key seems to go to the "other certs" aka "CAs" section
    assert cert is None
    assert len(cas) == 2
    assert key is None


def test_encode_pem_chain(perdir: Path) -> None:
    """Cert chain with key"""
    cert_orig = perdir / "public" / "tlsserver_chain.pem"
    key_orig = perdir / "private" / "tlsserver.key"
    pfxbytes = pkcs12.convert_pem_to_pkcs12(cert_orig, key_orig, b"1337", None, "server")
    key, cert, cas = load_key_and_certificates(pfxbytes, b"1337")
    LOGGER.debug("Got key={} cer={} cas={}".format(key, cert, cas))
    assert cert
    assert len(cas) == 1
    assert key
