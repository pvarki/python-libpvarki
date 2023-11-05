"""Helper to convert PEM to PKCS12 (legacy format)"""
from typing import Optional, Sequence, Union, cast
import logging
from pathlib import Path

from libadvian.binpackers import ensure_utf8, ensure_str
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    pkcs12,
    PrivateFormat,
)
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

LOGGER = logging.getLogger(__name__)
PKCS12KEYTYPES = (
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)


def serialize_legacy_pkcs12(
    friendlyname: bytes,
    key: Optional[pkcs12.PKCS12PrivateKeyTypes],
    main_cert: Optional[x509.Certificate],
    other_certs: Optional[Sequence[x509.Certificate]],
    password: bytes,
) -> bytes:
    """serialize_key_and_certificates but using the more compatible legacy format"""
    LOGGER.debug("key={}".format(key))
    LOGGER.debug("main_cert={}".format(main_cert))
    LOGGER.debug("other_certs={}".format(other_certs))

    encryption = (
        PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)  # nosec
        .hmac_hash(hashes.SHA1())  # nosec
        .build(password)
    )

    return pkcs12.serialize_key_and_certificates(friendlyname, key, main_cert, other_certs, encryption)


def get_src_bytes(certsrc: Union[bytes, Path, str]) -> bytes:
    """Get the specified source as bytes can be path/pathlike or just the bytes as-is"""
    if isinstance(certsrc, Path):
        return certsrc.read_bytes()
    if ensure_str(certsrc).startswith("-----BEGIN "):
        return ensure_utf8(certsrc)
    certpath = Path(ensure_str(certsrc))
    if certpath.exists():
        return certpath.read_bytes()
    raise ValueError(f"Could not resolve {certsrc!r}")


def convert_pem_to_pkcs12(
    certsrc: Optional[Union[bytes, Path, str]],
    keysrc: Optional[Union[bytes, Path, str]],
    p12password: Union[bytes, str],
    keypassword: Optional[Union[bytes, str]] = None,
    friendlyname: Optional[Union[str, bytes]] = None,
) -> bytes:
    """Convert PEM to PKCS12 (legacy format), in case of multiple certs first one is the main and rests "CA"s"""
    if certsrc is None:
        main_cert = None
        other_certs = None
    else:
        certs = x509.load_pem_x509_certificates(get_src_bytes(certsrc))
        LOGGER.debug("Found {} certificates".format(len(certs)))
        if not certs:
            main_cert = None
            other_certs = None
        elif len(certs) > 1:
            main_cert = certs[0]
            other_certs = certs[1:]
        else:
            main_cert = certs[0]
            other_certs = None

    if keysrc is None:
        key = None
    else:
        if keypassword is not None:
            keypassword = ensure_utf8(keypassword)
        key = load_pem_private_key(get_src_bytes(keysrc), keypassword)
        LOGGER.debug("Got key {}".format(key))
        if not isinstance(key, PKCS12KEYTYPES):
            raise ValueError("Invalid key type for PKCS12")

    if friendlyname is None:
        friendlyname = b""

    return serialize_legacy_pkcs12(
        ensure_utf8(friendlyname),
        cast(Optional[pkcs12.PKCS12PrivateKeyTypes], key),
        main_cert,
        other_certs,
        ensure_utf8(p12password),
    )
