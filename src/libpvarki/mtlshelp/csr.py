"""Create keys and CSRs"""

from typing import Mapping, Sequence, Tuple, Iterable
from pathlib import Path
import logging
import stat
import asyncio
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.name import _NAME_TO_NAMEOID

LOGGER = logging.getLogger(__name__)
KPTYPE = rsa.RSAPrivateKey  # TODO: should this be more than a type alias?
PUBDIR_MODE = stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH | stat.S_IXGRP | stat.S_IXOTH
PRIVDIR_MODE = stat.S_IRWXU

HASHER_MAP = {
    "sha256": hashes.SHA256,
}


def resolve_filepaths(basedir: Path, nameprefix: str) -> Tuple[Path, Path, Path]:
    """Returns paths for privkey, pubkey, and csr files (but the files are not created

    creates the parent directories if needed, will create "private" and "public" subdirs under the base
    if they do not exist, will ensure the directories have sane permissions"""
    pubdir = basedir / "public"
    pubdir.mkdir(parents=True, exist_ok=True)
    # everyone can read this dir, owner can write to it
    pubdir.chmod(PUBDIR_MODE)
    pubkeypath = pubdir / f"{nameprefix}.pub"
    csrpath = pubdir / f"{nameprefix}.csr"

    privdir = basedir / "private"
    privdir.mkdir(parents=True, exist_ok=True)
    # Owner can read and write this dir, others have no access
    privdir.chmod(PRIVDIR_MODE)
    privkeypath = privdir / f"{nameprefix}.key"

    return privkeypath, pubkeypath, csrpath


def create_keypair(privkeypath: Path, pubkeypath: Path, ktype: str = "RSA", ksize: int = 4096) -> rsa.RSAPrivateKey:
    """Generate a keypair, saves files to given paths (directory must exist) and returns the
    keypair object"""
    for check_path in (privkeypath, pubkeypath):
        if not check_path.parent.exists():
            LOGGER.error("Path {} does not exist".format(check_path.parent))
            raise ValueError("Invalid path {}".format(check_path))
        if not check_path.parent.is_dir():
            LOGGER.error("Path {} is not a directory".format(check_path.parent))
            raise ValueError("Invalid path {}".format(check_path))
        if check_path.exists():
            LOGGER.warning("{} already exists, it will be overwritten".format(check_path))
    LOGGER.info("Generating {} keypair of size {}, this will take a moment".format(ktype, ksize))
    if ktype == "RSA":
        ckp = rsa.generate_private_key(public_exponent=65537, key_size=ksize)
    else:
        raise NotImplementedError(f"Key type {ktype} not supported")
    LOGGER.info("Keygen done")
    privkeypath.write_bytes(
        ckp.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    privkeypath.chmod(stat.S_IRUSR)  # read-only to the owner, others get nothing
    pubkeypath.write_bytes(
        ckp.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    pubkeypath.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # everyone can read
    LOGGER.info("Wrote {} and {}".format(privkeypath, pubkeypath))
    return ckp


async def async_create_keypair(
    privkeypath: Path,
    pubkeypath: Path,
    ktype: str = "RSA",
    ksize: int = 4096,
) -> rsa.RSAPrivateKey:
    """Async wrapper for create_keypair see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_keypair, privkeypath, pubkeypath, ktype, ksize)


def sign_and_write_csrfile(
    builder: x509.CertificateSigningRequestBuilder,
    keypair: rsa.RSAPrivateKey,
    csrpath: Path,
    digest: str,
) -> str:
    """internal helper to be more DRY, returns the PEM"""
    csr = builder.sign(keypair, HASHER_MAP[digest.lower()]())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csrpath.write_bytes(csr_pem)
    csrpath.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # everyone can read
    LOGGER.info("Wrote {}".format(csrpath))
    return csr_pem.decode("utf-8")


def _build_san_names(names: Sequence[str]) -> Iterable[x509.GeneralName]:
    for name in names:
        if name.startswith("IP:"):
            yield x509.IPAddress(ip_address(name[3:]))
        else:
            dns_name = name[4:] if name.startswith("DNS:") else name
            yield x509.DNSName(dns_name)


def _build_csr_builder(
    subject_name: x509.Name,
    extended_usages: Iterable[x509.ObjectIdentifier],
) -> x509.CertificateSigningRequestBuilder:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject_name)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(extended_usages),
            critical=True,
        )
    )


def create_client_csr(
    keypair: rsa.RSAPrivateKey,
    csrpath: Path,
    reqdn: Mapping[str, str],
    digest: str = "sha256",
) -> str:
    """Generate CSR file with clientAuth extended usage, returns the PEM encoded contents

    reqdn must contain only names that are valid for X509Name, for example::

        { "CN": "me.pvarki.fi" }
    """
    name = x509.Name([x509.NameAttribute(_NAME_TO_NAMEOID[key], value) for key, value in reqdn.items()])
    req = _build_csr_builder(
        subject_name=name,
        extended_usages=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    return sign_and_write_csrfile(req, keypair, csrpath, digest)


async def async_create_client_csr(
    keypair: rsa.RSAPrivateKey,
    csrpath: Path,
    reqdn: Mapping[str, str],
    digest: str = "sha256",
) -> str:
    """Async wrapper for create_client_csr see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_client_csr, keypair, csrpath, reqdn, digest)


def create_server_csr(keypair: rsa.RSAPrivateKey, csrpath: Path, names: Sequence[str], digest: str = "sha256") -> str:
    """Generate CSR file with serverAuth extended usage, returns the PEM encoded contents
    First name will go to CN, all names will go to subjectAltNames

    If the value in names does not start with DNS: or IP: DNS: will be prepended, the first name will be used
    for CN and MUST NOT contain a prefix (thus it SHOULD be a dns name)
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    req = _build_csr_builder(
        subject_name=name,
        extended_usages=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH],
    )
    req = req.add_extension(
        x509.SubjectAlternativeName(list(_build_san_names(names))),
        critical=False,
    )

    return sign_and_write_csrfile(req, keypair, csrpath, digest)


async def async_create_server_csr(
    keypair: rsa.RSAPrivateKey,
    csrpath: Path,
    names: Sequence[str],
    digest: str = "sha256",
) -> str:
    """Async wrapper for create_server_csr see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_server_csr, keypair, csrpath, names, digest)
