"""Create keys and CSRs"""
from typing import Mapping, Sequence, Tuple
from pathlib import Path
import logging
import stat
import asyncio

from OpenSSL import crypto  # FIXME: use cryptography instead of pyOpenSSL


LOGGER = logging.getLogger(__name__)
KTYPE_NAMES = {getattr(crypto, name): name.replace("TYPE_", "") for name in dir(crypto) if name.startswith("TYPE_")}
KPTYPE = crypto.PKey
PUBDIR_MODE = stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH | stat.S_IXGRP | stat.S_IXOTH
PRIVDIR_MODE = stat.S_IRWXU


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


def create_keypair(privkeypath: Path, pubkeypath: Path, ktype: int = crypto.TYPE_RSA, ksize: int = 4096) -> crypto.PKey:
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
    ckp = crypto.PKey()
    LOGGER.info(
        "Generating {} keypair of size {}, this will take a moment".format(KTYPE_NAMES.get(ktype, "unknown"), ksize)
    )
    ckp.generate_key(ktype, ksize)
    LOGGER.info("Keygen done")
    privkeypath.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, ckp))
    privkeypath.chmod(stat.S_IRUSR)  # read-only to the owner, others get nothing
    pubkeypath.write_bytes(crypto.dump_publickey(crypto.FILETYPE_PEM, ckp))
    pubkeypath.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # everyone can read
    LOGGER.info("Wrote {} and {}".format(privkeypath, pubkeypath))
    return ckp


async def async_create_keypair(
    privkeypath: Path, pubkeypath: Path, ktype: int = crypto.TYPE_RSA, ksize: int = 4096
) -> crypto.PKey:
    """Async wrapper for create_keypair see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_keypair, privkeypath, pubkeypath, ktype, ksize)


def sign_and_write_csrfile(req: crypto.X509Req, keypair: crypto.PKey, csrpath: Path, digest: str = "sha265") -> str:
    """internal helper to be more DRY, returns the PEM"""
    req.set_pubkey(keypair)
    req.sign(keypair, digest)
    csrpath.write_bytes(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
    csrpath.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # everyone can read
    LOGGER.info("Wrote {}".format(csrpath))
    return csrpath.read_text(encoding="utf-8")


def create_client_csr(keypair: crypto.PKey, csrpath: Path, reqdn: Mapping[str, str], digest: str = "sha256") -> str:
    """Generate CSR file with clientAuth extended usage, returns the PEM encoded contents

    reqdn must contain only names that are valid for X509Name, for example::

        { "CN": "me.pvarki.fi" }
    """

    req = crypto.X509Req()
    sub = req.get_subject()
    for name, value in reqdn.items():
        setattr(sub, name, value)
    req.add_extensions(
        [
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature,nonRepudiation,keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", True, b"clientAuth"),
        ]
    )
    return sign_and_write_csrfile(req, keypair, csrpath, digest)


async def async_create_client_csr(
    keypair: crypto.PKey, csrpath: Path, reqdn: Mapping[str, str], digest: str = "sha256"
) -> str:
    """Async wrapper for create_client_csr see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_client_csr, keypair, csrpath, reqdn, digest)


def create_server_csr(keypair: crypto.PKey, csrpath: Path, names: Sequence[str], digest: str = "sha256") -> str:
    """Generate CSR file with serverAuth extended usage, returns the PEM encoded contents
    First name will go to CN, all names will go to subjectAltNames

    If the value in names does not start with DNS: or IP: DNS: will be prepended, the first name will be used
    for CN and MUST NOT contain a prefix (thus it SHOULD be a dns name)
    """

    req = crypto.X509Req()
    req.get_subject().CN = names[0]
    sannames = []
    for name in names:
        if name.startswith("IP:") or name.startswith("DNS:"):
            sannames.append(name)
        else:
            sannames.append(f"DNS:{name}")
    sanbytes = ", ".join(sannames).encode("utf-8")
    req.add_extensions(
        [
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature,nonRepudiation,keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
            crypto.X509Extension(b"subjectAltName", False, sanbytes),
        ]
    )
    return sign_and_write_csrfile(req, keypair, csrpath, digest)


async def async_create_server_csr(
    keypair: crypto.PKey, csrpath: Path, names: Sequence[str], digest: str = "sha256"
) -> str:
    """Async wrapper for create_server_csr see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_server_csr, keypair, csrpath, names, digest)
