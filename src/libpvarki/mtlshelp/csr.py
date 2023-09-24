"""Create keys and CSRs"""
from pathlib import Path
import logging
import stat
import asyncio

from OpenSSL import crypto  # FIXME: use cryptography instead of pyOpenSSL


LOGGER = logging.getLogger(__name__)
KTYPE_NAMES = {getattr(crypto, name): name.replace("TYPE_", "") for name in dir(crypto) if name.startswith("TYPE_")}


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
    return ckp


async def async_create_keypair(
    privkeypath: Path, pubkeypath: Path, ktype: int = crypto.TYPE_RSA, ksize: int = 4096
) -> crypto.PKey:
    """Async wrapper for create_keypair see it for details"""
    return await asyncio.get_event_loop().run_in_executor(None, create_keypair, privkeypath, pubkeypath, ktype, ksize)
