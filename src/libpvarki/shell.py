"""Shell related helpers"""
from typing import Tuple
import asyncio
import logging

LOGGER = logging.getLogger(__name__)


async def call_cmd(cmd: str, timeout: float = 2.5, *, stderr_warn: bool = True) -> Tuple[int, str, str]:
    """Do the boilerplate for calling cmd and returning the exit code and output as strings"""
    LOGGER.debug("Calling create_subprocess_shell(({})".format(cmd))
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(process.communicate(), timeout=timeout)
    out_str = out.decode("utf-8")
    err_str = err.decode("utf-8")
    if err and stderr_warn:
        LOGGER.warning("{} stderr: {}".format(cmd, err_str))
    LOGGER.info(out_str)
    assert isinstance(process.returncode, int)  # at this point it is, keep mypy happy
    if process.returncode != 0:
        LOGGER.error("{} returned nonzero code: {} (process: {})".format(cmd, process.returncode, process))
        LOGGER.error("{} stderr: {}".format(cmd, err_str))
        LOGGER.error("{} stdout: {}".format(cmd, out_str))

    return process.returncode, out_str, err_str
