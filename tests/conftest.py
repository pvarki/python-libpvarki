"""pytest automagics"""
from typing import Generator
import logging
from pathlib import Path

import pytest
from libadvian.testhelpers import monkeysession  # pylint: disable=W0611

LOGGER = logging.getLogger(__name__)

# pylint: disable=W0621


@pytest.fixture(scope="session")
def datadir() -> Path:
    """Resolve the data dir"""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session", autouse=True)
def tls_env_variables(datadir: Path, monkeysession: pytest.MonkeyPatch) -> Generator[pytest.MonkeyPatch, None, None]:
    """Set the TLS paths to env"""
    monkeysession.setenv("PERSISTENT_DATA_PATH", str(datadir / "persistent"))
    monkeysession.setenv("LOCAL_CA_CERTS_PATH", str(datadir / "ca_public"))

    yield monkeysession
    # The teardowns are done automagically
