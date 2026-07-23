"""Shared fixtures for the middleware tests"""

from typing import Generator

import pytest
from fastapi.testclient import TestClient

from .app import APP

MTLS_CLIENT_DN = "CN=harjoitus1.pvarki.fi,O=harjoitus1.pvarki.fi,L=KeskiSuomi,ST=Jyvaskyla,C=FI"


@pytest.fixture
def mtlsclient() -> Generator[TestClient, None, None]:
    """Client presenting a proxy-injected mTLS cert header (legacy / non-l5d path)."""
    yield TestClient(APP, headers={"X-ClientCert-DN": MTLS_CLIENT_DN})
