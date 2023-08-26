"""pytest automagics"""
from typing import Generator, AsyncGenerator
import logging
from pathlib import Path
import ssl
import random

import pytest
import pytest_asyncio
from libadvian.testhelpers import monkeysession  # pylint: disable=W0611
from libadvian.logging import init_logging
from aiohttp import web

from libpvarki.mtlshelp import get_ssl_context

init_logging(logging.DEBUG)
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


@pytest_asyncio.fixture()
async def test_server(datadir: Path) -> AsyncGenerator[str, None]:
    """Simple tls test server"""
    bind_port = random.randint(1000, 64000)  # nosec
    hostname = "mtls.localmaeher.pvarki.fi"
    persistentdir = datadir / "persistent"
    server_cert = (persistentdir / "public" / "tlsserver_chain.pem", persistentdir / "private" / "tlsserver.key")
    extra_ca_certs_path = datadir / "ca_public"

    async def handle(request: web.Request) -> web.Response:
        """Handle a request"""
        LOGGER.debug("request={}".format(request))
        LOGGER.debug("transport={}".format(request.transport))
        assert request.transport
        peer_cert = request.transport.get_extra_info("peercert")
        LOGGER.debug("peer_cert={}".format(peer_cert))
        assert peer_cert
        name = request.match_info.get("name", "Anonymous")
        text = "Hello, " + name
        return web.Response(text=text)

    app = web.Application()
    app.add_routes([web.get("/", handle), web.get("/{name}", handle)])

    ssl_ctx = get_ssl_context(server_cert, extra_ca_certs_path)
    # Enable client cert as required
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    LOGGER.debug("Starting the async server task(s)")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=hostname, port=bind_port, ssl_context=ssl_ctx)
    await site.start()

    uri = f"https://{hostname}:{bind_port}"
    LOGGER.debug("yielding {}".format(uri))
    yield uri

    LOGGER.debug("Stopping the async server task(s)")
    await runner.cleanup()
