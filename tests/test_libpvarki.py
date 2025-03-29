"""Package level tests"""
from libpvarki import __version__


def test_version() -> None:
    """Make sure version matches expected"""
    assert __version__ == "2.1.0"
