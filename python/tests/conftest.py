import pytest


@pytest.fixture
def hashfile(tmp_path):
    return str(tmp_path / "test.spi")


@pytest.fixture
def logfile(tmp_path):
    return str(tmp_path / "test.spl")
