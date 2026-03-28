import pytest


@pytest.fixture
def sample_ip() -> str:
    return "192.168.1.100"


@pytest.fixture
def sample_port() -> int:
    return 4444


@pytest.fixture
def sample_executable() -> str:
    return "/bin/sh"


@pytest.fixture
def sample_data() -> bytes:
    return b"test data for encryption"
