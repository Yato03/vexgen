import asyncio
import pytest

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop to allow scope=session in async fixtures."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()