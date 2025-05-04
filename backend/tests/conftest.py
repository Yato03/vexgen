import asyncio
import pytest

@pytest.fixture(scope="session")
def event_loop():
    """Crear un event loop de sesión para permitir scope=session en fixtures async."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()