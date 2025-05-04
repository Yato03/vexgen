import pytest
import pytest_asyncio
from app.models.models import User
from app.main import app
from httpx import AsyncClient, ASGITransport
import os
import zipfile
from app.models.models import GenerateVEXRequest, StatementsGroup

@pytest_asyncio.fixture(scope="session")
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

@pytest_asyncio.fixture(scope="session")
async def test_user(async_client):
    user_data = {
        "email": "test@test.com",
        "password": "1234testI&"
    }

    user = User(**user_data)
    user_dict = user.model_dump()

    response = await async_client.post("/auth/signup", json=user_dict)
    signup_data = response.json()
    assert signup_data["message"] in {"success", "user_already_exists"}

    login_response = await async_client.post("/auth/login", json=user_dict)
    assert login_response.status_code == 200

    return login_response.json()["user_id"]


@pytest.mark.asyncio
async def test_generate_vex(async_client, test_user):
    user_id = test_user
    
    test_data = {
        "owner": "depexorg",
        "name": "vex_generation",
        "sbom_path": "sbom.json",
        "statements_group": StatementsGroup.no_grouping.value,
        "user_id": user_id
    }
    
    request = GenerateVEXRequest(**test_data)
    
    response = await async_client.post("/vex/generate", json=request.model_dump())
    
    assert response.status_code == 200
    
    assert response.headers["content-type"] == "application/zip"
    
    zip_path = "test_vex.zip"
    with open(zip_path, "wb") as f:
        f.write(response.content)
    
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        files = zip_file.namelist()
        assert "vex.json" in files
        assert "extended_vex.json" in files
    
    os.remove(zip_path)

@pytest_asyncio.fixture(scope="session")
async def get_vex_by_user(async_client, test_user):
    response = await async_client.get(f"/vex/user/{test_user}")
    assert response.status_code == 200
    return response.json()

@pytest_asyncio.fixture(scope="session")
async def vex_data(test_user):
    return {
        "owner": "depexorg",
        "name": "vex_generation",
        "sbom_path": "sbom.json",
        "statements_group": "no_grouping",
        "user_id": test_user
    }

@pytest.mark.asyncio
async def test_vex_ingestion(async_client, get_vex_by_user):
    vex_id = get_vex_by_user[0]["_id"]
    
    result = await async_client.get(f"/vex/ingest/{vex_id}")
    result_json = result.json()
    
    assert isinstance(result_json, dict)
    assert "@context" in result_json