import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from flycatch_auth import Auth, AuthCoreJwtConfig, IdentityService


class MockIdentityService(IdentityService):
    def load_user(self, username: str):
        if username == "test_user":
            return {"id": "1", "username": "test_user", "password": "securepass", "grants": ["read_user"]}
        return None


def mock_credential_checker(input_password, stored_password):
    return input_password == stored_password


@pytest.fixture
def fastapi_app():
    app = FastAPI()
    auth = Auth(MockIdentityService(), mock_credential_checker, AuthCoreJwtConfig(
        enable=True,
        secret="test-secret",
        expiresIn="1h",
        refresh=True,
        prefix="/auth/jwt",
    ),)

    @app.get("/protected")
    async def protected_route(user=auth.verify):
        return {"message": "Access granted", "user": user}
    return app


@pytest.fixture
def client(fastapi_app):
    return TestClient(fastapi_app)


def test_fastapi_protected_route(client):
    response = client.get("/protected")
    print(response.json)
    assert response.status_code == 401  # Should be unauthorized without token
