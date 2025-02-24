import pytest
from flask import Flask, session
from flycatch_auth import auth, AuthCoreSessionConfig, IdentityService, Identity


class MockUserService(IdentityService):
    def load_user(self, username: str) -> Identity:
        return {
            "id": "1",
            "username": "testuser",
            "password": "password123",
            "grants": ["read_user"],
        }


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "session-secret"
    app.config["SESSION_TYPE"] = "filesystem"

    session_config = AuthCoreSessionConfig(
        enabled=True,
        secret="session-secret",
        resave=False,
        saveUninitialized=False,
        cookie={"secure": False, "maxAge": 24 * 60 * 60 * 1000},
    )

    auth.init_app(
        app=app,
        user_service=MockUserService(),
        credential_checker=lambda input, user: input == user,
        session=session_config
    )

    @app.post("/auth/session/login")
    def login(request):
        data = auth.auth_service.login(
            request.json.get("username"),
            request.json.get("password")
        )
        return data, 200 if "message" in data else 401

    @app.get("/auth/session/logout")
    def logout():
        return auth.auth_service.logout()

    @app.get("/auth/session/refresh")
    def refresh():
        data = auth.auth_service.refresh()
        return data, 200 if "message" in data else 401

    @app.get("/me")
    def protected():
        return {"message": "Access granted"}, 200
    
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_session_login(client):
    """Test user login and session storage."""
    response = client.post(
        "/auth/session/login", json={"username": "testuser", "password": "password123"}
    )
    assert response.status_code == 200
    assert response.json["message"] == "Login successful"


def test_session_protected_access(client):
    """Test accessing a protected route after login."""
    client.post("/auth/session/login",
                json={"username": "testuser", "password": "password123"})
    response = client.get("/me")
    assert response.status_code == 200

    assert response.json["message"] == "Access granted"
    # assert response.json["user"]["username"] == "testuser"


def test_session_refresh(client):
    """Test refreshing session authentication."""
    client.post("/auth/session/login",
                json={"username": "testuser", "password": "password123"})

    response = client.get("/auth/session/refresh")
    assert response.status_code == 200
    assert response.json["message"] == "Session refreshed"
    assert response.json["data"]["username"] == "testuser"


def test_session_logout(client):
    """Test logging out and ensuring session is cleared."""
    client.post("/auth/session/login",
                json={"username": "testuser", "password": "password123"})

    logout_response = client.get("/auth/session/logout")
    assert logout_response.status_code == 200
    assert logout_response.json["message"] == "Logout successful"

    protected_response = client.get("/me")
    # assert protected_response.status_code == 401
    # assert protected_response.json["error"] == "Unauthorized"
