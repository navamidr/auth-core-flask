import pytest
from flask import Flask, jsonify, request
from flycatch_auth import auth, AuthCoreJwtConfig, IdentityService, Identity, AuthCoreSessionConfig


class MockUserService(IdentityService):
    def load_user(self, username: str) -> Identity:
        return {"id": "1", "username": "testuser", "password": "password123", "grants": ["read_user"]}


@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "super-secret-key"

    jwt_config = AuthCoreJwtConfig(
        enable=True,
        secret="mysecret",
        expiresIn="2h",
        refresh=True,
        prefix="/auth/jwt",
    )
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
        jwt=jwt_config,
        session=session_config
    )

    @app.route("/me")
    @auth.verify()
    # @auth.has_grants(["read_user"])["flask"]
    def get_curr_user():
        return jsonify({"name": "Test User"}), 200
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_me_route_with_auth(client):
    """Test Jwt-based authentication for the /me route."""
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"})

    assert login_response.status_code == 200, "Login successful"

    token = login_response.json['data']['access_token']
    assert token, "Token is missing from response"

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/me", headers=headers)
    assert response.status_code == 200, "Access granted"
    assert response.json["name"] == "Test User"


def test_me_route_with_session(client):
    """Test session-based authentication for the /me route."""
    login_response = client.post(
        "/auth/session/login", json={"username": "testuser", "password": "password123"}
    )
    assert login_response.status_code == 200, "Login should be successful"
    assert "message" in login_response.json, "Login response should contain a message"

    # Step 2: Access the /me route using the session
    response = client.get("me")
    assert response.status_code == 200, "Authenticated session should access /me"
    assert response.json["name"] == "Test User"
