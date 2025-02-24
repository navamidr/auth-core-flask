import pytest
from flask import Flask, request, jsonify
from flycatch_auth import auth, AuthCoreJwtConfig, IdentityService, Identity, AuthCoreSessionConfig


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

    jwt_config = AuthCoreJwtConfig(
        enable=True,
        secret="mysecret",
        expiresIn="2h",
        refresh=True,
        prefix="/auth/jwt",
    )

    auth.init_app(
        app=app,
        user_service=MockUserService(),
        credential_checker=lambda input, user: input == user,
        jwt=jwt_config,
    )

    @app.post("/auth/jwt/login")
    def login():
        username = request.json.get("username")
        password = request.json.get("password")
        user = auth.authenticate(username, password)
        if user:
            tokens = auth.generate_tokens(user)
            return jsonify(tokens), 200
        return jsonify({"message": "Invalid credentials"}), 401

    @app.post("/auth/jwt/refresh")
    def refresh():
        refresh_token = request.json.get("refresh_token")
        new_token = auth.refresh_access_token(refresh_token)
        if new_token:
            return jsonify({"access_token": new_token}), 200
        return jsonify({"message": "Invalid refresh token"}), 401

    @app.get("/me")
    @auth.verify()
    def protected():
        return jsonify({"message": "Access granted"}), 200

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_jwt_token_generation(client):
    response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json.get("data")
    assert "refresh_token" in response.json.get("data")


def test_protected_route_access(client):
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"}
    )
    token = login_response.json["data"]["access_token"]

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["message"] == "Access granted"


def test_refresh_token(client):
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"}
    )
    refresh_token = login_response.json["data"]["refresh_token"]
    refresh_response = client.post(
        "/auth/jwt/refresh",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert refresh_response.json['code'] == 200
    assert "access_token" in refresh_response.json['data']
