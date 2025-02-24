from typing import Dict, Optional
from flask import session
import logging
from .base import AuthService
from ..model_types import IdentityService, CredentialChecker, api_response


logger = logging.getLogger(__name__)


def setup_session(app, config):
    """Configure and initialize session management for Flask."""
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SECRET_KEY"] = config["session"]["secret"]
    app.config["SESSION_COOKIE_SECURE"] = config["session"]["cookie"].get(
        "secure", False)
    app.config["PERMANENT_SESSION_LIFETIME"] = config["session"]["cookie"].get(
        "maxAge", 86400)


class SessionAuthService(AuthService):
    """Session-based authentication service."""

    def __init__(self, user_service: IdentityService, credential_checker: CredentialChecker):
        self.user_service = user_service
        self.credential_checker = credential_checker

    def authenticate(self) -> Optional[Dict]:
        """Check if a user is authenticated in the session."""
        user = session.get("user")
        if user:
            return {"user": user["username"], "authenticated": True},session
        return None

    def login(self, username: str, password: str) -> Dict:
        """Handle user login via session."""
        logger.info(f"Login attempt for username: {username}")

        user = self.user_service.load_user(username)
        if not user:
            logger.warning(f"Login failed: User not found (username {username})")
            return api_response(401, "Invalid username or password", False)

        if not self.credential_checker(password, user["password"]):
            logger.warning(f"Login failed: Invalid password for username {username}")
            return api_response(401, "Invalid username or password", False)

        # Store user in session
        session["user"] = {"username": user["username"]}
        logger.info(f"Session set with user: {session.get('user')}")
        logger.info(f"Login successful for username: {username}")
        return api_response(200, "Login successful", True, {"user":session.get("user")})


    def logout(self) -> Dict:
        """Handle user logout and remove session data."""
        session.pop("user", None)
        logger.info("User logged out successfully.")
        return api_response(200, "Logout successful", True)

    def refresh(self) -> Dict:
        """Refresh session authentication (if applicable)."""
        user = session.get("user")
        if user:
            logger.info(f"Session refreshed for user: {user['username']}")
            return api_response(200, "Session refreshed", False, user)
        return api_response(401, "No active session", False)
