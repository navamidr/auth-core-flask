import logging
from typing import Optional
from .model_types import IdentityService, CredentialChecker, AuthCoreSessionConfig, AuthCoreJwtConfig
from .services import JwtAuthService, SessionAuthService, setup_session
from .routes import create_jwt_routes, create_session_routes
from .middleware import verify_request


logger = logging.getLogger("auth_core")


class AuthCore:
    def __init__(self):
        self.app = None
        self.jwt = None
        self.session = None
        self.oauth = None
        self.user_service = None
        self.credential_checker = None
        self.auth_service = None

    def init_app(
        self,
        app,
        user_service: IdentityService,
        credential_checker: CredentialChecker,
        jwt: Optional[AuthCoreJwtConfig] = None,
        session: Optional[AuthCoreSessionConfig] = None,
    ):
        """Initialize authentication with JWT if enabled."""
        self.app = app
        self.jwt = jwt
        self.session = session
        self.user_service = user_service
        self.credential_checker = credential_checker

        if jwt and jwt.get("enable"):
            # Initialize JWT authentication service
            self.auth_service = JwtAuthService(
                user_service, credential_checker, jwt)

            # Set up JWT authentication routes
            create_jwt_routes(app, jwt, user_service, credential_checker)
        if session and session.get("enabled"):
            # Initialize session-based authentication service
            # Ensure session configuration is set up before initializing session routes
            # setup_session(app, {"session": session})  
            self.auth_service = SessionAuthService(
                user_service, credential_checker)
            create_session_routes(
                app, session, user_service, credential_checker)

        return self.auth_service

    def verify(self):
        """Middleware to verify authentication."""
        return verify_request(self.jwt, self.session, self.oauth)


auth = AuthCore()
