import jwt
import logging
from functools import wraps
from flask import request, session, jsonify
from flycatch_auth.model_types import api_response

logger = logging.getLogger(__name__)


def verify_request(jwt, session, google_config):
    """Middleware to verify authentication via JWT, session, or Google OAuth."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            auth_header = request.headers.get("Authorization")

            session_enabled = session and isinstance(session, dict) and session.get("enabled")
            jwt_enabled = jwt and isinstance(jwt, dict) and jwt.get("enable")
            google_enabled = google_config and isinstance(google_config, dict) and google_config.get("enabled")

            # Try verifying JWT first if enabled
            if jwt_enabled and auth_header:
                logger.info("JWT enabled, verifying token...")
                jwt_verified = verify_jwt(auth_header, jwt, f, *args, **kwargs)
                if jwt_verified:  # If JWT is valid, return response
                    return jwt_verified

            # If JWT fails or is missing, try verifying session
            if session_enabled:
                logger.info("Session enabled, verifying session...")
                session_verified = verify_session(session, f, *args, **kwargs)
                if session_verified:  # If session is valid, return response
                    return session_verified

            # If neither JWT nor session succeeded, check Google OAuth (if enabled)
            if google_enabled and auth_header:
                logger.info("Google OAuth enabled, verifying token...")
                google_verified = verify_jwt(auth_header, google_config, f, *args, **kwargs)
                if google_verified:
                    return google_verified

            # If no authentication enabled, return 500
            logger.warning("Authentication is not configured")
            return jsonify({"error": "Authentication not configured"}), 500

        return wrapper

    return decorator


def verify_jwt(auth_header, config, f, *args, **kwargs):
    """Helper function to verify JWT token."""
    try:
        token = auth_header.split(" ")[1]  # Extract the token
        decoded_token = jwt.decode(
            token, config.get("secret"), algorithms=["HS256"])
        logger.info(
            f"JWT verified successfully for username: {decoded_token['username']}")
        request.user = decoded_token  # Attach user info to request
        return f(*args, **kwargs)
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return unauthorized_response("Token expired")
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return unauthorized_response("Invalid token")


def verify_session(session_data, f, *args, **kwargs):
    """Helper function to verify session authentication."""
    user = session.get("user")
    if user:
        logger.info(f"Session verified for user: {user['username']}")
        request.user = user  # Attach session user info to request
        return f(*args, **kwargs)
    else:
        logger.warning("Unauthorized session access attempt")
        return unauthorized_response("Unauthorized: Invalid session")


def unauthorized_response(message):
    """Helper function to return a 401 Unauthorized response."""
    return api_response(401, message, False)
