from flask import Blueprint, request, session, jsonify
from ..services import SessionAuthService


def create_session_routes(app, config, user_service, credential_checker):
    """Setup session-based authentication routes."""
    session_bp = Blueprint("session_auth", __name__,
                           url_prefix=config.get("prefix", "/auth/session"))

    # Initialize session authentication service
    auth_service = SessionAuthService(user_service, credential_checker)

    @session_bp.route("/login", methods=["POST"])
    def login():
        """Handle user login and start session."""
        data = request.json
        username = data.get("username")
        password = data.get("password")
        try:
            user = user_service.load_user(username)
            if not user:
                return jsonify({"error": "Invalid username or password"}), 401

            valid_password = credential_checker(password, user["password"])
            if not valid_password:
                return jsonify({"error": "Invalid username or password"}), 401

            # Store user details in session
            session["user"] = {"username": user["username"]}
            return jsonify({"message": "Login successful"})

        except Exception as e:
            return jsonify({"error": "Internal server error"}), 500
        
    @session_bp.route("/logout", methods=["POST"])
    def logout():
        """Clear session on logout."""
        session.pop("user", None)
        return jsonify({"message": "Logout successful"})

    # Register the blueprint in the Flask app
    app.register_blueprint(session_bp)
