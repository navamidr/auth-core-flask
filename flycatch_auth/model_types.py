from abc import ABC, abstractmethod
from typing import List, Optional, TypedDict
from datetime import datetime


class Identity:
    """Manage user authentication and authorization."""

    def __init__(self, user_id: str, username: str, grants: List[str]):
        self.id = user_id
        self.username = username
        self.grants = grants

    def has_grant(self, grant: str) -> bool:
        """Check if the identity has a specific grant."""
        return grant in self.grants


class IdentityService(ABC):
    @abstractmethod
    def load_user(self, username: str) -> Optional[Identity]:
        """Override this method to fetch a user from DB."""
        pass


class UserType(TypedDict):
    id: str
    username: str
    password: str


class CredentialChecker:
    def __init__(self):
        pass

    def verify(self, input_password: str, user_password: str) -> bool:
        """Checks if the provided password matches the stored password."""
        return input_password == user_password


class AuthCoreSessionConfig(TypedDict, total=False):
    session_key: str
    session_expiration: int
    enabled: bool
    prefix: str
    secret: str
    resave: bool
    saveUninitialized: bool
    cookie: dict


class AuthCoreJwtConfig(TypedDict, total=False):
    enable: bool
    secret: str
    expiresIn: str
    refresh: bool
    prefix: str


def api_response(code: int, message: str, status: str, data=None):
    """Format API response."""
    return {
        "code": code,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": message,
        "status": status,
        "data": data or {},
    }
