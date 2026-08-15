"""Firebase Admin ID-token verification and fail-closed authorization helpers."""

import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError


class FirebaseAuthError(PermissionError):
    """Base class for authentication failures safe to expose generically."""


class FirebaseAuthNotConfigured(RuntimeError):
    """Raised when a protected action is attempted without Firebase configuration."""


class MissingFirebaseToken(FirebaseAuthError):
    pass


class InvalidFirebaseToken(FirebaseAuthError):
    pass


class ExpiredFirebaseToken(FirebaseAuthError):
    pass


class UnverifiedFirebaseEmail(FirebaseAuthError):
    pass


class UnauthorizedFirebaseUser(FirebaseAuthError):
    pass


class AuthenticatedUser(BaseModel):
    """Validated identity derived only from a server-verified Firebase ID token."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    uid: str = Field(min_length=1, max_length=128)
    email: EmailStr | None = None
    email_verified: bool = False
    sign_in_provider: str = Field(default="unknown", max_length=100)
    roles: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()

    @property
    def is_google_user(self) -> bool:
        return self.sign_in_provider == "google.com"


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Mapping[str, Any]: ...


class VerificationResendRateLimiter:
    """Thread-safe local cooldown for verification resend authorization."""

    def __init__(self, cooldown_seconds: int = 60) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._last_allowed: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            previous = self._last_allowed.get(key)
            if previous is not None and now - previous < self.cooldown_seconds:
                remaining = max(1, int(self.cooldown_seconds - (now - previous)))
                raise PermissionError(f"Verification resend is rate limited for {remaining} seconds")
            self._last_allowed[key] = now


@dataclass
class FirebaseTokenVerifier:
    """Production verifier backed by the real Firebase Admin SDK."""

    project_id: str | None = None
    check_revoked: bool = True

    def __post_init__(self) -> None:
        self.project_id = self.project_id or os.getenv("FIREBASE_PROJECT_ID")

    def verify(self, token: str) -> Mapping[str, Any]:
        if not self.project_id:
            raise FirebaseAuthNotConfigured("FIREBASE NOT CONFIGURED")
        try:
            import firebase_admin
            from firebase_admin import auth
        except ImportError as exc:
            raise FirebaseAuthNotConfigured("FIREBASE NOT CONFIGURED") from exc

        try:
            try:
                app = firebase_admin.get_app()
            except ValueError:
                app = firebase_admin.initialize_app(options={"projectId": self.project_id})
            return auth.verify_id_token(token, app=app, check_revoked=self.check_revoked)
        except auth.ExpiredIdTokenError as exc:
            raise ExpiredFirebaseToken("Firebase ID token expired") from exc
        except (auth.InvalidIdTokenError, auth.RevokedIdTokenError, auth.UserDisabledError) as exc:
            raise InvalidFirebaseToken("Firebase ID token is invalid") from exc
        except FirebaseAuthError:
            raise
        except Exception as exc:
            # Credential lookup, certificate retrieval, and project mismatch all fail closed.
            raise FirebaseAuthNotConfigured("FIREBASE NOT CONFIGURED") from exc


def extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise MissingFirebaseToken("Firebase ID token is required")
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token.strip():
        raise MissingFirebaseToken("Bearer Firebase ID token is required")
    return token.strip()


def authenticate_bearer_token(
    authorization: str | None,
    verifier: TokenVerifier | None = None,
) -> AuthenticatedUser:
    """Verify a bearer token server-side and return normalized trusted claims."""
    token = extract_bearer_token(authorization)
    claims = (verifier or FirebaseTokenVerifier()).verify(token)
    firebase_claim = claims.get("firebase") if isinstance(claims.get("firebase"), Mapping) else {}
    roles = _string_set(claims.get("roles"))
    permissions = _string_set(claims.get("permissions"))
    if isinstance(claims.get("role"), str):
        roles = roles | {claims["role"]}
    try:
        return AuthenticatedUser(
            uid=claims.get("uid") or claims.get("sub"),
            email=claims.get("email"),
            email_verified=claims.get("email_verified") is True,
            sign_in_provider=firebase_claim.get("sign_in_provider", "unknown"),
            roles=frozenset(roles),
            permissions=frozenset(permissions),
        )
    except ValidationError as exc:
        raise InvalidFirebaseToken("Firebase ID token claims are invalid") from exc


def require_authenticated_user(
    user: AuthenticatedUser,
    *,
    require_verified_email: bool = True,
    required_roles: frozenset[str] = frozenset(),
    required_permissions: frozenset[str] = frozenset(),
) -> AuthenticatedUser:
    """Apply protected-action verification and future role/permission checks."""
    if require_verified_email and not user.email_verified:
        raise UnverifiedFirebaseEmail("Verified email is required")
    if not required_roles.issubset(user.roles):
        raise UnauthorizedFirebaseUser("Required role is missing")
    if not required_permissions.issubset(user.permissions):
        raise UnauthorizedFirebaseUser("Required permission is missing")
    return user


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple, set, frozenset)):
        return {item for item in value if isinstance(item, str) and item}
    return set()
