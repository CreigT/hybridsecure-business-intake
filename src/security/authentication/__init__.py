"""Reusable authentication controls for HybridSecure applications."""

from .firebase_auth import (
    AuthenticatedUser,
    FirebaseAuthError,
    FirebaseAuthNotConfigured,
    FirebaseTokenVerifier,
    VerificationResendRateLimiter,
    authenticate_bearer_token,
    require_authenticated_user,
)

__all__ = [
    "AuthenticatedUser",
    "FirebaseAuthError",
    "FirebaseAuthNotConfigured",
    "FirebaseTokenVerifier",
    "VerificationResendRateLimiter",
    "authenticate_bearer_token",
    "require_authenticated_user",
]
