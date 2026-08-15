import unittest

from src.security.authentication.firebase_auth import (
    ExpiredFirebaseToken,
    FirebaseAuthNotConfigured,
    FirebaseTokenVerifier,
    InvalidFirebaseToken,
    MissingFirebaseToken,
    UnauthorizedFirebaseUser,
    UnverifiedFirebaseEmail,
    authenticate_bearer_token,
    require_authenticated_user,
)


VERIFIED = {
    "uid": "firebase-user-1",
    "email": "verified@example.com",
    "email_verified": True,
    "firebase": {"sign_in_provider": "password"},
    "roles": ["member"],
    "permissions": ["inquiry:read"],
}


class FixtureVerifier:
    """Test-only fixture; production defaults always use Firebase Admin."""

    def __init__(self, claims=None, error=None):
        self.claims = claims
        self.error = error
        self.received = None

    def verify(self, token):
        self.received = token
        if self.error:
            raise self.error
        return self.claims


class FirebaseAuthenticationTests(unittest.TestCase):
    def test_valid_verified_user(self):
        verifier = FixtureVerifier(VERIFIED)
        user = authenticate_bearer_token("Bearer real-client-token", verifier)
        self.assertEqual(user.uid, "firebase-user-1")
        self.assertTrue(user.email_verified)
        self.assertEqual(verifier.received, "real-client-token")
        self.assertEqual(require_authenticated_user(user).uid, user.uid)

    def test_unverified_email_user(self):
        user = authenticate_bearer_token(
            "Bearer token", FixtureVerifier({**VERIFIED, "email_verified": False}))
        with self.assertRaises(UnverifiedFirebaseEmail):
            require_authenticated_user(user)

    def test_missing_token(self):
        with self.assertRaises(MissingFirebaseToken):
            authenticate_bearer_token(None, FixtureVerifier(VERIFIED))

    def test_invalid_token(self):
        with self.assertRaises(InvalidFirebaseToken):
            authenticate_bearer_token(
                "Bearer invalid", FixtureVerifier(error=InvalidFirebaseToken("invalid")))

    def test_expired_token(self):
        with self.assertRaises(ExpiredFirebaseToken):
            authenticate_bearer_token(
                "Bearer expired", FixtureVerifier(error=ExpiredFirebaseToken("expired")))

    def test_unauthorized_user(self):
        user = authenticate_bearer_token("Bearer token", FixtureVerifier(VERIFIED))
        with self.assertRaises(UnauthorizedFirebaseUser):
            require_authenticated_user(user, required_permissions=frozenset({"admin:write"}))

    def test_google_authenticated_user_handling(self):
        claims = {**VERIFIED, "firebase": {"sign_in_provider": "google.com"}}
        user = authenticate_bearer_token("Bearer google-token", FixtureVerifier(claims))
        self.assertTrue(user.is_google_user)
        self.assertTrue(user.email_verified)

    def test_protected_action_denied_when_verification_required(self):
        user = authenticate_bearer_token(
            "Bearer token", FixtureVerifier({**VERIFIED, "email_verified": False}))
        with self.assertRaises(UnverifiedFirebaseEmail):
            require_authenticated_user(
                user, require_verified_email=True, required_roles=frozenset({"member"}))

    def test_production_verifier_reports_not_configured(self):
        with self.assertRaisesRegex(FirebaseAuthNotConfigured, "FIREBASE NOT CONFIGURED"):
            FirebaseTokenVerifier(project_id="").verify("token")


if __name__ == "__main__":
    unittest.main()
