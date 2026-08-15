"""Short-lived signed tickets binding pending inquiries to verified email ownership."""

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


class VerificationTicketError(PermissionError):
    pass


class VerificationTicketNotConfigured(RuntimeError):
    pass


@dataclass(frozen=True)
class VerificationTicket:
    request_id: str
    email: str
    expires_at: int


def create_verification_ticket(request_id: str, email: str) -> str:
    key = _signing_key()
    ttl = int(os.getenv("INTAKE_VERIFICATION_TICKET_SECONDS", "1800"))
    payload = {"request_id": request_id, "email": email.casefold(), "expires_at": int(time.time()) + ttl}
    encoded = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _encode(hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def verify_verification_ticket(ticket: str, request_id: str, email: str) -> VerificationTicket:
    key = _signing_key()
    try:
        encoded, supplied_signature = ticket.split(".", 1)
        expected = _encode(hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_signature, expected):
            raise VerificationTicketError("Verification ticket is invalid")
        payload = json.loads(_decode(encoded))
        result = VerificationTicket(**payload)
    except VerificationTicketError:
        raise
    except Exception as exc:
        raise VerificationTicketError("Verification ticket is invalid") from exc
    if result.expires_at < int(time.time()):
        raise VerificationTicketError("Verification ticket expired")
    if result.request_id != request_id or result.email != email.casefold():
        raise VerificationTicketError("Verification ticket does not match inquiry")
    return result


def _signing_key() -> bytes:
    value = os.getenv("INTAKE_VERIFICATION_SIGNING_KEY", "")
    if len(value) < 32:
        raise VerificationTicketNotConfigured("VERIFICATION SECURITY NOT CONFIGURED")
    return value.encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
