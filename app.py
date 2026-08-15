"""HybridSecure Business Intake public web application."""

import json
import os
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError

from src.ai.intake_provider import AIProviderError, AIProviderNotConfigured, OllamaIntakeProvider
from src.business.intake import BusinessInquiry
from src.intake_workflow import BusinessIntakeWorkflow
from src.security.audit import AuditLogger
from src.security.authentication.firebase_auth import (
    ExpiredFirebaseToken,
    FirebaseAuthError,
    FirebaseAuthNotConfigured,
    FirebaseTokenVerifier,
    VerificationResendRateLimiter,
    authenticate_bearer_token,
    require_authenticated_user,
)
from src.security.authentication.verification_ticket import (
    VerificationTicketError,
    VerificationTicketNotConfigured,
    create_verification_ticket,
    verify_verification_ticket,
)
from src.security.controls import InMemoryRateLimiter
from src.security.intake_security import sanitize_inquiry

ROOT = Path(__file__).resolve().parent
AUDIT_PATH = Path(os.getenv("BUSINESS_INTAKE_AUDIT_LOG", ROOT / "logs" / "business_intake_audit.jsonl"))
if not AUDIT_PATH.is_absolute():
    AUDIT_PATH = ROOT / AUDIT_PATH

app = FastAPI(
    title="HybridSecure Business Intake",
    description="Secure AI-assisted business inquiry intake with mandatory human review.",
    docs_url=None,
    redoc_url=None,
)
workflow = BusinessIntakeWorkflow(
    OllamaIntakeProvider(),
    AuditLogger(AUDIT_PATH),
    InMemoryRateLimiter(int(os.getenv("BUSINESS_INTAKE_RATE_LIMIT", "5"))),
)
audit = workflow.audit
firebase_verifier = FirebaseTokenVerifier()
verification_resend_limiter = VerificationResendRateLimiter(
    int(os.getenv("FIREBASE_VERIFICATION_RESEND_SECONDS", "60")))


def firebase_client_config() -> dict[str, str]:
    mapping = {
        "apiKey": "FIREBASE_API_KEY", "authDomain": "FIREBASE_AUTH_DOMAIN",
        "projectId": "FIREBASE_PROJECT_ID", "storageBucket": "FIREBASE_STORAGE_BUCKET",
        "messagingSenderId": "FIREBASE_MESSAGING_SENDER_ID", "appId": "FIREBASE_APP_ID",
    }
    config = {key: os.getenv(env_name, "") for key, env_name in mapping.items()}
    required = ("apiKey", "authDomain", "projectId", "appId")
    if any(not config[key] for key in required):
        raise FirebaseAuthNotConfigured("FIREBASE NOT CONFIGURED")
    return config


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://www.gstatic.com; style-src 'self'; img-src 'self'; "
        "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com https://securetoken.googleapis.com; "
        "frame-src https://*.firebaseapp.com https://accounts.google.com; font-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/", include_in_schema=False)
def landing_page() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/assets/styles.css", include_in_schema=False)
def styles() -> FileResponse:
    return FileResponse(ROOT / "web" / "styles.css", media_type="text/css")


@app.get("/assets/firebase-integration.css", include_in_schema=False)
def firebase_styles() -> FileResponse:
    return FileResponse(ROOT / "web" / "firebase-integration.css", media_type="text/css")


@app.get("/assets/app.js", include_in_schema=False)
def javascript() -> FileResponse:
    return FileResponse(ROOT / "web" / "app.js", media_type="text/javascript")


@app.get("/assets/firebase-auth.js", include_in_schema=False)
def firebase_javascript() -> FileResponse:
    return FileResponse(ROOT / "web" / "firebase-auth.js", media_type="text/javascript")


@app.get("/api/firebase-config")
def get_firebase_config() -> JSONResponse:
    try:
        return JSONResponse(firebase_client_config())
    except FirebaseAuthNotConfigured:
        return JSONResponse({"error": "FIREBASE NOT CONFIGURED"}, status_code=503)


@app.get("/health")
def health() -> dict:
    ai_configured = bool(os.getenv("OLLAMA_BASE_URL") and os.getenv("OLLAMA_MODEL"))
    try:
        firebase_client_config()
        firebase_configured = bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GOOGLE_CLOUD_PROJECT"))
    except FirebaseAuthNotConfigured:
        firebase_configured = False
    return {"status": "available", "ai_provider_configured": ai_configured,
            "firebase_configured": firebase_configured, "external_actions_enabled": False}


@app.post("/api/inquiries/pending")
async def submit_pending_inquiry(request: Request) -> JSONResponse:
    """Validate an inquiry and record pending verification without invoking AI."""
    try:
        firebase_client_config()
        payload = await _read_json_payload(request)
        inquiry = sanitize_inquiry(BusinessInquiry.model_validate(payload))
        request_id = str(uuid4())
        verification_ticket = create_verification_ticket(request_id, str(inquiry.email))
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="inquiry_submitted", validation_result="passed",
                    verification_status="pending", decision="EMAIL_VERIFICATION_PENDING",
                    execution_result="no_protected_processing")
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="verification_pending", verification_status="pending",
                    decision="EMAIL_VERIFICATION_PENDING", execution_result="no_external_action")
        return JSONResponse({"request_id": request_id, "verification_ticket": verification_ticket,
                             "email": str(inquiry.email),
                             "state": "EMAIL_VERIFICATION_PENDING",
                             "message": "Check your email to verify ownership before processing continues.",
                             "external_action": False}, status_code=202)
    except FirebaseAuthNotConfigured:
        return JSONResponse({"error": "FIREBASE NOT CONFIGURED", "state": "FAILED",
                             "external_action": False}, status_code=503)
    except VerificationTicketNotConfigured:
        return JSONResponse({"error": "VERIFICATION SECURITY NOT CONFIGURED", "state": "FAILED",
                             "external_action": False}, status_code=503)
    except RequestSizeError:
        return _json_error("Inquiry request is too large", 413)
    except json.JSONDecodeError:
        return _json_error("Request body must be valid JSON", 400)
    except ValidationError as exc:
        return _validation_error(exc)


@app.post("/api/inquiries/{request_id}/verification-events")
async def verification_event(request_id: str, request: Request) -> JSONResponse:
    """Record non-secret verification lifecycle events; never accepts a token."""
    try:
        UUID(request_id)
        payload = await _read_json_payload(request, maximum=2_048)
        event = payload.get("event")
        ticket = str(payload.get("verification_ticket", ""))
        email = str(payload.get("email", ""))
        verify_verification_ticket(ticket, request_id, email)
        allowed = {"verification_sent", "verification_failure", "resend_request"}
        if event not in allowed:
            return _json_error("Unsupported verification event", 400)
        if event == "resend_request":
            client_id = request.client.host if request.client else "unknown"
            verification_resend_limiter.check(f"{client_id}:{request_id}")
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake", event=event,
                    verification_status="pending" if event != "verification_failure" else "failed",
                    execution_result="no_protected_processing")
        return JSONResponse({"recorded": True, "resend_allowed": event == "resend_request"})
    except RequestSizeError:
        return _json_error("Verification event request is too large", 413)
    except (VerificationTicketError, VerificationTicketNotConfigured):
        return JSONResponse({"error": "Verification request is invalid or expired"}, status_code=401)
    except (ValueError, json.JSONDecodeError):
        return _json_error("Invalid verification event request", 400)
    except PermissionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=429)


@app.post("/api/inquiries")
async def submit_inquiry(request: Request) -> JSONResponse:
    try:
        payload = await _read_json_payload(request)
        request_id = str(payload.pop("request_id", ""))
        verification_ticket = str(payload.pop("verification_ticket", ""))
        UUID(request_id)
        user = authenticate_bearer_token(request.headers.get("authorization"), firebase_verifier)
        require_authenticated_user(user, require_verified_email=True)
        inquiry = BusinessInquiry.model_validate(payload)
        if not user.email or user.email.casefold() != str(inquiry.email).casefold():
            raise FirebaseAuthError("Verified Firebase email does not match inquiry email")
        verify_verification_ticket(verification_ticket, request_id, str(inquiry.email))
        client_id = request.client.host if request.client else "unknown"
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="verification_success", verification_status="verified",
                    firebase_uid=user.uid, sign_in_provider=user.sign_in_provider,
                    execution_result="no_external_action")
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="protected_workflow_started", authentication_result="verified",
                    verification_status="verified", execution_result="started")
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="ai_analysis_started", authentication_result="verified",
                    execution_result="started")
        result = workflow.process(payload, client_id, request_id=request_id,
                                  authentication_result="firebase_verified")
        audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                    event="human_review_state", verification_status="verified",
                    approval_state="HUMAN_REVIEW_REQUIRED", decision=result.state.value,
                    execution_result="no_external_action")
        return JSONResponse(result.model_dump(mode="json"), status_code=200)
    except FirebaseAuthNotConfigured:
        return JSONResponse({"error": "FIREBASE NOT CONFIGURED", "state": "FAILED",
                             "external_action": False}, status_code=503)
    except ExpiredFirebaseToken:
        audit.write(workflow="hybridsecure_business_intake", event="verification_failure",
                    verification_status="expired", execution_result="no_protected_processing")
        return JSONResponse({"error": "Firebase ID token expired", "state": "EMAIL_VERIFICATION_PENDING",
                             "external_action": False}, status_code=401)
    except FirebaseAuthError:
        audit.write(workflow="hybridsecure_business_intake", event="verification_failure",
                    verification_status="failed", execution_result="no_protected_processing")
        return JSONResponse({"error": "Verified Firebase identity is required", "state": "EMAIL_VERIFICATION_PENDING",
                             "external_action": False}, status_code=401)
    except VerificationTicketNotConfigured:
        return JSONResponse({"error": "VERIFICATION SECURITY NOT CONFIGURED", "state": "FAILED",
                             "external_action": False}, status_code=503)
    except VerificationTicketError:
        return JSONResponse({"error": "Verification request is invalid or expired",
                             "state": "EMAIL_VERIFICATION_PENDING", "external_action": False}, status_code=401)
    except RequestSizeError:
        return _json_error("Inquiry request is too large", 413)
    except ValueError:
        return _json_error("Inquiry request ID is invalid", 400)
    except AIProviderNotConfigured:
        return JSONResponse({"error": "AI PROVIDER NOT CONFIGURED",
                             "state": "REVIEW_REQUIRED", "external_action": False}, status_code=503)
    except json.JSONDecodeError:
        return _json_error("Request body must be valid JSON", 400)
    except ValidationError as exc:
        return _validation_error(exc)
    except PermissionError:
        return JSONResponse({"error": "Rate limit exceeded. Please try again later.",
                             "state": "FAILED", "external_action": False}, status_code=429)
    except AIProviderError:
        return JSONResponse({"error": "AI analysis failed; human review is required",
                             "state": "REVIEW_REQUIRED", "external_action": False}, status_code=502)
    except Exception:
        return JSONResponse({"error": "The inquiry could not be processed safely.",
                             "state": "FAILED", "external_action": False}, status_code=500)


async def _read_json_payload(request: Request, maximum: int = 16_384) -> dict:
    try:
        declared_size = int(request.headers.get("content-length", "0"))
    except ValueError as exc:
        raise json.JSONDecodeError("invalid content length", "", 0) from exc
    if declared_size > maximum:
        raise RequestSizeError()
    body = await request.body()
    if len(body) > maximum:
        raise RequestSizeError()
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise json.JSONDecodeError("object required", body.decode("utf-8", errors="ignore"), 0)
    return payload


class RequestSizeError(ValueError):
    pass


def _json_error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": message, "state": "FAILED", "external_action": False},
                        status_code=status_code)


def _validation_error(exc: ValidationError) -> JSONResponse:
    errors = [{"field": ".".join(map(str, item["loc"])), "message": item["msg"]} for item in exc.errors()]
    return JSONResponse({"error": "Inquiry validation failed", "details": errors,
                         "state": "FAILED", "external_action": False}, status_code=422)
