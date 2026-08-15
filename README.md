# HybridSecure Business Intake

HybridSecure Business Intake is a standalone, security-first public intake application for collecting and reviewing business inquiries. It validates untrusted input, verifies user identity through Firebase Authentication, applies deterministic risk policy, requests a structured recommendation from a configured local Ollama model, and keeps human review in control.

AI recommends. Policy evaluates. Humans authorize final business actions.

Sponsored by CREIGNIFICENT LLC.

## Current capabilities

- Responsive public intake form with email verification controls.
- Server-side Pydantic validation, sanitization, request-size limits, rate limiting, and security headers.
- Firebase ID-token verification using the server-side Firebase Admin SDK.
- Real local Ollama integration with validated structured output and fail-closed behavior.
- Structured, redacted JSONL audit events.
- No automated customer message delivery, payment processing, or unrestricted AI tool execution.

## Local setup

Requirements: Python 3.12+, a Firebase project, and an Ollama service with an installed model.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env.local
python scripts/run_business_intake.py
```

Environment files are not loaded automatically by the application. Load `.env.local` through your shell, process manager, container platform, or approved secret manager before starting it. Open `http://127.0.0.1:8000`.

## Configuration

See `.env.example`. Required production settings include the Ollama endpoint/model, Firebase client identifiers, Firebase Admin credentials or workload identity, and a random `INTAKE_VERIFICATION_SIGNING_KEY` of at least 32 characters. Never commit credentials or service-account JSON.

The application owns route `/`, API namespace `/api/inquiries`, audit namespace `hybridsecure_business_intake`, and local audit path `logs/business_intake_audit.jsonl`.

## Tests

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app.py config src scripts tests
```

## Docker deployment

Build with `docker build -t hybridsecure-business-intake .` or configure the required environment and credential mount before running `docker compose up --build`. Terminate TLS at a trusted reverse proxy, restrict `FORWARDED_ALLOW_IPS`, and replace the process-local limiter/local audit file before horizontal scaling.

This repository does not provision Firebase, Ollama, TLS, a domain, or production infrastructure. Deployment is not claimed until those real services are configured and verified.
