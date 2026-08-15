"""Deterministic intake sanitation, sensitive-data detection, and risk policy."""

import html
import re
from dataclasses import dataclass

from config.tools_registry import RiskLevel
from src.business.intake import BusinessInquiry


INJECTION_HIGH = (
    "ignore previous instructions", "reveal your system prompt", "send this immediately",
    "give yourself administrator access", "impersonate authorization", "financial commitment",
    "legal promise",
)
INJECTION_CRITICAL = (
    "read environment variables", "disable security", "execute this command", "execute arbitrary code",
    "access secrets", "delete all", "change permissions", "bypass approval",
)
SENSITIVE_PATTERNS = {
    "credential": re.compile(r"(?i)\b(password|passwd|api[_ -]?key|access[_ -]?token|auth[_ -]?token|token|secret)\s*[:=]\s*\S+"),
    "payment_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


@dataclass(frozen=True)
class SecurityAssessment:
    risk: RiskLevel
    findings: tuple[str, ...]


def sanitize_text(value: str) -> str:
    """Normalize control characters and escape markup before later UI rendering."""
    normalized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).strip()
    return html.escape(normalized, quote=True)


def sanitize_inquiry(inquiry: BusinessInquiry) -> BusinessInquiry:
    data = inquiry.model_dump()
    for field in ("full_name", "company", "phone", "service_needed", "message"):
        if data.get(field) is not None:
            data[field] = sanitize_text(data[field])
    return BusinessInquiry.model_validate(data)


def assess_risk(inquiry: BusinessInquiry) -> SecurityAssessment:
    text = " ".join(filter(None, [inquiry.full_name, inquiry.company, inquiry.phone,
                                   inquiry.service_needed, inquiry.message])).lower()
    findings: list[str] = []
    risk = RiskLevel.LOW
    for name, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(text):
            findings.append(f"sensitive_data:{name}")
            risk = RiskLevel.HIGH
    if any(phrase in text for phrase in INJECTION_HIGH):
        findings.append("prompt_injection_attempt")
        risk = max(risk, RiskLevel.HIGH, key=_risk_rank)
    if any(phrase in text for phrase in INJECTION_CRITICAL):
        findings.append("critical_control_bypass_attempt")
        risk = RiskLevel.CRITICAL
    return SecurityAssessment(risk, tuple(findings))


def _risk_rank(risk: RiskLevel) -> int:
    return [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL].index(risk)


def redact(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_PATTERNS.values():
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
