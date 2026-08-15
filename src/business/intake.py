"""Business contracts and deterministic workflow decisions for Project #1."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class WorkflowState(StrEnum):
    EMAIL_VERIFICATION_PENDING = "EMAIL_VERIFICATION_PENDING"
    REJECTED = "REJECTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DRAFT_READY = "DRAFT_READY"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class BusinessInquiry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    company: str = Field(min_length=2, max_length=150)
    phone: str | None = Field(default=None, max_length=30)
    service_needed: str = Field(min_length=2, max_length=100)
    message: str = Field(min_length=20, max_length=4000)


class IntakeResult(BaseModel):
    request_id: str
    state: WorkflowState
    risk: str
    confidence: float | None = None
    intent: str | None = None
    urgency: str | None = None
    summary: str | None = None
    missing_information: list[str] = Field(default_factory=list)
    response_draft: str | None = None
    message: str
    stages: dict[str, str]


def decide_state(risk: str, confidence: float) -> WorkflowState:
    """Risk overrides confidence; AI cannot approve itself."""
    if risk == "CRITICAL":
        return WorkflowState.REVIEW_REQUIRED
    if risk != "LOW" or confidence < 0.85:
        return WorkflowState.REVIEW_REQUIRED
    return WorkflowState.DRAFT_READY
