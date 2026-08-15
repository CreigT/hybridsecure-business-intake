"""Secure Project #1 orchestration. No external-action capability exists."""

from uuid import uuid4

from pydantic import ValidationError

from src.ai.intake_provider import AIProviderError, AIProviderNotConfigured, IntakeAIResult
from src.business.intake import BusinessInquiry, IntakeResult, WorkflowState, decide_state
from src.security.audit import AuditLogger
from src.security.controls import InMemoryRateLimiter
from src.security.intake_security import assess_risk, sanitize_inquiry


class BusinessIntakeWorkflow:
    def __init__(self, provider, audit: AuditLogger, limiter: InMemoryRateLimiter) -> None:
        self.provider = provider
        self.audit = audit
        self.limiter = limiter

    def process(self, payload: dict, client_id: str, request_id: str | None = None,
                authentication_result: str = "not_applicable_reference_workflow") -> IntakeResult:
        request_id = request_id or str(uuid4())
        stages = {name: "neutral" for name in (
            "Inquiry Received", "Security Check", "AI Analysis", "Response Drafted", "Human Review", "Audit Logged")}
        try:
            self.limiter.check(client_id)
            inquiry = sanitize_inquiry(BusinessInquiry.model_validate(payload))
            stages["Inquiry Received"] = "complete"
            assessment = assess_risk(inquiry)
            stages["Security Check"] = "complete"
            if assessment.risk.value == "CRITICAL":
                state = WorkflowState.REVIEW_REQUIRED
                result = IntakeResult(request_id=request_id, state=state, risk=assessment.risk.value,
                                      message="This inquiry requires security review. No external action occurred.", stages=stages)
            else:
                ai = IntakeAIResult.model_validate(self.provider.analyze(inquiry))
                stages["AI Analysis"] = "complete"
                state = decide_state(assessment.risk.value, ai.confidence)
                stages["Response Drafted"] = "complete"
                stages["Human Review"] = "required"
                result = IntakeResult(request_id=request_id, state=state, risk=assessment.risk.value,
                                      confidence=ai.confidence, intent=ai.intent, urgency=ai.urgency,
                                      summary=ai.summary, missing_information=ai.missing_information,
                                      response_draft=ai.response_draft,
                                      message="Draft ready for human review. No message was sent.", stages=stages)
            stages["Audit Logged"] = "complete"
            self.audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                             authentication_result=authentication_result, validation_result="passed",
                             security_findings=list(assessment.findings), risk_level=assessment.risk.value,
                             ai_confidence=result.confidence, decision=result.state.value,
                             approval_state="HUMAN_REVIEW_REQUIRED", execution_result="no_external_action")
            result.stages = stages
            return result
        except AIProviderNotConfigured as exc:
            stages["AI Analysis"] = "failed"
            self._audit_failure(request_id, stages, "AI_PROVIDER_NOT_CONFIGURED", exc)
            raise
        except (ValidationError, PermissionError, AIProviderError, ValueError) as exc:
            self._audit_failure(request_id, stages, "FAILED", exc)
            raise

    def _audit_failure(self, request_id: str, stages: dict[str, str], decision: str, exc: Exception) -> None:
        self.audit.write(request_id=request_id, workflow="hybridsecure_business_intake",
                         validation_result="failed" if isinstance(exc, ValidationError) else "unknown",
                         security_findings=[], risk_level="UNKNOWN", ai_confidence=None,
                         decision=decision, approval_state="HUMAN_REVIEW_REQUIRED",
                         error=type(exc).__name__, security_event=str(exc), execution_result="no_external_action")
