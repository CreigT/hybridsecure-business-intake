import { createFirebaseAuth, FirebaseNotConfiguredError } from "/assets/firebase-auth.js";

const STORAGE_KEY = "hybridsecure_pending_inquiry_v1";
const form = document.querySelector("#intake-form");
const alertBox = document.querySelector("#form-alert");
const resultPanel = document.querySelector("#result-panel");
const verificationPanel = document.querySelector("#verification-panel");
const verificationAlert = document.querySelector("#verification-alert");
const submitButton = form.querySelector('button[type="submit"]');
let firebaseAuth;

function updateStages(stages = {}) {
  document.querySelectorAll("#workflow-stages li").forEach((item) => {
    const state = stages[item.dataset.stage] || "neutral";
    item.className = state;
    item.querySelector("em").textContent = state === "complete" ? "Complete" : state === "required" ? "Required" : state === "failed" ? "Failed" : state === "pending" ? "Pending" : "Waiting";
  });
}

function showResult(data) {
  document.querySelector("#overall-status").textContent = data.state.replaceAll("_", " ");
  document.querySelector("#result-state").textContent = data.state.replaceAll("_", " ");
  document.querySelector("#result-message").textContent = data.message;
  const details = document.querySelector("#result-details");
  details.replaceChildren();
  [["Request ID", data.request_id], ["Risk", data.risk], ["Confidence", data.confidence == null ? "Not available" : `${Math.round(data.confidence * 100)}%`], ["Intent", data.intent], ["Urgency", data.urgency], ["Summary", data.summary], ["Response draft", data.response_draft]].forEach(([label, value]) => {
    if (!value) return;
    const dt = document.createElement("dt"); const dd = document.createElement("dd");
    dt.textContent = label; dd.textContent = value; details.append(dt, dd);
  });
  updateStages({...data.stages, "Email Verification": "complete"});
  verificationPanel.hidden = true;
  resultPanel.hidden = false;
}

async function loadFirebase() {
  if (firebaseAuth) return firebaseAuth;
  const response = await fetch("/api/firebase-config");
  const config = await response.json();
  if (!response.ok) throw new FirebaseNotConfiguredError();
  firebaseAuth = createFirebaseAuth(config, {verificationResendSeconds: 60});
  return firebaseAuth;
}

function getPending() {
  try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY)); } catch { return null; }
}

function showVerification(pending) {
  form.hidden = true;
  resultPanel.hidden = true;
  verificationPanel.hidden = false;
  document.querySelector("#verification-email").textContent = pending.inquiry.email;
  document.querySelector("#overall-status").textContent = "EMAIL VERIFICATION PENDING";
  updateStages({"Inquiry Received": "complete", "Email Verification": "pending"});
}

async function recordVerificationEvent(pending, event) {
  const response = await fetch(`/api/inquiries/${pending.request_id}/verification-events`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({event, verification_ticket: pending.verification_ticket, email: pending.inquiry.email}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Verification request failed");
  return data;
}

async function sendVerificationLink(pending, isResend = false) {
  const client = await loadFirebase();
  if (isResend) await recordVerificationEvent(pending, "resend_request");
  const actionUrl = `${window.location.origin}${window.location.pathname}?verifyInquiry=1`;
  await client.sendEmailLink(pending.inquiry.email, {url: actionUrl, handleCodeInApp: true});
  await recordVerificationEvent(pending, "verification_sent");
}

async function continueProtectedWorkflow(pending, user) {
  if (!user?.emailVerified) throw new Error("Firebase has not verified this email yet");
  const token = await firebaseAuth.getIdToken(true);
  const response = await fetch("/api/inquiries", {
    method: "POST",
    headers: {"Content-Type": "application/json", "Authorization": `Bearer ${token}`},
    body: JSON.stringify({...pending.inquiry, request_id: pending.request_id,
                          verification_ticket: pending.verification_ticket}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Protected inquiry processing failed");
  sessionStorage.removeItem(STORAGE_KEY);
  showResult(data);
}

async function completeEmailLinkIfPresent() {
  const pending = getPending();
  if (!pending || !window.location.search.includes("verifyInquiry=1")) return;
  try {
    const client = await loadFirebase();
    const credential = await client.completeEmailLink(pending.inquiry.email);
    await continueProtectedWorkflow(pending, credential.user);
    history.replaceState({}, "", window.location.pathname);
  } catch (error) {
    showVerification(pending);
    verificationAlert.textContent = error.message || "The verification link is invalid or expired. Request a new link.";
    verificationAlert.hidden = false;
    await recordVerificationEvent(pending, "verification_failure").catch(() => {});
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault(); alertBox.hidden = true; resultPanel.hidden = true;
  if (!form.reportValidity()) return;
  submitButton.disabled = true; submitButton.textContent = "Preparing verification…";
  const inquiry = Object.fromEntries(new FormData(form));
  delete inquiry.acknowledgement;
  if (!inquiry.phone) inquiry.phone = null;
  try {
    await loadFirebase();
    const response = await fetch("/api/inquiries/pending", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(inquiry),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The inquiry could not enter verification.");
    const pending = {request_id: data.request_id, verification_ticket: data.verification_ticket, inquiry};
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(pending));
    await sendVerificationLink(pending);
    showVerification(pending);
  } catch (error) {
    alertBox.textContent = error.message || "The inquiry could not be processed.";
    alertBox.hidden = false;
    document.querySelector("#overall-status").textContent = "Needs attention";
  } finally {
    submitButton.disabled = false; submitButton.innerHTML = 'Submit Secure Inquiry <span aria-hidden="true">→</span>';
  }
});

document.querySelector("#resend-verification").addEventListener("click", async () => {
  const pending = getPending();
  if (!pending) return;
  verificationAlert.hidden = true;
  try {
    await sendVerificationLink(pending, true);
    verificationAlert.textContent = "A new verification email was sent.";
    verificationAlert.hidden = false;
  } catch (error) {
    verificationAlert.textContent = error.message;
    verificationAlert.hidden = false;
  }
});

document.querySelector("#google-verification").addEventListener("click", async () => {
  const pending = getPending();
  if (!pending) return;
  verificationAlert.hidden = true;
  try {
    const client = await loadFirebase();
    const credential = await client.signInWithGoogle({redirect: false});
    await continueProtectedWorkflow(pending, credential.user);
  } catch (error) {
    verificationAlert.textContent = error.message;
    verificationAlert.hidden = false;
    await recordVerificationEvent(pending, "verification_failure").catch(() => {});
  }
});

document.querySelector("#change-email").addEventListener("click", () => {
  sessionStorage.removeItem(STORAGE_KEY);
  verificationPanel.hidden = true;
  form.hidden = false;
  form.querySelector('input[name="email"]').focus();
  updateStages();
  document.querySelector("#overall-status").textContent = "Not started";
});

const pendingAtLoad = getPending();
if (pendingAtLoad) showVerification(pendingAtLoad);
completeEmailLinkIfPresent();
