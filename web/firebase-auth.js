/**
 * Reusable Firebase Authentication browser module.
 * Production code calls the real Firebase Web SDK; no verified state is synthesized.
 */
import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-app.js";
import {
  getAuth,
  GoogleAuthProvider,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  sendEmailVerification,
  sendPasswordResetEmail,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  onAuthStateChanged,
  signOut,
} from "https://www.gstatic.com/firebasejs/12.2.1/firebase-auth.js";

const REQUIRED_KEYS = ["apiKey", "authDomain", "projectId", "appId"];

export class FirebaseNotConfiguredError extends Error {
  constructor() { super("FIREBASE NOT CONFIGURED"); }
}

export function createFirebaseAuth(config, { verificationResendSeconds = 60 } = {}) {
  if (!config || REQUIRED_KEYS.some((key) => !config[key])) throw new FirebaseNotConfiguredError();
  const app = getApps().length ? getApps()[0] : initializeApp(config);
  const auth = getAuth(app);
  const googleProvider = new GoogleAuthProvider();
  let lastVerificationSentAt = 0;

  const requireCurrentUser = () => {
    if (!auth.currentUser) throw new Error("Authentication required");
    return auth.currentUser;
  };

  return Object.freeze({
    auth,
    observe: (callback) => onAuthStateChanged(auth, (user) => callback(user ? {
      uid: user.uid,
      email: user.email,
      emailVerified: user.emailVerified,
      providerIds: user.providerData.map((entry) => entry.providerId),
    } : null)),
    signUpWithEmail: async (email, password) => {
      const credential = await createUserWithEmailAndPassword(auth, email, password);
      await sendEmailVerification(credential.user);
      lastVerificationSentAt = Date.now();
      return credential.user;
    },
    signInWithEmail: (email, password) => signInWithEmailAndPassword(auth, email, password),
    signInWithGoogle: ({ redirect = false } = {}) => redirect
      ? signInWithRedirect(auth, googleProvider)
      : signInWithPopup(auth, googleProvider),
    resendVerificationEmail: async () => {
      const elapsed = Date.now() - lastVerificationSentAt;
      if (elapsed < verificationResendSeconds * 1000) {
        throw new Error(`Verification email can be resent in ${Math.ceil((verificationResendSeconds * 1000 - elapsed) / 1000)} seconds`);
      }
      const user = requireCurrentUser();
      if (user.emailVerified) throw new Error("Email is already verified");
      await sendEmailVerification(user);
      lastVerificationSentAt = Date.now();
    },
    sendPasswordReset: (email) => sendPasswordResetEmail(auth, email),
    sendEmailLink: (email, actionCodeSettings) => sendSignInLinkToEmail(auth, email, actionCodeSettings),
    completeEmailLink: (email, currentUrl = window.location.href) => {
      if (!isSignInWithEmailLink(auth, currentUrl)) throw new Error("Invalid Firebase email sign-in link");
      return signInWithEmailLink(auth, email, currentUrl);
    },
    getIdToken: (forceRefresh = true) => requireCurrentUser().getIdToken(forceRefresh),
    verificationStatus: () => ({
      signedIn: Boolean(auth.currentUser),
      emailVerified: auth.currentUser?.emailVerified === true,
    }),
    signOut: () => signOut(auth),
  });
}
