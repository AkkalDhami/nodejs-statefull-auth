import {
  changePassword,
  deleteAccount,
  deleteSession,
  deleteSessions,
  deleteSingleSession,
  deleteUserSessions,
  getAllUserSessions,
  getGoogleAuthConsentScreen,
  getUserProfile,
  getUserSessions,
  googleAuthCallbackHandler,
  googleSignin,
  logout,
  reactivateAccount,
  resetPassword,
  signinUser,
  signupUser,
  updateProfile,
} from "#controllers/auth.controller.js";
import { sendOtp, verifyOtp } from "#controllers/otp.controller.js";
import {
  changePasswordLimiter,
  deleteAccountLimiter,
  otpRequestLimiter,
  otpVerificationLimiter,
  resetPasswordLimiter,
  signinLimiter,
  signupLimiter,
} from "#lib/rate-limiter.js";
import { checkEmailRestriction } from "#middlewares/check-email-restriction.js";
import upload from "#middlewares/upload-file.js";
import {
  authorizeRoles,
  isAuthenticated,
} from "#middlewares/verify-authentication.js";
import { Router } from "express";

const router = Router();

router.get("/profile", isAuthenticated, getUserProfile);
router.get(
  "/sessions",
  isAuthenticated,
  checkEmailRestriction,
  getUserSessions
);

router.post("/signup", signupLimiter, signupUser);
router.post("/signin", signinLimiter, signinUser);

router.post("/request-otp", otpRequestLimiter, sendOtp);
router.post("/verify-otp", otpVerificationLimiter, verifyOtp);

router.post("/reset-password", resetPasswordLimiter, resetPassword);
router.post(
  "/change-password",
  isAuthenticated,
  checkEmailRestriction,
  changePasswordLimiter,
  changePassword
);

router.patch(
  "/update-profile",
  upload.single("avatar"),
  isAuthenticated,
  checkEmailRestriction,
  updateProfile
);

router.post("/google-signin", googleSignin);
router.get("/google", getGoogleAuthConsentScreen);
router.get("/google/callback", googleAuthCallbackHandler);

router.post("/logout", isAuthenticated, checkEmailRestriction, logout);

router.delete(
  "/delete-account",
  isAuthenticated,
  checkEmailRestriction,
  deleteAccountLimiter,
  deleteAccount
);
router.put("/reactivate-account", isAuthenticated, reactivateAccount);

router.delete("/sessions/:sessionId", isAuthenticated, deleteSession);
router.delete("/sessions", isAuthenticated, deleteSessions);

router.get(
  "/admin/sessions",
  isAuthenticated,
  authorizeRoles("admin"),
  getAllUserSessions
);
router.delete(
  "/admin/sessions/users/:userId",
  isAuthenticated,
  authorizeRoles("admin"),
  deleteUserSessions
);
router.delete(
  "/admin/sessions/:sessionId",
  isAuthenticated,
  authorizeRoles("admin"),
  deleteSingleSession
);

export default router;
