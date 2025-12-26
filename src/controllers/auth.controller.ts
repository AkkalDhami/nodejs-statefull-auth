import { env } from "#configs/env.js";
import googleClient from "#configs/google.js";
import {
  LOCK_TIME_MS,
  LOGIN_MAX_ATTEMPTS,
  NEXT_OTP_DELAY,
  OTP_CODE_EXPIRY,
  OTP_CODE_LENGTH,
  REACTIVATION_AVAILABLE_AT,
} from "#constants/auth-constants.js";
import { STATUS_CODES } from "#constants/status-codes.js";
import {
  generateOtp,
  generateRandomToken,
  hashPassword,
  verifyPassword,
} from "#helpers/auth-helper.js";
import { clearAuthCookies } from "#helpers/cookie-helper.js";

import cloudinary from "#lib/cloudinary.js";
import { sendEmail } from "#lib/node-mailer.js";
import Otp from "#models/otp.model.js";
import Session from "#models/session.model.js";
import { User } from "#models/user.model.js";
import { AuthenticatedRequest } from "#types/user.js";
import { ApiError } from "#utils/api-error.js";
import { ApiResponse } from "#utils/api-response.js";
import { AsyncHandler } from "#utils/async-handler.js";
import { logger } from "#utils/logger.js";
import {
  ChangePasswordSchema,
  DeleteAccountSchema,
  GoogleSigninSchema,
  ResetPasswordSchema,
  SigninSchema,
  SignupSchema,
  UpdateProfileSchema,
} from "#validators/auth.js";
import { NextFunction, Request, Response } from "express";
import mongoose from "mongoose";
import z from "zod";

//? SIGNUP USER
export const signupUser = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = SignupSchema.safeParse(req.body);
    console.log(req.body);
    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { name, email, password, role } = data;
    if (!name || !email || !password) {
      return ApiResponse.BadRequest(
        res,
        "Name, email and password are required"
      );
    }

    const existingUser = await User.findOne({ email }).select("+password");

    if (existingUser) {
      return ApiResponse.Conflict(res, "User with this email already exists");
    }

    const hashedPassword = await hashPassword(password);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role,
    });

    if (!newUser) {
      return ApiResponse.BadRequest(res, "Failed to register user!");
    }

    await newUser.save();

    return ApiResponse.Created(res, "User registered successfully", {
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    });
  }
);

//? SIGNIN USER
export const signinUser = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = SigninSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { email, password } = data;
    if (!email || !password) {
      return ApiResponse.BadRequest(res, "Email and password are required");
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return ApiResponse.BadRequest(res, "Invalid credentials!");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    const isPasswordValid = await verifyPassword(password, user.password);

    if (!isPasswordValid) {
      let lockUntil = null;

      let newAttempts = user.failedLoginAttempts + 1;

      if (newAttempts >= LOGIN_MAX_ATTEMPTS) {
        lockUntil = new Date(Date.now() + LOCK_TIME_MS);
      }

      await User.updateOne(
        { _id: user._id },
        { $set: { failedLoginAttempts: newAttempts, lockUntil } }
      );
      return ApiResponse.BadRequest(res, "Invalid credentials!");
    }

    await User.updateOne(
      { _id: user._id },
      { $set: { failedLoginAttempts: 0, lockUntil: null } }
    );

    const otp = generateOtp(OTP_CODE_LENGTH, OTP_CODE_EXPIRY);
    logger.info(`Generated OTP:  ${otp.code}`);

    const existingOtp = await Otp.findOne({ email });
    if (existingOtp && new Date(existingOtp.nextResendAllowedAt) > new Date()) {
      const remainingSec = Math.ceil(
        (existingOtp.nextResendAllowedAt.getTime() - Date.now()) / 1000
      );
      return ApiResponse.BadRequest(
        res,
        `Please wait for ${remainingSec} seconds before sending another OTP`
      );
    }

    const nextResendAllowedAt = new Date(Date.now() + NEXT_OTP_DELAY);

    const newOtp = new Otp({
      email,
      otpType: "email-verification",
      otpHashCode: otp.hashCode,
      attempts: 0,
      isVerified: false,
      expiresAt: otp.expiresAt,
      nextResendAllowedAt,
    });
    await newOtp.save();

    if (!newOtp) {
      return ApiResponse.BadRequest(res, "Failed to send OTP");
    }

    if (existingOtp) {
      existingOtp.nextResendAllowedAt = nextResendAllowedAt;
      await existingOtp.save();
    }

    const html = `<p>OTP: ${otp.code}</p>`;
    // await sendEmail(email, `OTP for email verification`, html);

    return ApiResponse.Ok(res, `OTP sent to ${email}`);
  }
);

//? GET GOOLGE CONSENT SCREEN
export const getGoogleAuthConsentScreen = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const url = googleClient.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
      redirect_uri: env.GOOGLE_REDIRECT_URI,
    });

    return res.redirect(url);
  }
);

//? GOOGLE AUTH CALLBACK HANDLER
export const googleAuthCallbackHandler = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const code = req.query.code as string | undefined;
    if (!code) {
      return ApiResponse.BadRequest(res, "Missing google code in the callback");
    }

    const { tokens } = await googleClient.getToken(code);
    console.log({ tokens });

    if (!tokens.id_token) {
      return ApiResponse.BadRequest(res, "Google IdToken is required!");
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: env.GOOGLE_CLIENT_ID,
      maxExpiry: 600,
    });

    const payload = ticket.getPayload();
    console.log({ payload });
    const email = payload?.email;
    const isEmailVerified = payload?.email_verified;

    if (!email || !isEmailVerified) {
      return ApiResponse.BadRequest(res, "Please verify your google email!");
    }

    const user = await User.findOne({ email });

    if (user) {
      if (!user.isEmailVerified) {
        await User.findOneAndUpdate(
          {
            email: email,
          },
          {
            $set: { isEmailVerified: true },
          }
        );
      }

      return ApiResponse.Ok(res, "User signed in successfully!");
    } else {
      const newUser = new User({
        name: payload.name,
        email,
        isEmailVerified,
        provider: "google",
        providerId: payload?.sub,
        avatar: { url: payload.picture },
      });
      await newUser.save();
      return ApiResponse.Success(res, "User signed in successfully!", {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
        lastLoginAt: newUser.lastLoginAt,
        lockUntil: newUser.lockUntil,
      });
    }
  }
);

//? GOOGLE SIGNIN
export const googleSignin = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = GoogleSigninSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { name, email, provider, providerId, avatar } = data;

    const user = await User.findOne({ email });

    if (user) {
      return ApiResponse.Success(res, "User signed in successfully!", {
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        lastLoginAt: user.lastLoginAt,
        lockUntil: user.lockUntil,
      });
    } else {
      const newUser = new User({
        name,
        email,
        provider,
        providerId,
        avatar,
      });
      await newUser.save();
      return ApiResponse.Success(res, "User signed in successfully!", {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
        lastLoginAt: newUser.lastLoginAt,
        lockUntil: newUser.lockUntil,
      });
    }
  }
);

//? GET USER PROFILE
export const getUserProfile = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    console.log({ session: req.user });
    const userId = req.user?._id.toString();
    if (!userId) {
      return ApiResponse.NotFound(res, "User not found");
    }
    const user = await User.findById(userId);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }
    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    return ApiResponse.Success(res, "User profile fetched successfully!", {
      name: user.name,
      email: user.email,
      role: user.role,
      avatar: user.avatar,
      isEmailVerified: user.isEmailVerified,
      lastLoginAt: user.lastLoginAt,
      lockUntil: user.lockUntil,
    });
  }
);

//? GET USER SESSIONS
export const getUserSessions = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    console.log({ sessions: req.session });
    const userId = req.user?._id.toString();
    if (!userId) {
      return ApiResponse.NotFound(res, "User not found");
    }

    const user = await User.findById(userId);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    const sessions = await Session.find({ userId });

    return ApiResponse.Success(res, "User sessions fetched successfully!", {
      name: user.name,
      email: user.email,
      role: user.role,
      avatar: user.avatar,
      isEmailVerified: user.isEmailVerified,
      lastLoginAt: user.lastLoginAt,
      lockUntil: user.lockUntil,
      sessions,
    });
  }
);

//? RESET PASSWORD
export const resetPassword = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = ResetPasswordSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { newPassword, email } = data;
    if (!email) {
      return ApiResponse.BadRequest(res, "Email is required!");
    }

    const hashedResetPasswordToken = req.cookies?.hashedResetPasswordToken;

    const resetPasswordExpiry = req.cookies?.resetPasswordExpiry;

    if (!hashedResetPasswordToken) {
      return ApiResponse.BadRequest(res, "Reset password token not found");
    }

    if (!resetPasswordExpiry || new Date(resetPasswordExpiry) < new Date()) {
      return ApiResponse.BadRequest(
        res,
        "Reset password token expired. Please try again."
      );
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    const { hashedToken } = generateRandomToken(user._id.toString());

    if (hashedResetPasswordToken !== hashedToken) {
      return ApiResponse.BadRequest(res, "Invalid reset password token");
    }

    const oldPassword = user?.password;

    const isOldPassword = await verifyPassword(
      newPassword,
      oldPassword as string
    );

    if (isOldPassword) {
      return ApiResponse.BadRequest(res, "New password cannot be same as old");
    }

    const hashedNewPassword = await hashPassword(newPassword);

    user.password = hashedNewPassword;
    await user.save();

    res.clearCookie("hashedResetPasswordToken");
    res.clearCookie("resetPasswordExpiry");
    return ApiResponse.Ok(res, "Password reset successfully!");
  }
);

//? CHANGE PASSWORD
export const changePassword = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = ChangePasswordSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { oldPassword, newPassword } = data;

    if (!oldPassword || !newPassword) {
      return ApiResponse.BadRequest(
        res,
        "Old password and new password are required"
      );
    }

    const hashedChangePasswordToken = req.cookies?.hashedChangePasswordToken;

    const changePasswordExpiry = req.cookies?.changePasswordExpiry;

    if (!hashedChangePasswordToken) {
      return ApiResponse.BadRequest(
        res,
        "Change password token not found. Please request OTP for change password"
      );
    }

    if (!changePasswordExpiry || new Date(changePasswordExpiry) < new Date()) {
      return ApiResponse.BadRequest(
        res,
        "Change password token expired. Please try again."
      );
    }

    const user = await User.findById(req?.user?._id).select("+password");

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isEmailVerified === false) {
      return ApiResponse.BadRequest(res, "Please verify your email first");
    }

    const isOldPasswordMatch = await verifyPassword(oldPassword, user.password);
    if (!isOldPasswordMatch) {
      return ApiResponse.BadRequest(res, "Invalid old password");
    }

    const isOldPassword = await verifyPassword(newPassword, user.password);

    if (isOldPassword) {
      return ApiResponse.BadRequest(res, "New password cannot be same as old");
    }

    const hashedNewPassword = await hashPassword(newPassword);

    user.password = hashedNewPassword;
    await user.save();

    const currentSession = await Session.findOne({
      userId: user._id,
      isActive: true,
      _id: req.session?._id,
    });

    if (currentSession) {
      await currentSession.deleteOne();
    }

    res.clearCookie("sid");
    return ApiResponse.Ok(
      res,
      "Password changed successfully!, Please login again"
    );
  }
);

//? LOGOUT
export const logout = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = await User.findById(req?.user?._id);

    const sessionId = req.session?._id;

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    await Session.deleteMany({ userId: user._id, _id: sessionId });

    res.clearCookie("sid");
    return ApiResponse.Success(res, "Logged out successfully!");
  }
);

//? DELETE SESSION
export const deleteSession = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { sessionId } = req.params;
    const userId = req.user?._id;
    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return ApiResponse.BadRequest(res, "Invalid session ID");
    }

    const session = await Session.findOne({
      _id: sessionId,
      userId,
      isActive: true,
    });
    if (!session) {
      return ApiResponse.NotFound(res, "Session not found");
    }
    await session.deleteOne();

    const isCurrentSession =
      session._id.toString() === req.session?._id.toString();
    if (isCurrentSession) {
      res.clearCookie("sid");
    }

    return ApiResponse.Success(res, "Session deleted successfully");
  }
);

//? DELETE SESSIONS
export const deleteSessions = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userId = req.user?._id;
    if (!userId) {
      return ApiResponse.BadRequest(res, "Invalid user ID");
    }

    const sessions = await Session.find({
      userId,
      isActive: true,
    });
    if (!sessions) {
      return ApiResponse.NotFound(res, "Session not found");
    }

    await Session.deleteMany({ userId, isActive: true });

    clearAuthCookies(res);

    return ApiResponse.Success(res, "Sessions deleted successfully");
  }
);

//? UPDATE PROFILE
export const updateProfile = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = UpdateProfileSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { name } = data;

    const user = await User.findById(req?.user?._id);

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (req?.file && user?.avatar?.public_id) {
      await cloudinary.uploader.destroy(user?.avatar?.public_id);
    }

    if (req?.file && user?.avatar) {
      user.avatar = {
        public_id: req.file
          ? req.file.filename
          : (user?.avatar?.public_id as string),
        url: req.file ? req.file.path : (user.avatar.url as string),
        size: req.file ? req.file.size : (user.avatar.size as number),
      };
    }

    if (name) {
      user.name = name;
    }

    await user.save();

    return ApiResponse.Success(res, "Profile updated successfully!");
  }
);

//? DELETE/DEACTIVATE ACCOUNT
export const deleteAccount = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = DeleteAccountSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { userId, type } = data;
    if (userId !== req?.user?._id.toString()) {
      return ApiResponse.BadRequest(
        res,
        "You are not authorized to delete this account."
      );
    }

    const user = await User.findById(req?.user?._id);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (type === "soft") {
      user.isDeleted = true;
      user.deletedAt = new Date();
      user.reActivateAvailableAt = new Date(
        Date.now() + REACTIVATION_AVAILABLE_AT
      );
      await user.save();
    } else if (type === "hard") {
      if (user?.avatar?.public_id) {
        await cloudinary.uploader.destroy(user?.avatar?.public_id);
      }
      await User.findByIdAndDelete(req?.user?._id);
      await user.save();
    }

    return ApiResponse.Success(
      res,
      `Account ${type === "soft" ? "deactivated" : "deleted"} successfully!`
    );
  }
);

//? REACTIVATE ACCOUNT
export const reactivateAccount = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = await User.findById(req?.user?._id);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (!user?.isDeleted || !user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account is already active.");
    }

    if (
      user?.reActivateAvailableAt &&
      new Date(user?.reActivateAvailableAt) > new Date()
    ) {
      return ApiResponse.BadRequest(
        res,
        `You can reactivate your account after ${Math.ceil(
          (user?.reActivateAvailableAt.getTime() - Date.now()) /
            (1000 * 60 * 60 * 24)
        )} days.`
      );
    }

    if (user?.isDeleted || user?.deletedAt) {
      user.isDeleted = false;
      await user.save();
      await User.findOneAndUpdate(
        { _id: req?.user?._id },
        { $unset: { reActivateAvailableAt: "", deletedAt: "" } }
      );
      return ApiResponse.Success(res, "Account reactivated successfully!");
    }

    return ApiResponse.BadRequest(res, "Your account is already active.");
  }
);

//? GET ALL USER SESSIONS - ADMIN
export const getAllUserSessions = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    const { userId, isActive, email, role, ip, expired } = req.query;

    const matchStage: any = {};

    if (userId && mongoose.Types.ObjectId.isValid(String(userId))) {
      matchStage.userId = new mongoose.Types.ObjectId(String(userId));
    }

    if (typeof isActive !== "undefined") {
      matchStage.isActive = isActive === "true";
    }

    if (ip) {
      matchStage.ip = { $regex: ip, $options: "i" };
    }

    if (expired === "true") {
      matchStage.expiresAt = { $lt: new Date() };
    }

    if (expired === "false") {
      matchStage.expiresAt = { $gte: new Date() };
    }

    const [result] = await Session.aggregate([
      { $match: matchStage },

      { $sort: { createdAt: -1 } },

      {
        $lookup: {
          from: "users",
          localField: "userId",
          foreignField: "_id",
          as: "user",
        },
      },

      {
        $unwind: {
          path: "$user",
          preserveNullAndEmptyArrays: true,
        },
      },

      {
        $match: {
          ...(email && {
            "user.email": { $regex: email, $options: "i" },
          }),
          ...(role && {
            "user.role": role,
          }),
        },
      },

      {
        $project: {
          _id: 1,
          ip: 1,
          userAgent: 1,
          isActive: 1,
          lastUsedAt: 1,
          expiresAt: 1,
          createdAt: 1,
          updatedAt: 1,
          user: {
            _id: "$user._id",
            name: "$user.name",
            email: "$user.email",
            role: "$user.role",
            isEmailVerified: "$user.isEmailVerified",
            avatar: "$user.avatar",
          },
        },
      },

      {
        $facet: {
          sessions: [{ $skip: skip }, { $limit: limit }],
          total: [{ $count: "count" }],
        },
      },
    ]);

    const total = result.total[0]?.count || 0;
    const pages = Math.ceil(total / limit);

    return ApiResponse.Success(res, "All user sessions fetched successfully!", {
      sessions: result.sessions,
      pagination: {
        page,
        limit,
        total,
        pages,
      },
    });
  }
);

//? DELETE USER SESSIONS - ADMIN
export const deleteUserSessions = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return next(new ApiError(STATUS_CODES.BAD_REQUEST, "Invalid userId"));
    }

    const result = await Session.deleteMany({ userId });

    if (result.deletedCount <= 0) {
      return ApiResponse.NotFound(res, "Sessions not found!");
    }

    const shouldClearCookie = req.user?._id?.toString() === userId;
    if (shouldClearCookie) {
      clearAuthCookies(res);
    }

    return ApiResponse.Success(res, "User sessions deleted successfully");
  }
);

//? DELETE SINGLE SESSION - ADMIN
export const deleteSingleSession = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { sessionId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return ApiResponse.BadRequest(res, "Invalid sessionId");
    }

    const session = await Session.findById(sessionId);

    if (!session) {
      return ApiResponse.NotFound(res, "Session not found");
    }

    await Session.deleteOne({ _id: sessionId });

    if (req.session?._id === sessionId) {
      clearAuthCookies(res);
    }

    return ApiResponse.Success(res, "Session deleted successfully");
  }
);
