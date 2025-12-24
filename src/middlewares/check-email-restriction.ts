import { User } from "#models/user.model.js";
import { UserRequest } from "#types/user.js";
import { ApiResponse } from "#utils/api-response.js";
import { logger } from "#utils/logger.js";
import { NextFunction, Response } from "express";

export async function checkEmailRestriction(
  req: UserRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const user = await User.findById(req.user?._id);
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

    if (!user.isEmailVerified) {
      return ApiResponse.BadRequest(
        res,
        "Email not verified!, Please verify your email"
      );
    }

    return next();
  } catch (err: any) {
    logger.error(err?.message);
    return ApiResponse.BadRequest(res, "Something went wrong");
  }
}
