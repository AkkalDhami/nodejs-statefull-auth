import { NextFunction, Request, Response } from "express";

import { UserRequest } from "#types/user.js";
import { ApiResponse } from "#utils/api-response.js";
import { User } from "#models/user.model.js";
import { logger } from "#utils/logger.js";
import Session from "#models/session.model.js";
import { generateHashedToken } from "#helpers/auth-helper.js";
import { SESSION_EXPIRY } from "#constants/auth-constants.js";

export async function isAuthenticated(
  req: UserRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const sid = req.cookies?.sid;

    const authorization = req.headers.authorization;
    const token = authorization?.split(" ")[1];

    if (!sid || !token) {
      return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
    }

    const hashedSession = generateHashedToken(sid || token);

    const session = await Session.findOne({
      tokenHash: hashedSession,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      return ApiResponse.Unauthorized(res, "Session expired!");
    }

    if (
      session.userAgent !== req.headers["user-agent"] ||
      session.ip !== req.ip
    ) {
      return ApiResponse.Unauthorized(res, "Session invalid");
    }

    const user = await User.findById(session.userId);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found!");
    }

    req.user = {
      _id: user._id,
      role: user.role,
    };
    req.session = {
      _id: session._id.toString(),
      token: sid || token,
    };

    const remainingTime = session.expiresAt.getTime() - Date.now();
    const EXTEND_THRESHOLD = SESSION_EXPIRY * 0.25;

    if (remainingTime < EXTEND_THRESHOLD) {
      await Session.updateOne(
        { _id: session._id.toString() },
        {
          $set: {
            lastUsedAt: new Date(),
            expiresAt: new Date(Date.now() + SESSION_EXPIRY),
          },
        }
      );
    }

    return next();
  } catch (err: any) {
    logger.error(err?.message);
    return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
  }
}

export const authorizeRoles =
  (...allowedRoles: ("admin" | "user")[]) =>
  (req: UserRequest, res: Response, next: NextFunction) => {
    if (!req.user || !req.session) {
      return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
    }

    if (!allowedRoles.includes(req.user.role)) {
      return ApiResponse.Forbidden(res, "Forbidden, limited access!");
    }
    next();
  };
