import { Response } from "express";
import { SESSION_EXPIRY } from "#constants/auth-constants.js";
import { env } from "#configs/env.js";

const isProduction = env.NODE_ENV === "production";

export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? ("none" as const) : ("lax" as const),
  path: "/",
};

export function setAuthCookies(res: Response, sid: string) {
  res.cookie("sid", sid, {
    ...COOKIE_OPTIONS,
    maxAge: SESSION_EXPIRY,
  });
}

export function clearAuthCookies(res: Response, cookie: string = "sid") {
  res.clearCookie(cookie, COOKIE_OPTIONS);
}
