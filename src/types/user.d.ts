import { USER_ROLES } from "#constants/auth-constants.ts";
import { Request } from "express";
import mongoose from "mongoose";

export interface AuthenticatedRequest extends Request {
  user?: {
    _id: string | mongoose.Types.ObjectId;
    role: USER_ROLES;
  };
  session?: {
    _id: string;
    token: string;
  };
}

export interface UserRequest extends Request {
  user?: {
    _id?: string | mongoose.Types.ObjectId | undefined;
    role: USER_ROLES;
  };
  session?: {
    _id: string;
    token: string;
  };
}
