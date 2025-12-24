import mongoose, { Document, Schema, Model } from "mongoose";
import { OTP_CODE_EXPIRY, OTP_TYPES } from "#constants/auth-constants.js";

export interface IOtp extends Document {
  _id: mongoose.Types.ObjectId;
  email: string;
  otpType: (typeof OTP_TYPES)[number];
  otpHashCode: string;
  nextResendAllowedAt: Date;
  attempts: number;
  isVerified: boolean;
  expiresAt: Date;

  createdAt: Date;
  updatedAt: Date;
}

const otpSchema: Schema<IOtp> = new Schema(
  {
    email: {
      type: String,
      required: true,
      index: true,
    },
    otpType: {
      type: String,
      enum: ["email-verification", "password-reset", "password-change"],
      required: true,
    },
    otpHashCode: {
      type: String,
      required: true,
    },
    attempts: {
      type: Number,
      default: 0,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: OTP_CODE_EXPIRY / 1000 },
    },
    nextResendAllowedAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

otpSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: OTP_CODE_EXPIRY / 1000 }
);

const Otp: Model<IOtp> =
  mongoose.models.Otp || mongoose.model<IOtp>("Otp", otpSchema);

export default Otp;
