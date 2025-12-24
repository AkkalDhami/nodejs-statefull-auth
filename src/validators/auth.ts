import { OTP_TYPES } from "#constants/auth-constants.js";
import * as z from "zod";

export const nameSchema = z
  .string({ error: "Name must be a string" })
  .trim()
  .min(3, {
    message: "Name must be at least 3 characters long",
  })
  .max(50, {
    message: "Name must be at most 50 characters long",
  });

export const passwordSchema = z
  .string({ error: "Password must be a string" })
  .trim()
  .min(6, {
    message: "Password must be at least 6 characters long",
  })
  .max(80, {
    message: "Password must be at most 80 characters long",
  });

export const emailSchema = z
  .email({ message: "Please enter a valid email address." })
  .max(100, { message: "Email must be no more than 100 characters." });

export const roleSchema = z
  .enum(["user", "admin"], {
    error: "Role must be either applicant, recruiter, or admin",
  })
  .default("user");

export const SigninSchema = z.object({
  email: emailSchema,
  password: z.string({ error: "Password must be a string" }).trim().min(1, {
    message: "Password is required",
  }),
});

export const SignupSchema = z
  .object({
    name: nameSchema,
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: passwordSchema,
    role: roleSchema,
  })
  .refine(
    (data) => {
      return data.password === data.confirmPassword;
    },
    {
      message: "Passwords do not match",
      path: ["confirmPassword"],
    }
  );

export const RequestOtpSchema = z.object({
  email: emailSchema,
  otpType: z.enum(OTP_TYPES, { error: "Invalid otp type" }),
});

export const VerifyOtpSchema = z.object({
  otpCode: z.string().min(6, "Please enter a valid OTP"),
  email: emailSchema,
  resetPasswordToken: z.string().optional(),
});

export const ResetPasswordSchema = z
  .object({
    email: emailSchema,
    newPassword: passwordSchema,
    confirmNewPassword: passwordSchema,
  })
  .refine(
    (data) => {
      return data.newPassword === data.confirmNewPassword;
    },
    {
      message: "Passwords do not match",
      path: ["confirmNewPassword"],
    }
  );

export const ChangePasswordSchema = z
  .object({
    oldPassword: z.string({ error: "Password must be a string" }).min(1, {
      message: "Old password is required",
    }),
    newPassword: passwordSchema,
    confirmNewPassword: passwordSchema,
  })
  .refine(
    (data) => {
      return data.newPassword === data.confirmNewPassword;
    },
    {
      message: "Passwords do not match",
      path: ["confirmNewPassword"],
    }
  );

export const UpdateProfileSchema = z.object({
  name: nameSchema,
  avatar: z.string().optional(),
});

export const GoogleSigninSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  provider: z.enum(["google", "github"]).default("google"),
  providerId: z.string({ error: "Provider id must be a string" }).min(1, {
    message: "Provider id is required",
  }),
  avatar: z.string().optional(),
  isEmailVerified: z.boolean().default(false),
});

export const DeleteAccountSchema = z.object({
  userId: z.string({ error: "User id must be a string" }).min(1, {
    message: "User id is required",
  }),
  type: z
    .enum(["soft", "hard"], { error: "Type must be either soft or hard" })
    .default("soft"),
});
