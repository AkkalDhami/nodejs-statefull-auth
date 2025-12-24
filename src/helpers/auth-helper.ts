import crypto from "node:crypto";
import argon2 from "argon2";

export const hashPassword = async (password: string) => argon2.hash(password);

export const verifyPassword = async (
  password: string,
  hashedPassword: string
) => argon2.verify(hashedPassword, password);

export const generateOtp = (length: number, ttlMinutes: number) => {
  const code = String(
    Math.floor(Math.random() * Math.pow(10, length))
  ).padStart(length, "0");
  const hashCode = crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);
  return { code, hashCode, expiresAt };
};

export const verifyOtpCode = ({
  code,
  hashCode,
}: {
  code: string;
  hashCode: string;
}) => {
  const hashedCode = crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
  return hashedCode === hashCode;
};

export const generateRandomToken = (id: string) => {
  const token = crypto.createHash("sha256").update(String(id)).digest("hex");

  const hashedToken = crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");

  return { token, hashedToken };
};

export const generateToken = (size: number = 32): string => {
  const token = crypto.randomBytes(size).toString("hex");
  return token;
};

export const generateHashedToken = (token: string) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");

  return hashedToken;
};
