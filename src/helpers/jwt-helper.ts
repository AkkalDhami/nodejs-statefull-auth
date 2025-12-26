// import { env } from "#configs/env.js";
// import { ACCESS_TOKEN_EXPIRY, MILLISECONDS_PER_SECOND, REFRESH_TOKEN_EXPIRY } from "#constants/auth-constants.js";
// import jwt from "jsonwebtoken";


// export const generateAccessToken = ({ _id }: { _id: string | null }) => {
//   return jwt.sign({ _id }, env.JWT_ACCESS_SECRET, {
//     expiresIn: ACCESS_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND,
//   });
// };

// export const generateRefreshToken = (userId: string) => {
//   return jwt.sign({ userId }, env.JWT_REFRESH_SECRET, {
//     expiresIn: REFRESH_TOKEN_EXPIRY / MILLISECONDS_PER_SECOND,
//   });
// };

// export const verifyAccessToken = (token: string) => {
//   return jwt.verify(token, env.JWT_ACCESS_SECRET) as {
//     _id: string;
//   };
// };

// export const verifyRefreshToken = (token: string) => {
//   return jwt.verify(token, env.JWT_REFRESH_SECRET) as { userId: string };
// };
