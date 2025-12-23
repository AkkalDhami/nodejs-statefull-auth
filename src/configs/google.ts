import { OAuth2Client } from "google-auth-library";
import { env } from "./env";
import { logger } from "#utils/logger.js";

const clientId = env.GOOGLE_CLIENT_ID;
const clientSecret = env.GOOGLE_CLIENT_SECRET;
const redirectUri = env.GOOGLE_REDIRECT_URI;

if (!clientId || !clientSecret) {
  logger.error("Google client id and secret are requird!");
  throw new Error("Google client id and secret are requird!");
}

const googleClient = new OAuth2Client({
  clientId,
  clientSecret,
  redirectUri,
});

export default googleClient;
