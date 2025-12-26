import Otp from "#models/otp.model.js";
import { logger } from "#utils/logger.js";
import cron from "node-cron";

export const startOtpCleaner = () => {
  // cron.schedule("*/5 * * * *", async () => {
  //   try {
  //     logger.info("[CRON] Running OTP cleaner...");
  //     const now = new Date();
  //     await Otp.deleteMany({
  //       $or: [{ isVerified: true }, { expiresAt: { $lt: now } }],
  //     });
  //   } catch (error) {
  //     logger.error("[CRON] Failed to delete expired OTPs:", error);
  //   }
  // });
};

startOtpCleaner();
