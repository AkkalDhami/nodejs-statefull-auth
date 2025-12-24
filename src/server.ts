import app from "./app";
import { connectDB } from "./configs/db";
import { env } from "./configs/env";
import { logger } from "./utils/logger";

connectDB()
  .then(() => {
    app.listen(env.PORT, () => {
      logger.info(`✅ Server is running on http://localhost:${env.PORT}`);
    });
  })
  .catch((error) => {
    logger.error("❌ MongoDB Connection Failed:", error);
    process.exit(1);
  });
