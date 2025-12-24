import { sendEmail } from "#lib/node-mailer.js";
import { NewDeviceLoginAlertProps } from "#types/email.js";
import { getNewDeviceLoginAlertEmailTemplate } from "../emails/new-device-login-alert";

export const sendNewDeviceLoginAlertEmail = async ({
  ip,
  userAgent,
  loginTime,
  email,
  securityLink,
}: NewDeviceLoginAlertProps) => {
  const html = getNewDeviceLoginAlertEmailTemplate({
    ip,
    userAgent,
    loginTime,
    email,
    securityLink,
  });

  await sendEmail({
    to: email,
    subject: "New Device Login Alert",
    html,
  });
};
