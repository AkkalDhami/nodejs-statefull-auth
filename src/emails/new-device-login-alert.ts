import { NewDeviceLoginAlertProps } from "#types/email.js";

export function getNewDeviceLoginAlertEmailTemplate({
  ip,
  userAgent,
  loginTime,
  email,
  securityLink,
}: NewDeviceLoginAlertProps) {
  return `
    <!DOCTYPE html>
<html>  
  <head>
    <meta charset="UTF-8" />
    <title>New Device Login Alert</title>
  </head>
  <body style="margin:0;padding:0;background-color:#f4f6f8;font-family:Arial,Helvetica,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8;padding:20px 0;">
      <tr>
        <td align="center">
          <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:6px;overflow:hidden;">
            
            <!-- Header -->
            <tr>
              <td style="padding:20px;background-color:#111827;color:#ffffff;">
                <h2 style="margin:0;font-size:20px;">Security Alert</h2>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:24px;color:#333333;">
                <p style="margin:0 0 16px;font-size:14px;">
                  Hello,<${email}>
                </p>

                <p style="margin:0 0 16px;font-size:14px;">
                  We detected a sign-in to your account from a <strong>new device</strong>.
                </p>

                <table width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0;font-size:14px;">
                  <tr>
                    <td style="padding:6px 0;"><strong>Date & Time:</strong></td>
                    <td style="padding:6px 0;">${loginTime}</td>
                  </tr>
                  <tr>
                    <td style="padding:6px 0;"><strong>IP Address:</strong></td>
                    <td style="padding:6px 0;">${ip}</td>
                  </tr>
                  <tr>
                    <td style="padding:6px 0;"><strong>Device:</strong></td>
                    <td style="padding:6px 0;"> ${userAgent}</td>
                  </tr>
                </table>

                <p style="margin:16px 0;font-size:14px;">
                  If this was you, no action is required.
                </p>

                <p style="margin:16px 0;font-size:14px;color:#b91c1c;">
                  If you do not recognize this activity, please secure your account immediately by changing your password and logging out from all devices.
                </p>

                <div style="margin:24px 0;text-align:center;">
                  <a
                    href="${securityLink}"
                    style="display:inline-block;padding:10px 18px;background-color:#2563eb;color:#ffffff;text-decoration:none;border-radius:4px;font-size:14px;"
                  >
                    Secure My Account
                  </a>
                </div>

                <p style="margin:0;font-size:12px;color:#6b7280;">
                  This is an automated security message. Please do not reply to this email.
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:14px;background-color:#f9fafb;color:#6b7280;font-size:12px;text-align:center;">
                © ${new Date().getFullYear()} Your Company. All rights reserved.
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>

    `;
}
