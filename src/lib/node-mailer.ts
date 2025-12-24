import nodemailer from "nodemailer";
import "dotenv/config";
import { env } from "#configs/env.js";

let transporter: nodemailer.Transporter | null = null;

function getTransporter() {
  if (transporter) return transporter;
  const host = env.SMTP_HOST;
  const port = Number(env.SMTP_PORT || 587);
  const user = env.SMTP_USER;
  const pass = env.SMTP_USER;
  const from = env.EMAIL_FROM;
  if (!host || !user || !pass || !from) {
    throw new Error("SMTP/EMAIL env not configured");
  }
  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });
  return transporter;
}
type SendEmailParams = {
  from?: string;
  to: string;
  subject: string;
  html: string;
};

export async function sendEmail({
  from = env.EMAIL_FROM,
  to,
  subject,
  html,
}: SendEmailParams) {
  const transporter = getTransporter();
  return transporter.sendMail({
    from: `<${from}>`,
    to,
    subject,
    html,
  });
}
