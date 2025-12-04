import bcrypt from "bcrypt";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE);

export default async function handler(req, res) {

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ message: "Method not allowed" });
  }

  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword)
    return res.status(400).json({ message: "All fields required" });

  // Validate OTP
  const stored = global.forgotOTP?.[email];

  if (!stored || stored.otp !== otp || stored.expires < Date.now()) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  // Hash new password
  const hash = await bcrypt.hash(newPassword, 10);

  // Update Supabase
  const { error } = await supabase
    .from("users")
    .update({ password_hash: hash })
    .eq("email", email);

  if (error) {
    console.error(error);
    return res.status(500).json({ message: "Password update failed" });
  }

  delete global.forgotOTP[email];

  res.status(200).json({ message: "Password successfully reset" });
}
