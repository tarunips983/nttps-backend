import nodemailer from "nodemailer";

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

  const { email } = req.body;

  if (!email) return res.status(400).json({ message: "Email required" });

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Save temporarily in memory (same as your register OTP system)
  global.forgotOTP = global.forgotOTP || {};
  global.forgotOTP[email] = {
    otp,
    expires: Date.now() + 10 * 60 * 1000,
  };

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}`,
    });

    return res.status(200).json({ message: "OTP sent successfully" });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Email sending failed" });
  }
}
