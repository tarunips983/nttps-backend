const nodemailer = require("nodemailer");

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ message: "Method not allowed" });

  const { email, otp } = req.body;

  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verification Code",
      text: `Your OTP is ${otp}`
    });

    return res.json({ message: "OTP sent from Vercel Gmail SMTP" });

  } catch (error) {
    console.error("Vercel SMTP error:", error);
    return res.status(500).json({ message: "Failed to send OTP", error });
  }
}
