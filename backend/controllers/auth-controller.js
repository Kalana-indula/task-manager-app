import User from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Verification from "../models/verification.js";
import { sendEmail } from "../libs/send-email.js";
import aj from "../libs/arcjet.js";

// Small helper: ensure JWT secret exists
const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is missing in environment variables");
  }
  return secret;
};

// Small helper: create tokens consistently
const signToken = (payload, expiresIn) => {
  return jwt.sign(payload, getJwtSecret(), { expiresIn });
};

// Small helper: in dev, don’t block core flows if email fails
const trySendEmail = async (email, subject, body) => {
  // Optional guard: if you want to skip when SendGrid key is invalid
  // if (!process.env.SENDGRID_API_KEY?.startsWith("SG.")) return false;

  try {
    const ok = await sendEmail(email, subject, body);
    return Boolean(ok);
  } catch (err) {
    console.warn("Email send failed (ignored):", err?.message || err);
    return false;
  }
};

const registerUser = async (req, res) => {
  try {
    const { email, name, password } = req.body;

    // basic validation (optional but helpful)
    if (!email || !name || !password) {
      return res
        .status(400)
        .json({ message: "email, name and password are required" });
    }

    // Arcjet protect
    const decision = await aj.protect(req, { email });
    console.log("Arcjet decision denied:", decision.isDenied());

    if (decision.isDenied()) {
      return res.status(403).json({ message: "Invalid email address" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email address already in use" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    await User.create({
      email,
      password: hashPassword,
      name,
      isEmailVerified: true,
    });

    return res.status(201).json({
      message: "Account created successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error?.message || "Internal server error",
    });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "email and password are required" });
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // verified user -> login
    const token = signToken({ userId: user._id, purpose: "login" }, "7d");

    user.lastLogin = new Date();
    await user.save();

    const userData = user.toObject();
    delete userData.password;

    return res.status(200).json({
      message: "Login successful",
      token,
      user: userData,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error?.message || "Internal server error",
    });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;
    const payload = jwt.verify(token, getJwtSecret());

    const { userId, purpose } = payload || {};
    if (purpose !== "email-verification") {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const verification = await Verification.findOne({ userId, token });
    if (!verification) return res.status(401).json({ message: "Unauthorized" });

    if (verification.expiresAt < new Date()) {
      return res.status(401).json({ message: "Token expired" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    user.isEmailVerified = true;
    await user.save();

    await Verification.findByIdAndDelete(verification._id);

    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error?.message || "Internal server error",
    });
  }
};

const resetPasswordRequest = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (!user.isEmailVerified) {
      return res
        .status(400)
        .json({ message: "Please verify your email first" });
    }

    const existingVerification = await Verification.findOne({
      userId: user._id,
    });

    if (existingVerification && existingVerification.expiresAt > new Date()) {
      return res
        .status(400)
        .json({ message: "Reset password request already sent" });
    }

    if (existingVerification) {
      await Verification.findByIdAndDelete(existingVerification._id);
    }

    const resetPasswordToken = signToken(
      { userId: user._id, purpose: "reset-password" },
      "15m"
    );

    await Verification.create({
      userId: user._id,
      token: resetPasswordToken,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    });

    const resetPasswordLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetPasswordToken}`;
    const emailBody = `<p>Click <a href="${resetPasswordLink}">here</a> to reset your password</p>`;
    const emailSubject = "Reset your password";

    const isEmailSent = await trySendEmail(email, emailSubject, emailBody);

    return res.status(200).json({
      message: isEmailSent
        ? "Reset password email sent"
        : "Reset token created, but email could not be sent right now. Try again later.",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error?.message || "Internal server error",
    });
  }
};

const verifyResetPasswordTokenAndResetPassword = async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;

    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({
        message: "token, newPassword and confirmPassword are required",
      });
    }

    const payload = jwt.verify(token, getJwtSecret());
    const { userId, purpose } = payload || {};

    if (purpose !== "reset-password") {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const verification = await Verification.findOne({ userId, token });
    if (!verification) return res.status(401).json({ message: "Unauthorized" });

    if (verification.expiresAt < new Date()) {
      return res.status(401).json({ message: "Token expired" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ message: "Unauthorized" });

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashPassword;
    await user.save();

    await Verification.findByIdAndDelete(verification._id);

    return res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: error?.message || "Internal server error",
    });
  }
};

export {
  registerUser,
  loginUser,
  verifyEmail,
  resetPasswordRequest,
  verifyResetPasswordTokenAndResetPassword,
};
