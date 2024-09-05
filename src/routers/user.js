const express = require("express");
const User = require("../models/user");
const transporter = require("../utils/emailService");
const OTP = require("../models/otp");
const auth = require("../middleware/auth");
const jwt = require("jsonwebtoken");
const router = new express.Router();
const crypto = require("crypto");

router.post("/users/signup", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  try {
    // Create a new user
    const user = new User({ firstname, lastname, email, password });
    await user.save();

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    const expiresAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

    // Save OTP to database
    const otpEntry = new OTP({ email, otp, expiresAt });
    await otpEntry.save();

    // Send OTP to user’s email
    const resetUrl = `http://localhost:3000/verify-otp?otp=${otp}`;
    const mailOptions = {
      from: "noreply@example.com",
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It is valid for 10 minutes. Click the link to verify your email: ${resetUrl}`,
    };
    await transporter.sendMail(mailOptions);

    res
      .status(201)
      .send({ message: "User created and OTP sent to your email." });
  } catch (e) {
    res.status(400).send(e);
  }
});

router.post("/users/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const otpEntry = await OTP.findOne({ email, otp });

    if (!otpEntry) {
      return res.status(400).send({ error: "Invalid OTP." });
    }

    if (otpEntry.expiresAt < Date.now()) {
      return res.status(400).send({ error: "OTP expired." });
    }

    // Optionally, you can delete the OTP entry after successful verification
    await OTP.deleteOne({ _id: otpEntry._id });

    res.send({ message: "OTP verified successfully. You can now log in." });
  } catch (e) {
    res.status(500).send({ error: "An error occurred while verifying OTP." });
  }
});

router.post("/users/login", async (req, res) => {
  try {
    const user = await User.findByCredentials(
      req.body.email,
      req.body.password
    );
    const token = await user.generateAuthToken();
    res.send({ user, token });
  } catch (e) {
    res.status(400).send();
  }
});

router.post("/users/request-reset-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send({ error: "user not found" });
    }
    // Generate a reset token (this can also be a JWT)
    const resetToken = jwt.sign({ _id: user._id.toString() }, "authen", {
      expiresIn: "1h",
    });

    // Add token to user document or separate collection if needed
    user.resetToken = resetToken; // Make sure to add 'resetToken' field to user schema
    await user.save();

    // Send email with reset link
    const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: "noreply@example.com", // Replace with your email address
      to: user.email,
      subject: "Password Reset Request",
      text: `You requested a password reset. Click the link to reset your password: ${resetUrl}`,
    };

    await transporter.sendMail(mailOptions);

    res.send({ message: "Password reset email sent." });
  } catch (e) {
    res
      .status(500)
      .send({ error: "An error occurred while requesting a password reset." });
  }
});

// Route to handle password reset
router.post("/users/reset-password", async (req, res) => {
  try {
    const resetToken = req.body.token;
    const newPassword = req.body.password;

    if (!resetToken || !newPassword) {
      return res
        .status(400)
        .send({ error: "Token and new password are required." });
    }

    // Verify token
    const decoded = jwt.verify(resetToken, "authen");

    const user = await User.findOne({ _id: decoded._id, resetToken });

    if (!user) {
      return res.status(404).send({ error: "Invalid or expired token." });
    }

    // Update user's password
    user.password = newPassword; // Ensure you hash the password in a production setting
    user.resetToken = undefined; // Clear the reset token after use
    await user.save();

    res.send({ message: "Password reset successfully." });
  } catch (e) {
    res
      .status(500)
      .send({ error: "An error occurred while resetting the password." });
  }
});

module.exports = router;
