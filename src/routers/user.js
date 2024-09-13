const express = require("express");
const User = require("../models/user");
const transporter = require("../utils/emailService");
const OTP = require("../models/otp");
const jwt = require("jsonwebtoken");
const router = new express.Router();
const crypto = require("crypto");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;


// Protected route after Google or github login
router.get("/profile", async (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.redirect("/");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id);
    if (!user) {
      return res.redirect("/");
    }
    res.send(`Welcome ${user.firstname}`);
  } catch (e) {
    res.status(500).send("Invalid token.");
  }
});
// Google Strategy configuration

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Find or create a user in your database
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            firstname: profile.name.givenName,
            lastname: profile.name.familyName,
            email: profile.emails[0].value,
          });
        }
        done(null, user);
      } catch (error) {
        done(error, null);
      }
    }
  )
);
// Facebook Strategy configuration
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "emails", "name"], // Request fields from Facebook profile
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ facebookId: profile.id });

        if (!user) {
          user = new User({
            facebookId: profile.id,
            firstname: profile.name.givenName || 'FacebookUser',
            lastname: profile.name.familyName || '',
            email: profile.emails && profile.emails[0] ? profile.emails[0].value : null, // Handle missing email
            password: crypto.randomBytes(20).toString('hex'), // Generate random password for OAuth
            confirmpassword: crypto.randomBytes(20).toString('hex'),
          });
          await user.save();
        }
        done(null, user);
      } catch (error) {
        done(error, null);
      }
    }
  )
);
// GitHub Strategy configuration
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });

        if (!user) {
          user = new User({
            githubId: profile.id,
            firstname: profile.displayName || profile.username || 'GitHubUser',
            lastname: '',
            email: profile.emails && profile.emails[0] ? profile.emails[0].value : null, // GitHub might not return an email
            password: crypto.randomBytes(20).toString('hex'), // Generate random password for OAuth
            confirmpassword: crypto.randomBytes(20).toString('hex'),
          });
          await user.save();
        }
        done(null, user);
      } catch (error) {
        done(error, null);
      }
    }
  )
);

// Route to initiate Google Sign-In
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google OAuth callback route
router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      const token = await req.user.generateAuthToken();
      res.send({ user: req.user, token });
    } catch (e) {
      res.status(500).send("Error generating token.");
    }
  }
)

router.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);

// Facebook OAuth callback route
router.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      const token = await req.user.generateAuthToken();
      res.send({ user: req.user, token });
    } catch (e) {
      res.status(500).send("Error generating token.");
    }
  }
);


// Route to initiate GitHub Sign-In
router.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

// GitHub OAuth callback route
router.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      const token = await req.user.generateAuthToken();
      res.send({ user: req.user, token });
    } catch (e) {
      res.status(500).send("Error generating token.");
    }
  }
);


router.post("/users/signup", async (req, res) => {
  const { firstname, lastname,cellno, email, password, confirmpassword } =
    req.body;

  try {
    // Create a new user
    const user = new User({
      firstname,
      lastname,
      cellno,
      email,
      password,
      confirmpassword,
    });
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
    const token = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    ); // Add a secret key to .env
    res.send({ user, token });
    console.log("user login successfully");
  } catch (e) {
    res.status(400).send("Invalid login credentials");
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

router.post("/users/reset-password", async (req, res) => {
  try {
    const { token, password, confirmpassword } = req.body;

    // Validate input fields
    if (!token || !password || !confirmpassword) {
      return res
        .status(400)
        .send("Token, new password, and confirm password are required.");
    }

    // Check if passwords match
    if (password !== confirmpassword) {
      return res.status(400).send("Passwords do not match.");
    }

    // Verify token
    const decoded = jwt.verify(token, "authen");

    // Find the user with the matching token
    const user = await User.findOne({ _id: decoded._id, resetToken: token });

    if (!user) {
      return res.status(404).send("Invalid or expired token.");
    }

    // Update user's password
    user.password = password; // Ensure you hash the password in a production setting
    user.resetToken = undefined; // Clear the reset token after use
    await user.save();

    res.send("Password reset successfully.");
  } catch (e) {
    console.error(e);
    res.status(500).send("An error occurred while resetting the password.");
  }
});

module.exports = router;
