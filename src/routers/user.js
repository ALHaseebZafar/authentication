const express = require("express");
const User = require("../models/user");
const transporter = require("../utils/emailService");
const OTP = require("../models/otp");
const jwt = require("jsonwebtoken");
const router = new express.Router();
const crypto = require("crypto");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const GitHubStrategy = require("passport-github").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
require("dotenv").config();

function isLoggedIn(req, res, next) {
  req.user ? next() : res.sendStatus(401);
}
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      // Generate a JWT
      const token = jwt.sign(
        { _id: profile.id, email: profile.email },
        process.env.JWT_SECRET,
        { expiresIn: "2h" }
      );

      // Extract only the required information
      const userData = {
        name: profile.displayName,
        email: profile.email,
        token: token,
      };

      done(null, userData);
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        const emailsResponse = await fetch(
          "https://api.github.com/user/emails",
          {
            headers: {
              Authorization: `token ${accessToken}`,
              "User-Agent": "Node.js",
            },
          }
        );
        const emailData = await emailsResponse.json();

        console.log("GitHub Email Data:", emailData); // Log the email data

        // Find the primary email from the list
        const primaryEmail = emailData.find(
          (email) => email.primary && email.verified
        );

        // Attach the email to the profile
        profile.email = primaryEmail ? primaryEmail.email : null;
        profile.accessToken = accessToken;

        // Generate a JWT
        const token = jwt.sign(
          { _id: profile.id, email: profile.email },
          process.env.JWT_SECRET,
          { expiresIn: "2h" }
        );
        done(null, { profile, token });
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback",
      profileFields: ["id", "emails", "name"],
    },
    function (accessToken, refreshToken, profile, done) {
      console.log("Facebook Profile:", profile); // Log the profile object

      const email = profile.emails ? profile.emails[0].value : null;
      const name = profile.displayName; // Get the display name

      // Generate a JWT
      const token = jwt.sign(
        { _id: profile.id, email: email },
        process.env.JWT_SECRET,
        { expiresIn: "2h" }
      );
      done(null, { name, email, token });
    }
  )
);

router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    if (req.user) {
      const { name, email, token } = req.user;
      res.send(`Name: ${name}, Email: ${email}, AccessToken: ${token}`);
    } else {
      res.redirect("/auth/failure"); // Redirect to failure route if authentication fails
    }
  }
);

router.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] }) // Correct scope for GitHub
);

router.get(
  "/auth/github/callback",
  passport.authenticate("github", { session: false }),
  (req, res) => {
    if (req.user) {
      const { profile, token } = req.user;
      const email = profile.email || "No email found";
      res.send(`Email: ${email}, AccessToken: ${token}`);
    } else {
      res.redirect("/auth/failure");
    }
  }
);

router.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] }) // No 'profile' scope for Facebook
);

router.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { session: false }),
  (req, res) => {
    if (req.user) {
      const { email, token } = req.user;
      res.send(
        ` Email: ${email || "No email available"}, AccessToken: ${token}`
      );
    } else {
      res.redirect("/auth/failure");
    }
  }
);

router.get("/auth/failure", (req, res) => {
  res.send("something went wrong");
});

router.post("/users/signup", async (req, res) => {
  const { firstname, lastname, cellno, email, password, confirmpassword } =
    req.body;

  try {
    const user = new User({
      firstname,
      lastname,
      email,
      password,
      cellno,
      confirmpassword,
    });
    await user.save();

    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    const otpEntry = new OTP({ email, otp, expiresAt });
    await otpEntry.save();

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
    console.log("process", process.env.JWT_SECRET);
    console.log("user", user);
    const token = jwt.sign(
      { _id: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );
    res.send({ user, token });
    console.log("user login successfully");
  } catch (e) {
    console.log("error", e);
    res.status(400).send("Invalid login credentials");
  }
});
// forget password
router.post("/users/request-reset-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    const resetToken = jwt.sign({ _id: user._id.toString() }, "authen", {
      expiresIn: "1h",
    });
    user.resetToken = resetToken;
    await user.save();

    const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
    const mailOptions = {
      from: "noreply@example.com",
      to: user.email,
      subject: "Password Reset Request",
      text: `You requested a password reset. Click the link to reset your password: ${resetUrl}`,
    };
    await transporter.sendMail(mailOptions);

    // res.send({ message: "Password reset email sent." });
    res.send({ resetToken: resetToken, message: "Password reset email sent." }); //get token in frontEnd forget component
  } catch (e) {
    res
      .status(500)
      .send({ error: "An error occurred while requesting a password reset." });
  }
});
// reset password
router.post("/users/reset-password", async (req, res) => {
  try {
    const { token, password, confirmpassword } = req.body;
    if (!token || !password || !confirmpassword) {
      return res
        .status(400)
        .send("Token, new password, and confirm password are required.");
    }

    if (password !== confirmpassword) {
      return res.status(400).send("Passwords do not match.");
    }

    const decoded = jwt.verify(token, "authen");
    const user = await User.findOne({ _id: decoded._id, resetToken: token });
    if (!user) {
      return res.status(404).send("Invalid or expired token.");
    }

    user.password = password;
    user.resetToken = undefined;
    await user.save();

    res.send("Password reset successfully.");
  } catch (e) {
    console.error(e);
    res.status(500).send("An error occurred while resetting the password.");
  }
});

module.exports = router;
