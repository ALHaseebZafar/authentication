const express = require("express");
require('dotenv').config();  // Load environment variables
require('./db/mongoose');
const passport = require('./auth/passport');  // Import the passport config file
const session = require('express-session');  // Required for session-based authentication
const userRouter = require('./routers/user');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(userRouter);

app.use(session({
  secret: process.env.SESSION_SECRET,  // Use session secret from env file
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
