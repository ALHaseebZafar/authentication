const express=require('express')
require('dotenv').config();  // Load environment variables
require('./db/mongoose');    // Connect to MongoDB
const passport = require('passport');  // Import Passport directly
const session = require('express-session');  // Required for session-based authentication
const userRouter = require('./routers/user');
const bookRouter=require('./routers/books')

const port = process.env.PORT || 3000;

app.use(express.json());

// Set up session middleware before passport
app.use(session({
  secret: process.env.SESSION_SECRET,  // Use session secret from env file
  resave: false,
  saveUninitialized: true
}));
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Use session secret from env file
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Routers
app.use(userRouter);
app.use(bookRouter)
// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
