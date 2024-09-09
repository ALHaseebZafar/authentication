const express = require('express');
require('dotenv').config();  // Load environment variables
require('./db/mongoose');    // Connect to MongoDB
const passport = require('passport');  // Import Passport directly
const userRouter = require('./routers/user');
const bookRouter = require('./routers/books');  // Correctly import the bookRouter
const app = express();

const port = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('app is running perfectly');
});

// Initialize passport middleware
app.use(passport.initialize());  // No need for passport.session()

// Register the routers
app.use(userRouter);
app.use(bookRouter);  // Ensure bookRouter is correctly passed

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
