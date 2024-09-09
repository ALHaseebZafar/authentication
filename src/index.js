const express = require('express');
require('dotenv').config();  // Load environment variables
require('./db/mongoose');    // Connect to MongoDB
const passport = require('passport');  // Import Passport directly
const session = require('express-session');  // Required for session-based authentication
const userRouter = require('./routers/user');
const bookRouter = require('./routers/books');  // Correctly import the bookRouter
const app = express();
const MongoStore = require('connect-mongo');

const port = process.env.PORT || 3000;

app.use(express.json());

app.get('/',(req,res)=>{
  res.send('app is running perfectly')
})
//Set up session middleware before passport
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }) // Store sessions in MongoDB
}));

//Initialize passport middleware
app.use(passport.initialize());
// app.use(passport.session());

Routers
app.use(userRouter);
app.use(bookRouter);  // Ensure bookRouter is correctly passed

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
