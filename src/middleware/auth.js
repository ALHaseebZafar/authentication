const jwt = require('jsonwebtoken');
const User = require('../models/user');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', ''); // Extract token from Authorization header
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token with JWT secret
    const user = await User.findOne({ _id: decoded._id }); // Find the user by the decoded token's _id

    if (!user) {
      throw new Error(); // If no user is found, throw an error
    }

    req.user = user; // Attach the user to the request object
    next(); // Proceed to the next middleware or route handler
  } catch (e) {
    console.log("error", e);
    res.status(401).send("Please authenticate"); // Return a 401 error if authentication fails
  }
};

module.exports = auth;
