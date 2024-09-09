const jwt=require('jsonwebtoken')
const User=require('../models/user')

const auth = (req, res, next) => {
    try {
      const token = req.header('Authorization').replace('Bearer ', '');
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (e) {
      res.status(401).send("Please authenticate");
    }
  };
  
module.exports=auth