const nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "f5be83db0ae821",
      pass: "465c2e3a949328"
    }
  });

module.exports = transporter;