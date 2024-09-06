const mongoose = require('mongoose');
require('dotenv').config(); // Load environment variables

const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    // useUnifiedTopology: true // Uncomment this if needed
})
.then(() => {
    console.log("Database connected successfully");
})
.catch((err) => {
    console.error("Database connection error:", err);
});