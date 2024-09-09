const mongoose = require("mongoose");

const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  description: {
    type: String,
    required: true,
    trim: true,
  },
  author:{
    type:String,
    required:true,
    trim:true
  },
  publishdate:{
    type:Date,
    required:true,

  },
  owner: {
    type: mongoose.Schema.Types.ObjectId, // Reference to the user who created the book
    required: true,
    ref: 'User' // Referencing the User model
  }
});

const Book = mongoose.model("Book", bookSchema);

module.exports = Book;