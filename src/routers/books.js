const express = require("express");
const Book = require("../models/books");
const auth = require("../middleware/auth");
const router = new express.Router();

// Creating a book
router.post("/books", auth, async (req, res) => {
  const { title, description, author, publishdate } = req.body;

  // Check for required fields
  if (!title || !description || !author || !publishdate) {
    return res
      .status(400)
      .json({
        error:
          "All fields (title, description, author, publishdate) are required.",
      });
  }

  const book = new Book({
    ...req.body,
    owner: req.user.id,
  });

  try {
    await book.save();
    res.status(201).json(book);
  } catch (e) {
    if (e.name === "ValidationError") {
      return res.status(400).json({ error: e.message });
    }
    console.error(e);
    res
      .status(500)
      .json({ error: "An error occurred while creating the book." });
  }
});

// Getting all books
router.get("/books", auth, async (req, res) => {
  try {
    const books = await Book.find({ owner: req.user.id });

    if (books.length === 0) {
      return res.status(404).json({ error: "No books found for this user." });
    }

    res.status(200).json(books);
  } catch (e) {
    console.error(e);
    res
      .status(500)
      .json({ error: "An error occurred while retrieving books." });
  }
});

// Getting a book by its ID
router.get("/books/:id", auth, async (req, res) => {
  const _id = req.params.id;

  try {
    const book = await Book.findOne({ _id, owner: req.user._id });

    if (!book) {
      return res
        .status(404)
        .json({ error: "Book not found or not authorized." });
    }

    res.status(200).json(book);
  } catch (e) {
    console.error(e);
    res
      .status(500)
      .json({ error: "An error occurred while retrieving the book." });
  }
});

// Deleting a book by its ID
router.delete("/books/:id", auth, async (req, res) => {
  const _id = req.params.id;

  try {
    const book = await Book.findOneAndDelete({ _id, owner: req.user._id });

    if (!book) {
      return res
        .status(404)
        .json({ error: "Book not found or not authorized." });
    }

    res.status(200).json({ message: "Book deleted successfully." });
  } catch (e) {
    console.error(e);
    res
      .status(500)
      .json({ error: "An error occurred while deleting the book." });
  }
});

// Updating a book by its ID
router.patch("/books/:id", auth, async (req, res) => {
  const _id = req.params.id;
  const updates = Object.keys(req.body);
  const allowedUpdates = ["title", "description", "author", "publishdate"];
  const isValidOperation = updates.every((update) =>
    allowedUpdates.includes(update)
  );

  if (!isValidOperation) {
    return res.status(400).json({ error: "Invalid updates!" });
  }

  try {
    const book = await Book.findOne({ _id, owner: req.user._id });

    if (!book) {
      return res
        .status(404)
        .json({ error: "Book not found or not authorized." });
    }

    updates.forEach((update) => (book[update] = req.body[update]));

    await book.save();

    res.status(200).json(book);
  } catch (e) {
    if (e.name === "ValidationError") {
      return res.status(400).json({ error: e.message });
    }
    console.error(e);
    res
      .status(500)
      .json({ error: "An error occurred while updating the book." });
  }
});

module.exports = router;
