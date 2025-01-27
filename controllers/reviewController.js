const mongoose = require('mongoose');
const Review = require('../models/reviewModels');
const User = require('../models/userModels'); // Ensure this is the correct path
const Category = require('../models/adminModels'); // Ensure this is the correct path

// Create a new review
exports.createReview = async (req, res) => {
  const { categoryId, comment, rating } = req.body;
  const userId = req.user.id; // Extract userId from the token

  try {
    // Validate inputs
    if (!categoryId || !comment || !rating) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Validate ObjectIds
    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ success: false, message: 'Invalid categoryId' });
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check if category exists
    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({ success: false, message: 'Category not found' });
    }

    // Create and save the review
    const review = new Review({
      categoryId,
      userId,
      comment,
      rating,
    });
    await review.save();

    // Optionally, update the category's average rating
    const reviews = await Review.find({ categoryId });
    const averageRating = reviews.length ? reviews.reduce((acc, review) => acc + review.rating, 0) / reviews.length : 0;

    category.averageRating = averageRating;
    await category.save();

    res.status(201).json({ success: true, review });
  } catch (error) {
    console.error('Error creating review:', error);
    res.status(500).json({ success: false, message: 'Failed to create review', error });
  }
};

// Get reviews for a category
exports.getReviewsByCategory = async (req, res) => {
  const { categoryId } = req.params;

  try {
    // Validate categoryId
    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ success: false, message: 'Invalid categoryId' });
    }

    // Get all reviews for the category
    const reviews = await Review.find({ categoryId }).populate('userId', 'firstName lastName');
    res.status(200).json({ success: true, reviews });
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch reviews', error });
  }
};
