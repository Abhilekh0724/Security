// controllers/bookControllers.js
const mongoose = require('mongoose');
const Booking = require('../models/bookModels');
const User = require('../models/userModels');
const Category = require('../models/adminModels');

// Create a new booking
exports.createBooking = async (req, res) => {
  const { categoryId, bookingDate } = req.body;
  const userId = req.user.id; // Corrected to use `id` instead of `_id`

  try {
    if (!categoryId || !bookingDate) {
      return res.status(400).json({ success: false, message: 'Category ID and booking date are required' });
    }

    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ success: false, message: 'Invalid categoryId' });
    }

    const currentDate = new Date();
    if (new Date(bookingDate) < currentDate) {
      return res.status(400).json({ success: false, message: 'Booking date cannot be in the past' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({ success: false, message: 'Category not found' });
    }

    const existingBooking = await Booking.findOne({ userId, categoryId });
    if (existingBooking) {
      return res.status(400).json({ success: false, message: 'You cannot book this category more than once' });
    }

    const newBooking = new Booking({ userId, categoryId, bookingDate });
    const savedBooking = await newBooking.save();

    res.status(201).json({
      success: true,
      booking: savedBooking,
      message: 'Booking successful. Payment should be made 5 days before the booked date, or it will get canceled.'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to create booking',
      error: error.message
    });
  }
};

// Get bookings by category
exports.getBookingsByCategory = async (req, res) => {
  const { categoryId } = req.params;

  try {
    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ success: false, message: 'Invalid categoryId' });
    }

    const bookings = await Booking.find({ categoryId })
      .populate('userId', 'firstName lastName') // Populate booker's name
      .populate('categoryId'); // Populate category details

    res.status(200).json({ success: true, bookings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch bookings', error });
  }
};

// Get bookings by user
exports.getBookingsByUser = async (req, res) => {
  const userId = req.user.id;

  try {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid userId' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const bookings = await Booking.find({ userId }).populate('categoryId');
    res.status(200).json({ success: true, bookings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch bookings', error });
  }
};

// Cancel a booking
exports.cancelBooking = async (req, res) => {
  const { bookingId } = req.params;

  try {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      return res.status(400).json({ success: false, message: 'Invalid bookingId' });
    }

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    booking.status = 'canceled';
    await booking.save();

    res.status(200).json({ success: true, message: 'Booking canceled successfully', booking });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to cancel booking', error });
  }
};

// Delete a booking
exports.deleteBooking = async (req, res) => {
  const { bookingId } = req.params;

  try {
    if (!mongoose.Types.ObjectId.isValid(bookingId)) {
      return res.status(400).json({ success: false, message: 'Invalid bookingId' });
    }

    const booking = await Booking.findByIdAndDelete(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    res.status(200).json({ success: true, message: 'Booking deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete booking', error });
  }
};

// Get all bookings (admin only)
exports.getAllBookings = async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const bookings = await Booking.find()
      .populate('categoryId')
      .populate('userId', 'firstName lastName'); // Populate booker's name

    res.status(200).json({ success: true, bookings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch bookings', error });
  }
};
