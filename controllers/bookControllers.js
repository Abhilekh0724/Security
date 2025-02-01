// controllers/bookControllers.js
const mongoose = require('mongoose');
const Booking = require('../models/bookModels');
const User = require('../models/userModels');
const Category = require('../models/adminModels');

// Create a new booking
exports.createBooking = async (req, res) => {
  const { categoryId, bookingDate, amount } = req.body;
  const userId = req.user.id;

  try {
    // Basic validation
    if (!categoryId || !bookingDate || !amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Category ID, booking date, and amount are required' 
      });
    }

    if (!mongoose.Types.ObjectId.isValid(categoryId)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid category ID' 
      });
    }

    // Validate booking date
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const bookingDateObj = new Date(bookingDate);
    bookingDateObj.setHours(0, 0, 0, 0);

    if (bookingDateObj < currentDate) {
      return res.status(400).json({ 
        success: false, 
        message: 'Booking date cannot be in the past' 
      });
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Check if category exists and validate amount
    const category = await Category.findById(categoryId);
    if (!category) {
      return res.status(404).json({ 
        success: false, 
        message: 'Category not found' 
      });
    }

    if (amount !== category.price) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid amount for this venue' 
      });
    }

    // Check for existing booking on the same date
    const existingBooking = await Booking.findOne({
      categoryId,
      bookingDate: bookingDateObj,
      status: { $ne: 'canceled' }
    });

    if (existingBooking) {
      return res.status(400).json({ 
        success: false, 
        message: 'This venue is already booked for the selected date' 
      });
    }

    // Create new booking
    const newBooking = new Booking({
      userId,
      categoryId,
      bookingDate: bookingDateObj,
      amount,
      status: 'pending'
    });

    const savedBooking = await newBooking.save();

    res.status(201).json({
      success: true,
      booking: savedBooking,
      message: 'Booking confirmed successfully. Please complete the payment within 5 days to avoid automatic cancellation.'
    });
  } catch (error) {
    console.error('Booking error:', error);
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
