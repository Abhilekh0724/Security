// routes/bookRoutes.js
const express = require('express');
const router = express.Router();
const BookingController = require('../controllers/bookControllers');
const { authGuard, adminGuard } = require('../middleware/authGuard');

// Create a booking
router.post('/book', authGuard, BookingController.createBooking);

// Get bookings by category
router.get('/category/:categoryId', authGuard, BookingController.getBookingsByCategory);

// Get bookings by user
router.get('/bookeduser', authGuard, BookingController.getBookingsByUser);

// Get all bookings (admin only)
router.get('/all', authGuard, adminGuard, BookingController.getAllBookings); // Ensure this route is protected for admins only

// Cancel a booking
router.patch('/cancel/:bookingId', authGuard, BookingController.cancelBooking);

// Delete a booking
router.delete('/delete/:bookingId', authGuard, BookingController.deleteBooking);

module.exports = router;
