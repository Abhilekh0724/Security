const axios = require('axios');
const Booking = require('../models/bookModels');
const User = require('../models/userModels'); 

// Controller to place a new booking order
const placeOrder = async (req, res) => {
  try {
    // Create a new booking
    const newBooking = new Booking({
      userId: req.body.userId,
      categoryId: req.body.categoryId,
      bookingDate: req.body.bookingDate,
      status: 'pending', // Initially set status to 'pending'
    });

    // Save the new booking to the database
    await newBooking.save();

    // Prepare eSewa form data
    const esewaFormData = {
      amt: req.body.amount,
      psc: 0,
      pdc: 0,
      txAmt: 0,
      tAmt: req.body.amount,
      pid: newBooking._id,
      scd: process.env.ESEWA_SCD,
      su: `${process.env.ESEWA_SUCCESS_URL}?oid=${newBooking._id}&amt=${req.body.amount}&scd=${process.env.ESEWA_SCD}`,
      fu: process.env.ESEWA_FAIL_URL,
    };

    // Send the form data back to the client
    res.json({ success: true, formData: esewaFormData });
  } catch (error) {
    // Log and handle any errors
    console.error("Error placing booking:", error);
    res.status(500).json({
      success: false,
      message: "Error placing booking",
      error: error.message,
    });
  }
};

// Controller to verify eSewa payment
const verifyEsewaPayment = async (req, res) => {
  const { oid, amt, refId } = req.query;

  // Log the parameters being sent for verification
  console.log("Verifying eSewa Payment with parameters:", {
    amt,
    refId,
    oid,
    scd: process.env.ESEWA_SCD,
  });

  try {
    // Make a GET request to eSewa's transaction verification API
    const response = await axios.get('https://uat.esewa.com.np/epay/transrec', {
      params: {
        amt,
        rid: refId,
        pid: oid,
        scd: process.env.ESEWA_SCD,
      },
    });

    // Log the response from eSewa
    console.log("eSewa Verification Response:", response.data);

    // Check if the payment was successful
    if (response.data.response_code === "Success") {
      // Update the booking's status to 'paid'
      await Booking.findByIdAndUpdate(oid, { status: 'paid' });
      res.json({ success: true, message: "Payment Successful" });
    } else {
      // Handle payment verification failure
      console.log("Payment verification failed:", response.data);
      res.json({
        success: false,
        message: "Payment Verification Failed",
        details: response.data,
      });
    }
  } catch (error) {
    // Log and handle any errors
    console.error("Error verifying payment:", error);
    res.status(500).json({
      success: false,
      message: "Error verifying payment",
      error: error.message,
    });
  }
};

module.exports = {
  placeOrder,
  verifyEsewaPayment,
};
