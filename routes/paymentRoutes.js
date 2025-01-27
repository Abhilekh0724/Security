const express = require('express');
const paymentControllers = require('../controllers/paymentControllers');
const { authGuard } = require('../middleware/authGuard'); // Adjust the path as necessary

const paymentRouter = express.Router();

// Route to place a new order (requires authentication)
paymentRouter.post('/place', authGuard, paymentControllers.placeOrder);

// Route to handle eSewa payment success callback
paymentRouter.get('/esewa/success', paymentControllers.verifyEsewaPayment);

// Route to handle eSewa payment failure callback
paymentRouter.get('/esewa/fail', (req, res) => res.send('Payment Failed'));

// If verifyOrder is not implemented, comment out the line below or implement the function in paymentControllers
// paymentRouter.post('/verify', authGuard, paymentControllers.verifyOrder);

// Route to get all orders for the logged-in user (requires authentication)
// paymentRouter.post('/userorders', authGuard, paymentControllers.userOrders);

// Route to list all orders (admin access required)
// paymentRouter.get('/list', adminGuard, paymentControllers.listOrders);

// Route to update order status (admin access required)
// paymentRouter.post('/status', adminGuard, paymentControllers.updateStatus);

module.exports = paymentRouter;
