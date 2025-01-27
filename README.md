The backend of the VenueVendor is the server-side component responsible for handling the application's core functionalities, data processing, and interactions with the database. It serves as the foundation for the app's operations, managing tasks such as user authentication, data storage, and business logic execution
Technologies
Node.js : Server-side runtime environment
Express.js : Backend Framework for building applications
MongoDB : NoSQL database for storing data
Mongoose : Object data modeling library 

Features:
Admin
post('/create' createCategory);
get('/get' getAllCategories);
put('/update/:id'updateCategory); 
delete('/delete/:id'deleteCategory); 
get('/search'searchCategory);

Book
post('/book'createBooking);
get('/category/:categoryId'getBookingsByCategory);
get('/bookeduser'getBookingsByUser);
get('/all'getAllBookings); 
patch('/cancel/:bookingId'cancelBooking)
delete('/delete/:bookingId'deleteBooking);

user
post("/create createUser);
router.post("/login" loginUser);

profile
post('/uploadProfilePic' uploadProfilePic);
get('/info' getUserInfo);

reviews
post('/reviews',authGuard createReview);
get('/reviews/:categoryId'getReviewsByCategory);

Environment Variables:
MONGODB_URL = mongodb://localhost:27017/VenueVendor
JWT_SECRET = SFDJHKHFJKHSJKL
