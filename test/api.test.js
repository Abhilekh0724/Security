const request = require('supertest');
const app = require('../index');  // Import your app here
const mongoose = require('mongoose');
const User = require('../models/userModels');  // Import User model
const Booking = require('../models/bookModels');
const Category = require('../models/adminModels');

// Mock the models
jest.mock('../models/userModels');
jest.mock('../models/bookModels');
jest.mock('../models/adminModels');

// Valid JWT Token
const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2YjQ2OTBkYTNjMjMyM2U0NzA4NzUyNCIsImlzQWRtaW4iOnRydWUsImlhdCI6MTcyMzIxOTg3NH0.EgJ1kPdpmKPvENy_3HeEdRlFQpaNBC5Guv7Cb1pfaSM';

let server;

beforeAll((done) => {
  server = app.listen(5500, () => {
    console.log('Test server running on port 5500');
    done();
  });
});

afterAll(async () => {
  await mongoose.connection.close();  // Ensure MongoDB connection is closed
  server.close(() => {
    console.log('Server closed');
  });
});

describe('User API Tests', () => {
  // Test for creating a new user
  it('POST /api/user/create | Should create a new user', async () => {
    // Mock implementation of userModel.findOne
    User.findOne = jest.fn().mockResolvedValue(null);
    // Mock implementation of userModel.save
    User.prototype.save = jest.fn().mockResolvedValue({});

    const response = await request(app)
      .post('/api/user/create')
      .send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        password: 'password123',
      });

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toEqual('User created successfully');
  });

  // Test for logging in a user
  it('POST /api/user/login | Should log in a user', async () => {
    // Mock implementation of userModel.findOne
    User.findOne = jest.fn().mockResolvedValue({
      _id: '123',
      email: 'jane.doe@example.com',
      password: 'hashedpassword',  // Simulate a hashed password
    });
    // Mock implementation of bcrypt.compare
    const bcrypt = require('bcrypt');
    bcrypt.compare = jest.fn().mockResolvedValue(true);
    // Mock implementation of jwt.sign
    const jwt = require('jsonwebtoken');
    jwt.sign = jest.fn().mockReturnValue(validToken);

    const response = await request(app)
      .post('/api/user/login')
      .send({
        email: 'jane.doe@example.com',
        password: 'password123',
      });

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body).toHaveProperty('token');
    expect(response.body).toHaveProperty('userData');
    expect(response.body.userData.email).toBe('jane.doe@example.com');
  });
});

describe('Booking API Tests', () => {
  it('POST /api/book/book | Should create a new booking', async () => {
    User.findById = jest.fn().mockResolvedValue({ _id: '66b4690da3c2323e47087524' });
    Category.findById = jest.fn().mockResolvedValue({ _id: '66b639f30d37770ba74e7cee' });
    Booking.findOne = jest.fn().mockResolvedValue(null);
    Booking.prototype.save = jest.fn().mockResolvedValue({});

    const response = await request(app)
      .post('/api/book/book')
      .set('Authorization', `Bearer ${validToken}`) // Use valid token
      .send({
        categoryId: 'categoryId',
        bookingDate: new Date().toISOString(),
      });

    expect(response.statusCode).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toEqual('Booking successful. Payment should be made 5 days before the booked date, or it will get canceled.');
  });

  it('GET /api/book/category/:categoryId | Should get bookings by category', async () => {
    Booking.find = jest.fn().mockResolvedValue([
      { _id: 'bookingId', userId: 'userId', categoryId: 'categoryId', bookingDate: new Date().toISOString() },
    ]);
    User.findById = jest.fn().mockResolvedValue({ firstName: 'John', lastName: 'Doe' });
    Category.findById = jest.fn().mockResolvedValue({});

    const response = await request(app)
      .get('/api/book/category/categoryId')
      .set('Authorization', `Bearer ${validToken}`);

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.bookings).toBeDefined();
  });

  it('GET /api/book/bookeduser | Should get bookings by user', async () => {
    Booking.find = jest.fn().mockResolvedValue([
      { _id: 'bookingId', userId: 'userId', categoryId: 'categoryId', bookingDate: new Date().toISOString() },
    ]);
    Category.findById = jest.fn().mockResolvedValue({});

    const response = await request(app)
      .get('/api/book/bookeduser')
      .set('Authorization', `Bearer ${validToken}`);

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.bookings).toBeDefined();
  });

  it('PATCH /api/book/cancel/:bookingId | Should cancel a booking', async () => {
    Booking.findById = jest.fn().mockResolvedValue({ _id: 'bookingId', save: jest.fn() });

    const response = await request(app)
      .patch('/api/book/cancel/bookingId')
      .set('Authorization', `Bearer ${validToken}`);

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toEqual('Booking canceled successfully');
  });

  it('DELETE /api/book/delete/:bookingId | Should delete a booking', async () => {
    Booking.findByIdAndDelete = jest.fn().mockResolvedValue({ _id: 'bookingId' });

    const response = await request(app)
      .delete('/api/book/delete/bookingId')
      .set('Authorization', `Bearer ${validToken}`);

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.message).toEqual('Booking deleted successfully');
  });

  it('GET /api/book/all | Should get all bookings (admin only)', async () => {
    Booking.find = jest.fn().mockResolvedValue([
      { _id: 'bookingId', userId: 'userId', categoryId: 'categoryId', bookingDate: new Date().toISOString() },
    ]);
    User.findById = jest.fn().mockResolvedValue({ firstName: 'John', lastName: 'Doe', isAdmin: true });
    Category.findById = jest.fn().mockResolvedValue({});

    // Mock user being an admin
    const authGuardMock = (req, res, next) => {
      req.user = { isAdmin: true };
      next();
    };
    app.use('/api/book/all', authGuardMock);

    const response = await request(app)
      .get('/api/book/all')
      .set('Authorization', `Bearer ${validToken}`);

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.bookings).toBeDefined();
  });
});
describe('Admin API Tests', () => {
    // Test for creating a new category
    it('POST /api/admin/create | Should create a new category', async () => {
      Category.prototype.save = jest.fn().mockResolvedValue({
        price: 100,
        name: 'Test Category',
        info: 'Category Info',
        photo: '/uploads/test-photo.jpg',
      });
  
      const response = await request(app)
        .post('/api/admin/create')
        .set('Authorization', `Bearer ${validToken}`) 
        .field('price', 100)
        .field('name', 'Test Category')
        .field('info', 'Category Info')
        .attach('photo', 'category.photo'); // Ensure the path is valid in your environment
  
      expect(response.statusCode).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toEqual('Category Created!');
    });
  
    // Test for fetching all categories
    it('GET /api/admin/get | Should fetch all categories', async () => {
      Category.find = jest.fn().mockResolvedValue([
        { _id: 'categoryId1', price: 100, name: 'Category 1', info: 'Info 1' },
        { _id: 'categoryId2', price: 200, name: 'Category 2', info: 'Info 2' },
      ]);
  
      const response = await request(app)
        .get('/api/admin/get')
        .set('Authorization', `Bearer ${validToken}`); // Use valid token
  
      expect(response.statusCode).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.categories).toHaveLength(2);
    });
  
    // Test for updating a category
    it('PUT /api/admin/update/:id | Should update a category', async () => {
      Category.findByIdAndUpdate = jest.fn().mockResolvedValue({
        _id: 'categoryId',
        price: 150,
        name: 'Updated Category',
        info: 'Updated Info',
        photo: '/uploads/updated-photo.jpg',
      });
  
      const response = await request(app)
        .put('/api/admin/update/categoryId')
        .set('Authorization', `Bearer ${eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2YjQ2OTBkYTNjMjMyM2U0NzA4NzUyNCIsImlzQWRtaW4iOnRydWUsImlhdCI6MTcyMzIxOTg3NH0.EgJ1kPdpmKPvENy_3HeEdRlFQpaNBC5Guv7Cb1pfaSM}`) // Use valid token
        .field('price', 150)
        .field('name', 'Updated Category')
        .field('info', 'Updated Info')
        .attach('photo', 'public/uploads'); 
  
      expect(response.statusCode).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toEqual('Category updated successfully!');
    });
  
    // Test for deleting a category
    it('DELETE /api/admin/delete/:id | Should delete a category', async () => {
      Category.findByIdAndDelete = jest.fn().mockResolvedValue({
        _id: 'categoryId',
        price: 100,
        name: 'Category to Delete',
        info: 'Info to Delete',
      });
  
      const response = await request(app)
        .delete('/api/admin/delete/categoryId')
        .set('Authorization', `Bearer ${validToken}`);
  
      expect(response.statusCode).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toEqual('Category deleted successfully!');
    });
  
    // Test for fetching a single category by ID
    it('GET /api/admin/get/:id | Should fetch a single category by ID', async () => {
      Category.findById = jest.fn().mockResolvedValue({
        _id: 'categoryId',
        price: 100,
        name: 'Single Category',
        info: 'Single Category Info',
        photo: '/uploads/single-category.jpg',
      });
  
      const response = await request(app)
        .get('/api/admin/get/categoryId')
        .set('Authorization', `Bearer ${validToken}`); 
  
      expect(response.statusCode).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.category).toBeDefined();
    });
  });
  