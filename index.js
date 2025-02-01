const express = require('express');
const dotenv = require('dotenv');
const connectDb = require('./database/database');
const cors = require('cors');
const fileupload = require('express-fileupload');
const path = require('path');
const https = require('https');
const fs = require('fs');
const helmet = require('helmet');

dotenv.config();

const app = express();

// Regular middleware first
app.use(express.json());
app.use(fileupload());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors({
  origin: 'https://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false, // We'll configure CSP separately
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: false,
  })
);

// Configure CSP separately
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "img-src 'self' data: blob: https: http: *; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com; " +
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "connect-src 'self' https://localhost:5500 https://localhost:3000; " +
    "font-src 'self' https://cdn.jsdelivr.net data:; " +
    "object-src 'none'; " +
    "media-src 'self'; " +
    "frame-src 'self' https://www.google.com"
  );
  next();
});

// Connect to MongoDB
connectDb();

// Routes
app.use('/api/user', require('./routes/userRoutes'));
app.use('/api/profile', require('./routes/profileRoutes'));
app.use('/api/admin', require('./routes/adminRoutes'));
app.use('/api/review', require('./routes/reviewRoutes'));
app.use('/api/book', require('./routes/bookRoutes'));
app.use('/api/payment', require('./routes/paymentRoutes'));

if (require.main === module) {
  const PORT = process.env.PORT || 5500;
  
  // SSL certificate configuration
  const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'ssl', 'private.key')),
    cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.crt'))
  };

  // Create HTTPS server
  const server = https.createServer(sslOptions, app);
  
  server.listen(PORT, () => {
    console.log(`HTTPS Server is running on port ${PORT}`);
  });
}

module.exports = app;
