const express = require('express');
const app = express();
const ipBlocker = require('./middleware/ipBlocker');

// ... other imports and middleware ...

// Apply IP blocker to all routes
app.use(ipBlocker);

// ... rest of your app configuration ... 