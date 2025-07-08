const express = require('express');
const router = express.Router();

const AuthController = require('../controllers/authController');
const { requireSession, redirectIfAuthenticated } = require('../middleware/auth');
const { authLimiter, validateRegistration, validateLogin } = require('../middleware/security');

// User registration
router.post('/register', 
  authLimiter,
  validateRegistration,
  AuthController.register
);

// User login
router.post('/login', 
  authLimiter,
  validateLogin,
  AuthController.login
);

// User logout
router.post('/logout', AuthController.logout);

// Get user profile (requires authentication)
router.get('/profile', requireSession, AuthController.profile);

// Check authentication status
router.get('/status', AuthController.status);

module.exports = router; 