const JWTUtils = require('../utils/jwt');
const User = require('../models/User');

// Middleware to check if user is authenticated via session
const requireSession = async (req, res, next) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required'
      });
    }

    // Optionally verify user still exists
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy((err) => {
        if (err) console.error('Session destroy error:', err);
      });
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'User not found'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Session authentication error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal authentication error'
    });
  }
};

// Middleware to check if user is authenticated via session (optional)
const optionalSession = async (req, res, next) => {
  try {
    if (req.session && req.session.userId) {
      const user = await User.findById(req.session.userId);
      if (user) {
        req.user = user;
      }
    }
    next();
  } catch (error) {
    console.error('Optional session authentication error:', error);
    // Continue without authentication
    next();
  }
};

// Middleware to verify JWT access token
const requireAccessToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = JWTUtils.extractBearerToken(authHeader);

    if (!token) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Missing or invalid access token'
      });
    }

    const decoded = JWTUtils.verifyToken(token);
    
    if (decoded.token_type !== 'access_token') {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid token type'
      });
    }

    // Get user information
    const user = await User.getProfile(decoded.sub);
    if (!user) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'User not found'
      });
    }

    req.user = user;
    req.token = decoded;
    next();
  } catch (error) {
    console.error('Access token verification error:', error);
    
    if (error.message === 'Invalid token') {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Invalid or expired access token'
      });
    }

    res.status(500).json({
      error: 'server_error',
      error_description: 'Token verification error'
    });
  }
};

// Middleware to redirect to login if not authenticated
const redirectToLogin = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    // Store original request for redirect after login
    req.session.returnTo = req.originalUrl;
    return res.redirect('/login');
  }
  next();
};

// Middleware to check if user is already logged in
const redirectIfAuthenticated = (req, res, next) => {
  if (req.session && req.session.userId) {
    const returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    return res.redirect(returnTo);
  }
  next();
};

module.exports = {
  requireSession,
  optionalSession,
  requireAccessToken,
  redirectToLogin,
  redirectIfAuthenticated
}; 