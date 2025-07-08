const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const config = require('../config');

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  message: {
    error: 'too_many_requests',
    error_description: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Strict rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    error: 'too_many_requests',
    error_description: 'Too many authentication attempts, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful requests
});

// Very strict rate limiting for token endpoint
const tokenLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: {
    error: 'too_many_requests',
    error_description: 'Too many token requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// User registration validation
const validateRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name must be between 1 and 100 characters'),
  handleValidationErrors
];

// User login validation
const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

// OAuth authorization validation
const validateAuthorization = [
  query('response_type')
    .equals('code')
    .withMessage('response_type must be "code"'),
  query('client_id')
    .notEmpty()
    .withMessage('client_id is required'),
  query('redirect_uri')
    .isURL()
    .withMessage('redirect_uri must be a valid URL'),
  query('scope')
    .notEmpty()
    .contains('openid')
    .withMessage('scope must include "openid"'),
  query('state')
    .notEmpty()
    .withMessage('state parameter is required'),
  handleValidationErrors
];

// OAuth token validation
const validateTokenRequest = [
  body('grant_type')
    .equals('authorization_code')
    .withMessage('grant_type must be "authorization_code"'),
  body('code')
    .notEmpty()
    .withMessage('code is required'),
  body('redirect_uri')
    .isURL()
    .withMessage('redirect_uri must be a valid URL'),
  body('client_id')
    .notEmpty()
    .withMessage('client_id is required'),
  body('client_secret')
    .notEmpty()
    .withMessage('client_secret is required'),
  handleValidationErrors
];

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // XSS Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Content Security Policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'"
  );
  
  next();
};

// CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin matches allowed pattern
    const allowedPattern = /^https:\/\/.*\.daveenci\.ai$/;
    if (allowedPattern.test(origin)) {
      return callback(null, true);
    }
    
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie']
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    };
    
    // Log authentication events
    if (req.originalUrl.includes('/oauth/') || req.originalUrl.includes('/login') || req.originalUrl.includes('/register')) {
      logData.userId = req.user?.id;
      logData.clientId = req.body?.client_id || req.query?.client_id;
    }
    
    console.log('Request:', JSON.stringify(logData));
  });
  
  next();
};

module.exports = {
  generalLimiter,
  authLimiter,
  tokenLimiter,
  validateRegistration,
  validateLogin,
  validateAuthorization,
  validateTokenRequest,
  securityHeaders,
  corsOptions,
  requestLogger,
  handleValidationErrors
}; 