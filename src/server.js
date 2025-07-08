const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

// Load configuration
const config = require('../config');

// Import middleware
const { 
  generalLimiter, 
  securityHeaders, 
  corsOptions, 
  requestLogger 
} = require('../middleware/security');

// Import routes
const authRoutes = require('../routes/auth');
const oauthRoutes = require('../routes/oauth');
const wellKnownRoutes = require('../routes/wellknown');

// Import middleware for page routes
const { redirectToLogin, redirectIfAuthenticated } = require('../middleware/auth');

// Create Express app
const app = express();

// Trust proxy (important for Render deployment)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // We'll handle CSP in our custom middleware
  crossOriginEmbedderPolicy: false
}));

app.use(securityHeaders);

// CORS
app.use(cors(corsOptions));

// Request logging
app.use(requestLogger);

// Rate limiting
app.use(generalLimiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookie parsing
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  cookie: config.session.cookie,
  name: 'connect.sid'
}));

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: require('../package.json').version
  });
});

// Root endpoint
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({
      message: 'Daveenci AI Authentication Service',
      authenticated: true,
      user: {
        id: req.session.userId
      },
      endpoints: {
        login: '/login',
        register: '/register',
        logout: '/auth/logout',
        profile: '/auth/profile',
        oauth_authorize: '/oauth/authorize',
        oauth_token: '/oauth/token',
        oauth_userinfo: '/oauth/userinfo',
        discovery: '/.well-known/openid_configuration'
      }
    });
  } else {
    res.json({
      message: 'Daveenci AI Authentication Service',
      authenticated: false,
      endpoints: {
        login: '/login',
        register: '/register',
        oauth_authorize: '/oauth/authorize',
        oauth_token: '/oauth/token',
        oauth_userinfo: '/oauth/userinfo',
        discovery: '/.well-known/openid_configuration'
      }
    });
  }
});

// Serve login page
app.get('/login', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

// Serve registration page
app.get('/register', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/register.html'));
});

// API routes
app.use('/auth', authRoutes);
app.use('/oauth', oauthRoutes);
app.use('/.well-known', wellKnownRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // Handle CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      error: 'forbidden',
      error_description: 'CORS policy violation'
    });
  }
  
  // Handle validation errors
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid JSON in request body'
    });
  }
  
  // Handle payload too large
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'payload_too_large',
      error_description: 'Request payload too large'
    });
  }
  
  // Generic error response
  res.status(500).json({
    error: 'server_error',
    error_description: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'not_found',
    error_description: 'Endpoint not found'
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// Start server
const PORT = config.port;
const server = app.listen(PORT, () => {
  console.log(`🚀 Daveenci AI Authentication Service running on port ${PORT}`);
  console.log(`🌍 Environment: ${config.isDevelopment ? 'development' : 'production'}`);
  console.log(`🔑 JWT Issuer: ${config.jwt.issuer}`);
  console.log(`📱 Registered clients: ${config.clients.length}`);
  console.log(`💾 Database: ${config.database.url ? 'Connected' : 'Not configured'}`);
  
  if (config.isDevelopment) {
    console.log(`🔗 Login: http://localhost:${PORT}/login`);
    console.log(`🔗 Register: http://localhost:${PORT}/register`);
    console.log(`🔗 Discovery: http://localhost:${PORT}/.well-known/openid_configuration`);
  }
});

module.exports = app; 