require('dotenv').config();

const config = {
  // Server Configuration
  port: process.env.PORT || 3000,
  
  // Database Configuration
  database: {
    url: process.env.DATABASE_URL
  },
  
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET,
    accessTokenExpiry: '1h',
    idTokenExpiry: '10m',
    issuer: process.env.ISSUER_URL || 'https://authentication.daveenci.ai'
  },
  
  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'lax',
      domain: process.env.COOKIE_DOMAIN || '.daveenci.ai'
    }
  },
  
  // OAuth Clients Configuration
  clients: JSON.parse(process.env.CLIENTS || '[]'),
  
  // Security Configuration
  cors: {
    origin: process.env.CORS_ORIGIN || 'https://*.daveenci.ai',
    credentials: true
  },
  
  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
  },
  
  // Environment
  isDevelopment: process.env.NODE_ENV === 'development',
  isProduction: process.env.NODE_ENV === 'production'
};

// Validation
if (!config.database.url) {
  throw new Error('DATABASE_URL environment variable is required');
}

if (!config.jwt.secret) {
  throw new Error('JWT_SECRET environment variable is required');
}

if (!config.session.secret) {
  throw new Error('SESSION_SECRET environment variable is required');
}

module.exports = config; 