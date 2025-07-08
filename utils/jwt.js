const jwt = require('jsonwebtoken');
const config = require('../config');

class JWTUtils {
  // Generate access token
  static generateAccessToken(userId, clientId) {
    const payload = {
      sub: userId.toString(),
      aud: clientId,
      iss: config.jwt.issuer,
      iat: Math.floor(Date.now() / 1000),
      token_type: 'access_token'
    };

    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.accessTokenExpiry
    });
  }

  // Generate ID token
  static generateIdToken(user, clientId, scopes = []) {
    const now = Math.floor(Date.now() / 1000);
    
    const payload = {
      sub: user.id.toString(),
      aud: clientId,
      iss: config.jwt.issuer,
      iat: now,
      auth_time: now
    };

    // Add claims based on requested scopes
    if (scopes.includes('email') && user.email) {
      payload.email = user.email;
      payload.email_verified = user.validated || false;
    }

    if (scopes.includes('profile')) {
      if (user.name) payload.name = user.name;
      payload.updated_at = user.updated_at ? Math.floor(new Date(user.updated_at).getTime() / 1000) : now;
    }

    return jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.idTokenExpiry
    });
  }

  // Verify and decode token
  static verifyToken(token) {
    try {
      return jwt.verify(token, config.jwt.secret);
    } catch (error) {
      console.error('JWT verification error:', error.message);
      throw new Error('Invalid token');
    }
  }

  // Decode token without verification (for debugging)
  static decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      console.error('JWT decode error:', error.message);
      return null;
    }
  }

  // Check if token is expired
  static isTokenExpired(token) {
    try {
      const decoded = jwt.decode(token);
      if (!decoded || !decoded.exp) return true;
      
      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch (error) {
      return true;
    }
  }

  // Extract bearer token from authorization header
  static extractBearerToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7);
  }
}

module.exports = JWTUtils; 