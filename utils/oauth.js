const { v4: uuidv4 } = require('uuid');
const config = require('../config');

// In-memory storage for authorization codes (use Redis in production)
const authorizationCodes = new Map();

class OAuthUtils {
  // Get client by ID
  static getClient(clientId) {
    return config.clients.find(client => client.clientId === clientId);
  }

  // Validate client credentials
  static validateClient(clientId, clientSecret) {
    const client = this.getClient(clientId);
    return client && client.clientSecret === clientSecret;
  }

  // Check if redirect URI is valid for client
  static validateRedirectUri(clientId, redirectUri) {
    const client = this.getClient(clientId);
    return client && client.redirectUris.includes(redirectUri);
  }

  // Check if requested scopes are valid for client
  static validateScopes(clientId, requestedScopes) {
    const client = this.getClient(clientId);
    if (!client) return false;

    const requestedScopeArray = requestedScopes.split(' ');
    return requestedScopeArray.every(scope => client.scopes.includes(scope));
  }

  // Generate authorization code
  static generateAuthorizationCode(userId, clientId, redirectUri, scopes, state) {
    const code = uuidv4();
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    authorizationCodes.set(code, {
      userId,
      clientId,
      redirectUri,
      scopes,
      state,
      expiry,
      used: false
    });

    // Clean up expired codes periodically
    this.cleanupExpiredCodes();

    return code;
  }

  // Validate and consume authorization code
  static validateAuthorizationCode(code, clientId, redirectUri) {
    const codeData = authorizationCodes.get(code);
    
    if (!codeData) {
      return { valid: false, error: 'Invalid authorization code' };
    }

    if (codeData.used) {
      return { valid: false, error: 'Authorization code already used' };
    }

    if (new Date() > codeData.expiry) {
      authorizationCodes.delete(code);
      return { valid: false, error: 'Authorization code expired' };
    }

    if (codeData.clientId !== clientId) {
      return { valid: false, error: 'Client ID mismatch' };
    }

    if (codeData.redirectUri !== redirectUri) {
      return { valid: false, error: 'Redirect URI mismatch' };
    }

    // Mark as used and return data
    codeData.used = true;
    authorizationCodes.set(code, codeData);

    // Delete after a short delay to prevent reuse
    setTimeout(() => {
      authorizationCodes.delete(code);
    }, 1000);

    return {
      valid: true,
      userId: codeData.userId,
      scopes: codeData.scopes,
      state: codeData.state
    };
  }

  // Clean up expired authorization codes
  static cleanupExpiredCodes() {
    const now = new Date();
    for (const [code, data] of authorizationCodes.entries()) {
      if (now > data.expiry) {
        authorizationCodes.delete(code);
      }
    }
  }

  // Validate OAuth request parameters
  static validateAuthorizationRequest(query) {
    const { response_type, client_id, redirect_uri, scope, state } = query;
    const errors = [];

    if (!response_type || response_type !== 'code') {
      errors.push('Invalid or missing response_type. Must be "code"');
    }

    if (!client_id) {
      errors.push('Missing client_id parameter');
    } else if (!this.getClient(client_id)) {
      errors.push('Invalid client_id');
    }

    if (!redirect_uri) {
      errors.push('Missing redirect_uri parameter');
    } else if (client_id && !this.validateRedirectUri(client_id, redirect_uri)) {
      errors.push('Invalid redirect_uri for this client');
    }

    if (!scope) {
      errors.push('Missing scope parameter');
    } else if (!scope.includes('openid')) {
      errors.push('Scope must include "openid" for OpenID Connect');
    } else if (client_id && !this.validateScopes(client_id, scope)) {
      errors.push('Invalid scope for this client');
    }

    if (!state) {
      errors.push('Missing state parameter (required for security)');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Validate token request parameters
  static validateTokenRequest(body) {
    const { grant_type, code, redirect_uri, client_id, client_secret } = body;
    const errors = [];

    if (!grant_type || grant_type !== 'authorization_code') {
      errors.push('Invalid or missing grant_type. Must be "authorization_code"');
    }

    if (!code) {
      errors.push('Missing code parameter');
    }

    if (!redirect_uri) {
      errors.push('Missing redirect_uri parameter');
    }

    if (!client_id) {
      errors.push('Missing client_id parameter');
    }

    if (!client_secret) {
      errors.push('Missing client_secret parameter');
    }

    if (client_id && client_secret && !this.validateClient(client_id, client_secret)) {
      errors.push('Invalid client credentials');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Build authorization response URL
  static buildAuthorizationResponse(redirectUri, code, state) {
    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    url.searchParams.set('state', state);
    return url.toString();
  }

  // Build error response URL
  static buildErrorResponse(redirectUri, error, errorDescription, state) {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    if (errorDescription) {
      url.searchParams.set('error_description', errorDescription);
    }
    if (state) {
      url.searchParams.set('state', state);
    }
    return url.toString();
  }
}

module.exports = OAuthUtils; 