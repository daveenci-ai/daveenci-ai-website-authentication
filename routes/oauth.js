const express = require('express');
const router = express.Router();

const OAuthController = require('../controllers/oauthController');
const { requireAccessToken, optionalSession } = require('../middleware/auth');
const { tokenLimiter, validateAuthorization, validateTokenRequest } = require('../middleware/security');

// OAuth Authorization endpoint
router.get('/authorize', 
  validateAuthorization,
  optionalSession,
  OAuthController.authorize
);

// OAuth Token endpoint
router.post('/token', 
  tokenLimiter,
  validateTokenRequest,
  OAuthController.token
);

// OAuth UserInfo endpoint
router.get('/userinfo', 
  requireAccessToken,
  OAuthController.userinfo
);

// Token revocation endpoint
router.post('/revoke', OAuthController.revoke);

module.exports = router; 