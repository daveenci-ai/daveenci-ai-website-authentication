const express = require('express');
const router = express.Router();

const OAuthController = require('../controllers/oauthController');

// OpenID Connect Discovery endpoint
router.get('/openid_configuration', OAuthController.discovery);

// JSON Web Key Set endpoint
router.get('/jwks.json', OAuthController.jwks);

module.exports = router; 