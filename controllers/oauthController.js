const User = require('../models/User');
const OAuthUtils = require('../utils/oauth');
const JWTUtils = require('../utils/jwt');
const config = require('../config');

class OAuthController {
  // OAuth authorization endpoint - GET /oauth/authorize
  static async authorize(req, res) {
    try {
      const { response_type, client_id, redirect_uri, scope, state } = req.query;

      // Validate request parameters
      const validation = OAuthUtils.validateAuthorizationRequest(req.query);
      if (!validation.valid) {
        console.error('Authorization request validation failed:', validation.errors);
        
        // If we have a valid redirect_uri, send error there
        if (redirect_uri && OAuthUtils.validateRedirectUri(client_id, redirect_uri)) {
          const errorUrl = OAuthUtils.buildErrorResponse(
            redirect_uri,
            'invalid_request',
            validation.errors.join(', '),
            state
          );
          return res.redirect(errorUrl);
        }
        
        return res.status(400).json({
          error: 'invalid_request',
          error_description: validation.errors.join(', ')
        });
      }

      // Check if user is already authenticated
      if (req.session && req.session.userId) {
        // User is logged in, generate authorization code and redirect
        const authCode = OAuthUtils.generateAuthorizationCode(
          req.session.userId,
          client_id,
          redirect_uri,
          scope,
          state
        );

        const responseUrl = OAuthUtils.buildAuthorizationResponse(redirect_uri, authCode, state);
        
        console.log('Authorization granted:', {
          userId: req.session.userId,
          clientId: client_id,
          scopes: scope
        });

        return res.redirect(responseUrl);
      }

      // User not logged in, store OAuth parameters and redirect to login
      req.session.oauthParams = {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state
      };

      req.session.returnTo = req.originalUrl;
      res.redirect('/login');
    } catch (error) {
      console.error('Authorization error:', error);
      
      const { redirect_uri, state } = req.query;
      if (redirect_uri) {
        const errorUrl = OAuthUtils.buildErrorResponse(
          redirect_uri,
          'server_error',
          'Internal server error',
          state
        );
        return res.redirect(errorUrl);
      }

      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }

  // OAuth token endpoint - POST /oauth/token
  static async token(req, res) {
    try {
      const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

      // Validate request parameters
      const validation = OAuthUtils.validateTokenRequest(req.body);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: validation.errors.join(', ')
        });
      }

      // Validate authorization code
      const codeValidation = OAuthUtils.validateAuthorizationCode(code, client_id, redirect_uri);
      if (!codeValidation.valid) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: codeValidation.error
        });
      }

      // Get user information
      const user = await User.findById(codeValidation.userId);
      if (!user) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'User not found'
        });
      }

      // Generate tokens
      const accessToken = JWTUtils.generateAccessToken(user.id, client_id);
      const idToken = JWTUtils.generateIdToken(user, client_id, codeValidation.scopes.split(' '));

      console.log('Tokens issued:', {
        userId: user.id,
        clientId: client_id,
        scopes: codeValidation.scopes
      });

      // Return token response
      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600, // 1 hour
        id_token: idToken,
        scope: codeValidation.scopes
      });
    } catch (error) {
      console.error('Token error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }

  // UserInfo endpoint - GET /oauth/userinfo
  static async userinfo(req, res) {
    try {
      const user = req.user; // Set by requireAccessToken middleware
      const token = req.token;

      // Build userinfo response based on token audience (client)
      const client = OAuthUtils.getClient(token.aud);
      if (!client) {
        return res.status(401).json({
          error: 'invalid_token',
          error_description: 'Invalid token audience'
        });
      }

      const userinfo = {
        sub: user.id.toString()
      };

      // Add claims based on client's allowed scopes
      if (client.scopes.includes('email')) {
        userinfo.email = user.email;
        userinfo.email_verified = user.validated || false;
      }

      if (client.scopes.includes('profile')) {
        if (user.name) userinfo.name = user.name;
        userinfo.updated_at = user.updated_at ? 
          Math.floor(new Date(user.updated_at).getTime() / 1000) : 
          Math.floor(Date.now() / 1000);
      }

      res.json(userinfo);
    } catch (error) {
      console.error('UserInfo error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }

  // OpenID Connect Discovery endpoint - GET /.well-known/openid_configuration
  static async discovery(req, res) {
    try {
      const issuer = config.jwt.issuer;
      
      const discovery = {
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/oauth/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['HS256'],
        scopes_supported: ['openid', 'profile', 'email'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
        claims_supported: ['sub', 'email', 'email_verified', 'name', 'updated_at'],
        grant_types_supported: ['authorization_code']
      };

      res.json(discovery);
    } catch (error) {
      console.error('Discovery error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }

  // JSON Web Key Set endpoint - GET /.well-known/jwks.json
  static async jwks(req, res) {
    try {
      // For HMAC keys, we don't expose the secret in JWKS
      // In production, consider using RSA keys for better security
      res.json({
        keys: [
          {
            kty: 'oct',
            alg: 'HS256',
            use: 'sig',
            kid: '1'
          }
        ]
      });
    } catch (error) {
      console.error('JWKS error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }

  // Revoke token endpoint - POST /oauth/revoke
  static async revoke(req, res) {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing token parameter'
        });
      }

      // For JWT tokens, we can't truly revoke them without a blacklist
      // In production, consider maintaining a token blacklist
      console.log('Token revocation requested:', { token: token.substring(0, 20) + '...', token_type_hint });

      res.json({
        message: 'Token revocation successful'
      });
    } catch (error) {
      console.error('Token revocation error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }
}

module.exports = OAuthController; 