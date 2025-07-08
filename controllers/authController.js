const User = require('../models/User');
const config = require('../config');

class AuthController {
  // User registration
  static async register(req, res) {
    try {
      const { email, password, name } = req.body;

      // Check if user already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(400).json({
          error: 'user_exists',
          error_description: 'A user with this email already exists'
        });
      }

      // Create new user
      const user = await User.create({ email, password, name });
      
      console.log('User registered:', { userId: user.id, email: user.email });

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          validated: user.validated
        }
      });
    } catch (error) {
      console.error('Registration error:', error);
      
      if (error.message === 'Email already exists') {
        return res.status(400).json({
          error: 'user_exists',
          error_description: 'A user with this email already exists'
        });
      }

      res.status(500).json({
        error: 'server_error',
        error_description: 'Registration failed'
      });
    }
  }

  // User login
  static async login(req, res) {
    try {
      const { email, password } = req.body;

      // Find user by email
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(401).json({
          error: 'invalid_credentials',
          error_description: 'Invalid email or password'
        });
      }

      // Verify password
      const isValidPassword = await User.verifyPassword(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({
          error: 'invalid_credentials',
          error_description: 'Invalid email or password'
        });
      }

      // Create session
      req.session.userId = user.id;
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
        }
      });

      console.log('User logged in:', { userId: user.id, email: user.email });

      // Check if there's a return URL from OAuth flow
      const returnTo = req.session.returnTo;
      if (returnTo) {
        delete req.session.returnTo;
        return res.json({
          message: 'Login successful',
          redirectUrl: returnTo,
          user: {
            id: user.id,
            email: user.email,
            name: user.name
          }
        });
      }

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Login failed'
      });
    }
  }

  // User logout
  static async logout(req, res) {
    try {
      const userId = req.session?.userId;
      
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destroy error:', err);
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Logout failed'
          });
        }

        // Clear session cookie
        res.clearCookie('connect.sid', {
          domain: config.session.cookie.domain,
          httpOnly: true,
          secure: config.session.cookie.secure,
          sameSite: config.session.cookie.sameSite
        });

        console.log('User logged out:', { userId });

        res.json({
          message: 'Logout successful'
        });
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Logout failed'
      });
    }
  }

  // Get current user profile
  static async profile(req, res) {
    try {
      res.json({
        user: {
          id: req.user.id,
          email: req.user.email,
          name: req.user.name,
          validated: req.user.validated,
          created_at: req.user.created_at
        }
      });
    } catch (error) {
      console.error('Profile error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to get profile'
      });
    }
  }

  // Check authentication status
  static async status(req, res) {
    try {
      if (req.session && req.session.userId) {
        const user = await User.findById(req.session.userId);
        if (user) {
          return res.json({
            authenticated: true,
            user: {
              id: user.id,
              email: user.email,
              name: user.name
            }
          });
        }
      }

      res.json({
        authenticated: false
      });
    } catch (error) {
      console.error('Status check error:', error);
      res.json({
        authenticated: false
      });
    }
  }
}

module.exports = AuthController; 