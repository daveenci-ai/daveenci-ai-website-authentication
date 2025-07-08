const bcrypt = require('bcrypt');
const { query } = require('./database');

class User {
  // Find user by email
  static async findByEmail(email) {
    try {
      const result = await query(
        'SELECT * FROM public.users WHERE email = $1',
        [email]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw new Error('Database error');
    }
  }

  // Find user by ID
  static async findById(id) {
    try {
      const result = await query(
        'SELECT * FROM public.users WHERE id = $1',
        [id]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by ID:', error);
      throw new Error('Database error');
    }
  }

  // Create new user
  static async create({ email, password, name = null }) {
    try {
      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const result = await query(
        `INSERT INTO public.users (email, password, name, validated, created_at, updated_at) 
         VALUES ($1, $2, $3, false, NOW(), NOW()) 
         RETURNING id, email, name, validated, created_at`,
        [email, hashedPassword, name]
      );

      return result.rows[0];
    } catch (error) {
      console.error('Error creating user:', error);
      if (error.code === '23505') { // Unique constraint violation
        throw new Error('Email already exists');
      }
      throw new Error('Database error');
    }
  }

  // Verify password
  static async verifyPassword(plainPassword, hashedPassword) {
    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      console.error('Error verifying password:', error);
      throw new Error('Password verification error');
    }
  }

  // Update user
  static async update(id, updates) {
    try {
      const fields = [];
      const values = [];
      let paramIndex = 1;

      Object.keys(updates).forEach(key => {
        if (updates[key] !== undefined) {
          fields.push(`${key} = $${paramIndex}`);
          values.push(updates[key]);
          paramIndex++;
        }
      });

      if (fields.length === 0) {
        throw new Error('No fields to update');
      }

      fields.push(`updated_at = NOW()`);
      values.push(id);

      const result = await query(
        `UPDATE public.users SET ${fields.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
        values
      );

      return result.rows[0] || null;
    } catch (error) {
      console.error('Error updating user:', error);
      throw new Error('Database error');
    }
  }

  // Get user profile (without sensitive data)
  static async getProfile(id) {
    try {
      const result = await query(
        'SELECT id, email, name, validated, created_at FROM public.users WHERE id = $1',
        [id]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error getting user profile:', error);
      throw new Error('Database error');
    }
  }

  // Validate email format
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password strength
  static isValidPassword(password) {
    return password && password.length >= 8;
  }
}

module.exports = User; 