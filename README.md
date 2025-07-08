# Daveenci AI Authentication Service

A secure, production-ready OpenID Connect/OAuth 2.0 authentication service that enables Single Sign-On (SSO) across your Daveenci AI subdomains (`crm.daveenci.ai`, `avatar.daveenci.ai`, etc.).

## 🚀 Features

- **OpenID Connect/OAuth 2.0 compliant** identity provider
- **Single Sign-On (SSO)** across multiple subdomains
- **Secure JWT tokens** with proper validation
- **User registration and authentication** with bcrypt password hashing
- **Rate limiting and security headers** for production use
- **Modern, responsive UI** for login and registration
- **PostgreSQL integration** with existing user tables
- **Render deployment ready** with infrastructure as code

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   crm.daveenci  │    │  authentication  │    │ avatar.daveenci │
│       .ai       │◄──►│   .daveenci.ai   │◄──►│       .ai       │
│  (Service       │    │  (Identity       │    │  (Service       │
│   Provider)     │    │   Provider)      │    │   Provider)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ PostgreSQL   │
                       │ Database     │
                       │ (users table)│
                       └──────────────┘
```

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL database with existing `users` table
- Render account (for deployment)

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd daveenci-ai-website-authentication
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   Create a `.env` file in the root directory:
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development

   # Database Configuration
   DATABASE_URL=postgresql://username:password@localhost:5432/database_name

   # JWT Configuration (use a strong, random 256-bit key)
   JWT_SECRET=your_very_long_and_secure_jwt_secret_key_here_at_least_256_bits
   SESSION_SECRET=your_very_long_and_secure_session_secret_key_here

   # OAuth Clients Configuration
   CLIENTS=[{"clientId":"crm_app","clientSecret":"very_secret_crm_key","redirectUris":["https://crm.daveenci.ai/auth/callback"],"scopes":["openid","profile","email"]},{"clientId":"avatar_app","clientSecret":"very_secret_avatar_key","redirectUris":["https://avatar.daveenci.ai/auth/callback"],"scopes":["openid","profile"]}]

   # Security Configuration
   ISSUER_URL=https://authentication.daveenci.ai
   COOKIE_DOMAIN=.daveenci.ai
   CORS_ORIGIN=https://*.daveenci.ai
   ```

4. **Database Schema:**
   Ensure your PostgreSQL `users` table has this structure:
   ```sql
   CREATE TABLE public.users (
     id SERIAL PRIMARY KEY,
     email VARCHAR(255) UNIQUE NOT NULL,
     password VARCHAR(255) NOT NULL,
     name VARCHAR(100),
     validated BOOLEAN DEFAULT false,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```

## 🚦 Running Locally

1. **Development mode (with auto-restart):**
   ```bash
   npm run dev
   ```

2. **Production mode:**
   ```bash
   npm start
   ```

3. **Access the service:**
   - Login: http://localhost:3000/login
   - Register: http://localhost:3000/register
   - Discovery: http://localhost:3000/.well-known/openid_configuration

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `DATABASE_URL` | PostgreSQL connection string | ✅ | `postgresql://user:pass@host:5432/db` |
| `JWT_SECRET` | Secret for signing JWT tokens | ✅ | `your-256-bit-secret` |
| `SESSION_SECRET` | Secret for session cookies | ✅ | `your-session-secret` |
| `CLIENTS` | OAuth client configurations (JSON) | ✅ | See example above |
| `PORT` | Server port | ❌ | `3000` |
| `ISSUER_URL` | OAuth issuer URL | ❌ | `https://authentication.daveenci.ai` |
| `COOKIE_DOMAIN` | Cookie domain for SSO | ❌ | `.daveenci.ai` |
| `CORS_ORIGIN` | Allowed CORS origins | ❌ | `https://*.daveenci.ai` |

### OAuth Client Configuration

Each client in the `CLIENTS` array should have:

```json
{
  "clientId": "unique_client_identifier",
  "clientSecret": "secure_client_secret",
  "redirectUris": ["https://your-app.daveenci.ai/auth/callback"],
  "scopes": ["openid", "profile", "email"]
}
```

## 🌐 API Endpoints

### Authentication Endpoints
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Get user profile
- `GET /auth/status` - Check authentication status

### OAuth/OpenID Connect Endpoints
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `GET /oauth/userinfo` - UserInfo endpoint
- `POST /oauth/revoke` - Token revocation

### Discovery Endpoints
- `GET /.well-known/openid_configuration` - OpenID Connect Discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set

### Utility Endpoints
- `GET /health` - Health check
- `GET /` - Service information

## 🔒 Security Features

- **Rate limiting** on authentication endpoints
- **CORS protection** with domain whitelisting
- **Security headers** (CSP, XSS protection, etc.)
- **Input validation** and sanitization
- **Password strength requirements**
- **JWT token validation** with proper expiry
- **Session security** with HttpOnly, Secure, SameSite cookies
- **SQL injection protection** with parameterized queries

## 🚀 Deployment to Render

### Option 1: Using render.yaml (Recommended)

1. **Push your code to GitHub**

2. **Connect to Render:**
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New" → "Blueprint"
   - Connect your GitHub repository
   - Render will automatically detect the `render.yaml` file

3. **Set environment variables in Render Dashboard:**
   ```
   DATABASE_URL=your_postgresql_connection_string
   JWT_SECRET=your_jwt_secret
   SESSION_SECRET=your_session_secret
   CLIENTS=your_oauth_clients_json
   ```

4. **Configure custom domain:**
   - In your service settings, add `authentication.daveenci.ai` as a custom domain
   - Configure DNS to point to Render

### Option 2: Manual Setup

1. **Create a new Web Service**
2. **Connect your repository**
3. **Configure:**
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Environment: Node.js
4. **Add environment variables**
5. **Deploy**

## 🔗 Integration with Client Applications

### Authorization Code Flow Example

1. **Redirect user to authorization endpoint:**
   ```
   https://authentication.daveenci.ai/oauth/authorize?
     response_type=code&
     client_id=crm_app&
     redirect_uri=https://crm.daveenci.ai/auth/callback&
     scope=openid profile email&
     state=random_state_value
   ```

2. **Exchange authorization code for tokens:**
   ```bash
   curl -X POST https://authentication.daveenci.ai/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code=AUTHORIZATION_CODE" \
     -d "redirect_uri=https://crm.daveenci.ai/auth/callback" \
     -d "client_id=crm_app" \
     -d "client_secret=very_secret_crm_key"
   ```

3. **Get user information:**
   ```bash
   curl -X GET https://authentication.daveenci.ai/oauth/userinfo \
     -H "Authorization: Bearer ACCESS_TOKEN"
   ```

## 🧪 Testing

```bash
# Run tests (when implemented)
npm test

# Test the health endpoint
curl http://localhost:3000/health

# Test OpenID Connect discovery
curl http://localhost:3000/.well-known/openid_configuration
```

## 📝 Logging

The service logs important events:
- User registration and login attempts
- OAuth authorization grants
- Token issuance
- Security events (rate limiting, CORS violations)
- Errors and debugging information

## 🔧 Troubleshooting

### Common Issues

1. **Database connection errors:**
   - Verify `DATABASE_URL` is correct
   - Ensure PostgreSQL is running and accessible
   - Check firewall settings

2. **JWT token errors:**
   - Verify `JWT_SECRET` is set and consistent
   - Check token expiry times
   - Ensure proper token format

3. **CORS errors:**
   - Verify `CORS_ORIGIN` configuration
   - Check subdomain patterns
   - Ensure HTTPS in production

4. **Session issues:**
   - Verify `SESSION_SECRET` is set
   - Check cookie domain settings
   - Ensure proper HTTPS configuration

## 📚 Standards Compliance

This service implements:
- [OAuth 2.0 Authorization Framework (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Token (JWT) (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For support with this authentication service:
1. Check the troubleshooting section above
2. Review the logs for error messages
3. Verify your environment configuration
4. Create an issue in the repository

---

**Security Note:** Always use strong, unique secrets for `JWT_SECRET` and `SESSION_SECRET` in production. Never commit sensitive environment variables to your repository.