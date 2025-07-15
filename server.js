const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const requiredEnvVars = ['JWT_SECRET', 'BASE_URL', 'EMAIL_HOST', 'EMAIL_PORT'];

requiredEnvVars.forEach(env => {
  if (!process.env[env]) {
    console.error(`FATAL ERROR: Missing required environment variable: ${env}`);
    process.exit(1);
  }
});

const app = express();


// Add CSP headers right here ▼
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', `
    default-src 'self';
    script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com;
    style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com;
    img-src 'self' data:;
    font-src 'self' cdnjs.cloudflare.com;
    connect-src 'self' ${process.env.API_BASE_URL || 'http://localhost:3000'};
  `.replace(/\s+/g, ' '));
  next();
});


// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'usersdb',
  password: 'sagar123',
  port: 5432,
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false,
  },
});


// Registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;
    
    // Check if user exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1', 
      [email]
    );
    
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Create user
    const newUser = await pool.query(
      `INSERT INTO users (full_name, email, phone, password, verification_token) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [fullName, email, phone, hashedPassword, verificationToken]
    );

    
    // Send verification email
 await transporter.sendMail({
  from: `"InvestSecure" <${process.env.EMAIL_USER}>`,
  to: email,
  subject: 'Verify Your Email',
  html: `
    <h2>Welcome to InvestSecure!</h2>
    <p>Please verify your email by clicking the link below:</p>
    <a href="${process.env.BASE_URL}/verify-email?token=${verificationToken}">
      Verify Email
    </a>
    <p>If you didn't request this, please ignore this email.</p>
  `,
});

    res.status(201).json({ message: 'Registration successful. Please check your email.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});



// Add login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
         // Check if user exists
        if (user.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  // Check password
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

         // Check if email is verified
            if (!user.rows[0].is_verified) {
            return res.status(403).json({ 
                error: 'Email not verified',
                message: 'Please check your email for verification link',
                needsVerification: true
            });
        }
        
        // Generate JWT
        const token = jwt.sign(
            { userId: user.rows[0].id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

         // Set secure cookie here ▼
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict', // Prevent CSRF
      maxAge: 3600000, // 1 hour expiration (matches your JWT expiry)
      path: '/', // Accessible across all routes
      domain: process.env.COOKIE_DOMAIN || undefined // Set in production
    });
    
    
    res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

//resend verification endpoint
app.post('/api/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }

        if (user.rows[0].is_verified) {
            return res.status(400).json({ error: 'Email already verified' });
        }

        const verificationToken = jwt.sign(
            { email },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        await pool.query(
            'UPDATE users SET verification_token = $1 WHERE email = $2',
            [verificationToken, email]
        );

        await transporter.sendMail({
            from: `"InvestSecure" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify Your Email',
            html: `
                <h2>Verify Your Email</h2>
                <p>Click <a href="${process.env.BASE_URL}/verify-email?token=${verificationToken}">
                here</a> to verify your email.</p>
            `,
        });

        res.json({ message: 'Verification email resent' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to resend verification email' });
    }
});

// Email verification endpoint
app.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Update user in database
    const result = await pool.query(
      `UPDATE users 
       SET is_verified = TRUE, verification_token = NULL 
       WHERE email = $1 AND verification_token = $2
       RETURNING *`,
      [decoded.email, token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send(`
        <h2>Verification Failed</h2>
        <p>Invalid or expired verification link.</p>
        <a href="/login.html">Go to Login</a>
      `);
    }

    
    // Successful verification response
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .success { color: green; font-size: 24px; }
        </style>
      </head>
      <body>
        <div class="success">✓ Email Verified Successfully</div>
        <p>Your email has been verified. You can now log in to your account.</p>
        <a href="/login.html" style="
          display: inline-block;
          margin-top: 20px;
          padding: 10px 20px;
          background: #4361ee;
          color: white;
          text-decoration: none;
          border-radius: 5px;
        ">Continue to Login</a>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Verification error:', error);
    res.status(400).send(`
      <h2>Verification Failed</h2>
      <p>${error.message}</p>
      <a href="/login.html">Go to Login</a>
    `);
  }
});

//Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    // Security: Always return success even if email doesn't exist
    if (user.rows.length === 0) {
      return res.json({ message: 'If the email exists, a reset link has been sent' });
    }

    const resetToken = jwt.sign(
      { email, 
        userId: user.rows[0].id,
        iat: Math.floor(Date.now() / 1000) // Current time in seconds
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_created_at = NOW() WHERE id = $2',
      [resetToken, user.rows[0].id]
    );


    // Create the password reset link
    const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;

    // Send email with proper HTML template
    await transporter.sendMail({
      from: `"InvestSecure" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4361ee;">Password Reset</h2>
          <p>You requested to reset your password. Click the button below to proceed:</p>
          
          <a href="${resetLink}" 
             style="display: inline-block; padding: 12px 24px; 
                    background-color: #4361ee; color: white; 
                    text-decoration: none; border-radius: 4px; 
                    margin: 20px 0;">
            Reset Password
          </a>
          
          <p>Or copy and paste this URL into your browser:</p>
          <p style="word-break: break-all; background: #f5f5f5; padding: 10px;">
            ${resetLink}
          </p>
          
          <p>This link will expire in 15 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `,
      text: `To reset your password, visit this link: ${resetLink}\n\nThis link expires in 15 minutes.`
    });

    res.json({ message: 'Password reset link sent' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token and check expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Additional check - verify token exists in database and is not expired
    const user = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND reset_token = $2',
      [decoded.userId, token]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Check if token was created more than 15 minutes ago
    const tokenAgeMinutes = await pool.query(
      'SELECT EXTRACT(EPOCH FROM (NOW() - reset_token_created_at))/60 AS minutes FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (tokenAgeMinutes.rows[0].minutes > 15) {
      return res.status(400).json({ error: 'Reset link has expired' });
    }

    // Update password and clear reset token
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_created_at = NULL WHERE id = $2',
      [hashedPassword, decoded.userId]
    );

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

//Token Validatio Endpoint
app.post('/api/validate-reset-token', async (req, res) => {
  try {
    const { token } = req.body;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND reset_token = $2',
      [decoded.userId, token]
    );

    if (user.rows.length === 0) {
      throw new Error('Invalid token');
    }

    const tokenAge = await pool.query(
      'SELECT EXTRACT(EPOCH FROM (NOW() - reset_token_created_at))/60 AS minutes FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (tokenAge.rows[0].minutes > 15) {
      throw new Error('Token expired');
    }

    res.json({ valid: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Serve reset password page
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Handle password reset submission
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password and clear reset token
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL WHERE id = $2',
      [hashedPassword, decoded.userId]
    );
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});


// Dashboard endpoint
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        // Get user details
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
        
        // In a real app, you would fetch actual portfolio data here
        const dashboardData = {
            user: {
                full_name: user.rows[0].full_name,
                email: user.rows[0].email,
                phone: user.rows[0].phone
            },
            stats: {
                portfolioValue: 12456.78,
                dailyChange: 245.67,
                investedAmount: 10000.00,
                profitLoss: 2456.78
            },
            activities: [
                { type: 'investment', message: 'Added $500 to Tech ETF', date: '2 hours ago' },
                { type: 'dividend', message: 'Received $12.45 dividend from AAPL', date: '1 day ago' },
                { type: 'buy', message: 'Purchased 5 shares of MSFT', date: '3 days ago' }
            ]
        };

        res.json(dashboardData);
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard data' });
    }
});

// Auth middleware
function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Serve HTML files

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});