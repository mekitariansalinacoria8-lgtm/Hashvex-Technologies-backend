require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const moment = require('moment');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const CryptoJS = require('crypto-js');
const cron = require('node-cron');
const winston = require('winston');
const morgan = require('morgan');
const compression = require('compression');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

// Initialize Express app
const app = express();
const { createServer } = require('http');
const { Server } = require('socket.io');
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
    credentials: true
  }
});

// Winston logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console()
  ]
});

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// File upload configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('application/pdf')) {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'), false);
    }
  }
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com", "https://res.cloudinary.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://hashvex-technologies-backend.onrender.com", "https://api.coingecko.com", "https://api.coincap.io", "wss://hashvex-technologies-backend.onrender.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com"]
    }
  },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

app.use(cors({
  origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(compression());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP, please try again later'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: 'Too many login attempts, please try again later'
});

app.use('/api', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// CSRF protection
const csrfProtection = csrf({ 
  cookie: { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:VB8vFPiZmFnJ8wFm@hashvex.kwnsunt.mongodb.net/?appName=Hashvex', {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50,
  wtimeoutMS: 2500,
  retryWrites: true
}).then(() => {
  logger.info('MongoDB connected successfully');
}).catch(err => {
  logger.error('MongoDB connection error:', err);
  process.exit(1);
});

// Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3
});

redis.on('error', (err) => {
  logger.error('Redis error:', err);
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Google OAuth client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI
});

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s';
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083;

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, select: false },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  city: { type: String },
  googleId: { type: String },
  isVerified: { type: Boolean, default: false },
  is2FAEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, select: false },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  otp: { type: String },
  otpExpires: { type: Date },
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'none'], default: 'none' },
  kycData: {
    identityDocument: { type: String },
    addressDocument: { type: String },
    facialVerification: { type: String },
    submittedAt: { type: Date }
  },
  balances: {
    btc: { type: Number, default: 0 },
    usd: { type: Number, default: 0 },
    miningBalance: { type: Number, default: 0 },
    availableBalance: { type: Number, default: 0 }
  },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  ipAddresses: [{ type: String }],
  devices: [{
    deviceId: String,
    userAgent: String,
    lastUsed: Date
  }],
  notificationPreferences: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  }
});

const MinerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  model: { type: String, required: true },
  hashRate: { type: Number, required: true },
  powerConsumption: { type: Number, required: true },
  price: { type: Number, required: true },
  dailyProfit: { type: Number, required: true },
  type: { type: String, enum: ['rent', 'sale'], required: true },
  status: { type: String, enum: ['available', 'rented', 'sold', 'maintenance'], default: 'available' },
  imageUrl: { type: String },
  specifications: {
    algorithm: String,
    noiseLevel: String,
    dimensions: String,
    weight: String
  }
});

const OwnedMinerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
  purchaseDate: { type: Date, required: true },
  expiryDate: { type: Date },
  status: { type: String, enum: ['active', 'expired', 'maintenance'], default: 'active' },
  totalEarned: { type: Number, default: 0 },
  currentHashRate: { type: Number },
  powerConsumption: { type: Number }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'purchase', 'earning', 'loan'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  description: { type: String },
  metadata: { type: mongoose.Schema.Types.Mixed },
  txHash: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const WithdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['btc', 'bank'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'], default: 'pending' },
  btcAddress: { type: String },
  bankDetails: {
    accountName: String,
    accountNumber: String,
    bankName: String,
    swiftCode: String
  },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number },
  adminNotes: { type: String },
  completedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const DepositSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['btc', 'card'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'completed', 'failed'], default: 'pending' },
  btcAddress: { type: String },
  btxTxHash: { type: String },
  cardDetails: {
    last4: String,
    brand: String,
    chargeId: String
  },
  confirmationCount: { type: Number, default: 0 },
  requiredConfirmations: { type: Number, default: 3 },
  createdAt: { type: Date, default: Date.now }
});

const LoanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  term: { type: Number, required: true }, // in days
  status: { type: String, enum: ['active', 'repaid', 'defaulted'], default: 'active' },
  dueDate: { type: Date, required: true },
  totalRepaid: { type: Number, default: 0 },
  remainingBalance: { type: Number },
  collateral: { type: mongoose.Schema.Types.ObjectId, ref: 'OwnedMiner' },
  createdAt: { type: Date, default: Date.now }
});

const CartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
    quantity: { type: Number, default: 1 },
    type: { type: String, enum: ['rent', 'sale'] }
  }],
  totalAmount: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});

const APITokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  permissions: [{ type: String }],
  lastUsed: { type: Date },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const NewsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, enum: ['general', 'bitcoin', 'mining', 'announcement'] },
  imageUrl: { type: String },
  author: { type: String },
  isPublished: { type: Boolean, default: true },
  publishedAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', UserSchema);
const Miner = mongoose.model('Miner', MinerSchema);
const OwnedMiner = mongoose.model('OwnedMiner', OwnedMinerSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Deposit = mongoose.model('Deposit', DepositSchema);
const Loan = mongoose.model('Loan', LoanSchema);
const Cart = mongoose.model('Cart', CartSchema);
const APIToken = mongoose.model('APIToken', APITokenSchema);
const News = mongoose.model('News', NewsSchema);

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Send email utility
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: `"Hashvex Technologies" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
    return true;
  } catch (error) {
    logger.error('Email send error:', error);
    return false;
  }
};

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  logger.info('New client connected:', socket.id);
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        socket.userId = user._id;
        socket.join(`user:${user._id}`);
        socket.emit('authenticated', { success: true });
      }
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });
  
  socket.on('disconnect', () => {
    logger.info('Client disconnected:', socket.id);
  });
});

// Bitcoin price cache
let bitcoinPriceCache = {
  price: 0,
  lastUpdated: null
};

const updateBitcoinPrice = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true');
    bitcoinPriceCache = {
      price: response.data.bitcoin.usd,
      marketCap: response.data.bitcoin.usd_market_cap,
      volume: response.data.bitcoin.usd_24h_vol,
      change: response.data.bitcoin.usd_24h_change,
      lastUpdated: new Date()
    };
    io.emit('bitcoin_price_update', bitcoinPriceCache);
  } catch (error) {
    logger.error('Bitcoin price update error:', error);
  }
};

// Schedule tasks
cron.schedule('*/5 * * * *', updateBitcoinPrice);
updateBitcoinPrice(); // Initial call

// API Routes

// ==================== AUTHENTICATION ROUTES ====================

// Signup
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').notEmpty().trim().escape(),
  body('lastName').notEmpty().trim().escape(),
  body('city').optional().trim().escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, firstName, lastName, city } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate referral code
    const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    
    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      city,
      referralCode
    });

    await user.save();

    // Generate OTP for verification
    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60000); // 10 minutes
    await user.save();

    // Send verification email
    const emailSent = await sendEmail(
      email,
      'Verify Your Hashvex Account',
      `<h2>Welcome to Hashvex Technologies!</h2>
      <p>Your verification code is: <strong>${otp}</strong></p>
      <p>This code will expire in 10 minutes.</p>`
    );

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Account created successfully. Please verify your email.',
      token,
      requiresOTP: true,
      emailSent
    });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    
    // Find user with password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate OTP if 2FA is enabled
    if (user.is2FAEnabled) {
      const otp = generateOTP();
      user.otp = otp;
      user.otpExpires = new Date(Date.now() + 10 * 60000);
      await user.save();

      // Send OTP email
      await sendEmail(
        email,
        'Your Login Verification Code',
        `<h2>Login Verification</h2>
        <p>Your verification code is: <strong>${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>`
      );

      const tempToken = generateToken(user._id);
      
      return res.json({
        success: true,
        message: 'OTP sent to your email',
        requiresOTP: true,
        tempToken
      });
    }

    // Generate final token
    const token = generateToken(user._id);
    
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Google OAuth
app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub: googleId } = payload;
    
    // Find or create user
    let user = await User.findOne({ email });
    
    if (!user) {
      user = new User({
        email,
        firstName: given_name,
        lastName: family_name || '',
        googleId,
        isVerified: true
      });
      await user.save();
    } else if (!user.googleId) {
      user.googleId = googleId;
      await user.save();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const jwtToken = generateToken(user._id);
    
    res.json({
      success: true,
      message: 'Google login successful',
      token: jwtToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    logger.error('Google auth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Send OTP
app.post('/api/auth/send-otp', authenticate, async (req, res) => {
  try {
    const user = req.user;
    const otp = generateOTP();
    
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60000);
    await user.save();
    
    // Send OTP email
    const emailSent = await sendEmail(
      user.email,
      'Your Verification Code',
      `<h2>Verification Code</h2>
      <p>Your verification code is: <strong>${otp}</strong></p>
      <p>This code will expire in 10 minutes.</p>`
    );
    
    res.json({
      success: true,
      message: 'OTP sent successfully',
      emailSent
    });
  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', authenticate, [
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { otp } = req.body;
    const user = req.user;
    
    if (!user.otp || user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    
    // Clear OTP
    user.otp = null;
    user.otpExpires = null;
    
    // Mark as verified if this was a signup
    if (!user.isVerified) {
      user.isVerified = true;
    }
    
    await user.save();
    
    // Generate final token
    const token = generateToken(user._id);
    
    res.json({
      success: true,
      message: 'OTP verified successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    logger.error('Verify OTP error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// Verify token
app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      isVerified: req.user.isVerified,
      kycStatus: req.user.kycStatus
    }
  });
});

// Logout
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // Invalidate token (store in Redis blacklist)
    await redis.setex(`blacklist:${req.token}`, parseInt(JWT_EXPIRES_IN), '1');
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour
    
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpires;
    await user.save();
    
    // Send reset email
    const resetUrl = `https://hashvex-technologies.vercel.app/reset-password.html?token=${resetToken}`;
    const emailSent = await sendEmail(
      email,
      'Password Reset Request',
      `<h2>Password Reset</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>`
    );
    
    res.json({
      success: true,
      message: 'Password reset email sent',
      emailSent
    });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Verify reset token
app.post('/api/auth/verify-reset-token', async (req, res) => {
  try {
    const { token } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    res.json({ success: true });
  } catch (error) {
    logger.error('Verify reset token error:', error);
    res.status(500).json({ error: 'Token verification failed' });
  }
});

// Reset password
app.post('/api/auth/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { token, password } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();
    
    res.json({
      success: true,
      message: 'Password reset successful'
    });
  } catch (error) {
    logger.error('Reset password error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        city: user.city,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        createdAt: user.createdAt,
        referralCode: user.referralCode
      }
    });
  } catch (error) {
    logger.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

// Update user profile
app.put('/api/users/profile', authenticate, [
  body('firstName').optional().trim().escape(),
  body('lastName').optional().trim().escape(),
  body('city').optional().trim().escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const updates = req.body;
    const user = req.user;
    
    Object.keys(updates).forEach(key => {
      if (updates[key] !== undefined) {
        user[key] = updates[key];
      }
    });
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        city: user.city
      }
    });
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ==================== BALANCE ROUTES ====================

// Get user balances
app.get('/api/balances', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    res.json({
      success: true,
      balances: user.balances,
      bitcoinPrice: bitcoinPriceCache.price
    });
  } catch (error) {
    logger.error('Get balances error:', error);
    res.status(500).json({ error: 'Failed to get balances' });
  }
});

// ==================== MINER ROUTES ====================

// Get miners for rent
app.get('/api/miners/rent', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ 
      type: 'rent',
      status: 'available'
    })
    .skip(skip)
    .limit(limit)
    .sort({ price: 1 });
    
    const total = await Miner.countDocuments({ 
      type: 'rent',
      status: 'available'
    });
    
    res.json({
      success: true,
      miners,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get rent miners error:', error);
    res.status(500).json({ error: 'Failed to get miners' });
  }
});

// Get miners for sale
app.get('/api/miners/sale', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ 
      type: 'sale',
      status: 'available'
    })
    .skip(skip)
    .limit(limit)
    .sort({ price: 1 });
    
    const total = await Miner.countDocuments({ 
      type: 'sale',
      status: 'available'
    });
    
    res.json({
      success: true,
      miners,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get sale miners error:', error);
    res.status(500).json({ error: 'Failed to get miners' });
  }
});

// Get owned miners
app.get('/api/miners/owned', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const ownedMiners = await OwnedMiner.find({ userId: req.user._id })
      .populate('minerId')
      .skip(skip)
      .limit(limit)
      .sort({ purchaseDate: -1 });
    
    const total = await OwnedMiner.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      miners: ownedMiners,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get owned miners error:', error);
    res.status(500).json({ error: 'Failed to get owned miners' });
  }
});

// Get miner details
app.get('/api/miners/:id', authenticate, async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    res.json({
      success: true,
      miner
    });
  } catch (error) {
    logger.error('Get miner details error:', error);
    res.status(500).json({ error: 'Failed to get miner details' });
  }
});

// Extend miner rental
app.post('/api/miners/:id/extend', authenticate, [
  body('months').isInt({ min: 1, max: 12 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { months } = req.body;
    const ownedMiner = await OwnedMiner.findOne({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!ownedMiner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    // Calculate extension cost
    const miner = await Miner.findById(ownedMiner.minerId);
    const extensionCost = miner.price * months;
    
    // Check balance
    if (req.user.balances.usd < extensionCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Deduct balance
    req.user.balances.usd -= extensionCost;
    await req.user.save();
    
    // Extend expiry
    const currentExpiry = ownedMiner.expiryDate || new Date();
    ownedMiner.expiryDate = new Date(currentExpiry.setMonth(currentExpiry.getMonth() + months));
    await ownedMiner.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'purchase',
      amount: extensionCost,
      currency: 'USD',
      status: 'completed',
      description: `Extended miner rental for ${months} months`,
      metadata: {
        minerId: miner._id,
        minerName: miner.name,
        months
      }
    });
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Miner rental extended successfully',
      newExpiryDate: ownedMiner.expiryDate
    });
  } catch (error) {
    logger.error('Extend miner error:', error);
    res.status(500).json({ error: 'Failed to extend miner rental' });
  }
});

// ==================== TRANSACTION ROUTES ====================

// Get transaction history
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ userId: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Transaction.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to get transactions' });
  }
});

// ==================== WITHDRAWAL ROUTES ====================

// Get withdrawal history
app.get('/api/withdrawals/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const withdrawals = await Withdrawal.find({ userId: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Withdrawal.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      withdrawals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get withdrawal history error:', error);
    res.status(500).json({ error: 'Failed to get withdrawal history' });
  }
});

// Bitcoin withdrawal
app.post('/api/withdrawals/btc', authenticate, [
  body('amount').isFloat({ min: 0.001 }),
  body('address').isLength({ min: 26, max: 35 }),
  body('pin').isLength({ min: 4, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { amount, address, pin } = req.body;
    const user = req.user;
    
    // Check KYC status
    if (user.kycStatus !== 'verified') {
      return res.status(400).json({ error: 'KYC verification required' });
    }
    
    // Check balance
    if (user.balances.btc < amount) {
      return res.status(400).json({ error: 'Insufficient BTC balance' });
    }
    
    // Calculate fee (0.0005 BTC fixed fee + network fee)
    const fee = 0.0005;
    const networkFee = 0.0002;
    const totalFee = fee + networkFee;
    const netAmount = amount - totalFee;
    
    if (netAmount <= 0) {
      return res.status(400).json({ error: 'Amount too small after fees' });
    }
    
    // Create withdrawal record
    const withdrawal = new Withdrawal({
      userId: user._id,
      type: 'btc',
      amount,
      currency: 'BTC',
      status: 'pending',
      btcAddress: address,
      fee: totalFee,
      netAmount
    });
    await withdrawal.save();
    
    // Deduct from balance
    user.balances.btc -= amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: amount * -1,
      currency: 'BTC',
      status: 'pending',
      description: 'BTC withdrawal',
      metadata: {
        withdrawalId: withdrawal._id,
        address,
        fee: totalFee
      }
    });
    await transaction.save();
    
    // Notify admin via WebSocket
    io.to('admin').emit('new_withdrawal', {
      withdrawalId: withdrawal._id,
      userId: user._id,
      amount,
      address,
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      withdrawalId: withdrawal._id,
      netAmount,
      fee: totalFee
    });
  } catch (error) {
    logger.error('BTC withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

// Bank withdrawal
app.post('/api/withdrawals/bank', authenticate, [
  body('amount').isFloat({ min: 50 }),
  body('accountName').notEmpty().trim().escape(),
  body('accountNumber').isLength({ min: 8, max: 20 }),
  body('bankName').notEmpty().trim().escape(),
  body('swiftCode').optional().trim().escape(),
  body('pin').isLength({ min: 4, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { amount, accountName, accountNumber, bankName, swiftCode, pin } = req.body;
    const user = req.user;
    
    // Check KYC status
    if (user.kycStatus !== 'verified') {
      return res.status(400).json({ error: 'KYC verification required' });
    }
    
    // Check balance
    if (user.balances.usd < amount) {
      return res.status(400).json({ error: 'Insufficient USD balance' });
    }
    
    // Calculate fee (2.5% or $10, whichever is higher)
    const feePercentage = 0.025;
    const minFee = 10;
    const fee = Math.max(amount * feePercentage, minFee);
    const netAmount = amount - fee;
    
    // Create withdrawal record
    const withdrawal = new Withdrawal({
      userId: user._id,
      type: 'bank',
      amount,
      currency: 'USD',
      status: 'pending',
      bankDetails: {
        accountName,
        accountNumber,
        bankName,
        swiftCode
      },
      fee,
      netAmount
    });
    await withdrawal.save();
    
    // Deduct from balance
    user.balances.usd -= amount;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: amount * -1,
      currency: 'USD',
      status: 'pending',
      description: 'Bank withdrawal',
      metadata: {
        withdrawalId: withdrawal._id,
        bankName,
        accountNumber: accountNumber.slice(-4),
        fee
      }
    });
    await transaction.save();
    
    // Notify admin via WebSocket
    io.to('admin').emit('new_withdrawal', {
      withdrawalId: withdrawal._id,
      userId: user._id,
      amount,
      bankName,
      accountNumber: accountNumber.slice(-4),
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      message: 'Bank withdrawal request submitted',
      withdrawalId: withdrawal._id,
      netAmount,
      fee
    });
  } catch (error) {
    logger.error('Bank withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

// ==================== DEPOSIT ROUTES ====================

// Get BTC deposit address
app.get('/api/deposits/btc-address', authenticate, async (req, res) => {
  try {
    // Generate unique deposit address for user
    const user = req.user;
    const address = `3${crypto.randomBytes(20).toString('hex')}`;
    
    // Store address in Redis for 24 hours
    await redis.setex(`deposit:${user._id}:btc:address`, 86400, address);
    
    res.json({
      success: true,
      address,
      qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(address)}`
    });
  } catch (error) {
    logger.error('Get BTC address error:', error);
    res.status(500).json({ error: 'Failed to generate address' });
  }
});

// Check BTC deposit status
app.post('/api/deposits/btc-status', authenticate, async (req, res) => {
  try {
    const { txHash } = req.body;
    
    // In production, you would check with a Bitcoin node or block explorer API
    // This is a mock implementation
    const mockStatus = Math.random() > 0.3 ? 'confirmed' : 'pending';
    const confirmations = mockStatus === 'confirmed' ? 3 : Math.floor(Math.random() * 3);
    
    res.json({
      success: true,
      status: mockStatus,
      confirmations,
      requiredConfirmations: 3
    });
  } catch (error) {
    logger.error('Check BTC status error:', error);
    res.status(500).json({ error: 'Failed to check status' });
  }
});

// Get deposit history
app.get('/api/deposits/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const deposits = await Deposit.find({ userId: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Deposit.countDocuments({ userId: req.user._id });
    
    res.json({
      success: true,
      deposits,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get deposit history error:', error);
    res.status(500).json({ error: 'Failed to get deposit history' });
  }
});

// Process card payment
app.post('/api/payments/store-card', authenticate, [
  body('amount').isFloat({ min: 10 }),
  body('cardNumber').isCreditCard(),
  body('expMonth').isInt({ min: 1, max: 12 }),
  body('expYear').isInt({ min: new Date().getFullYear() }),
  body('cvc').isLength({ min: 3, max: 4 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { amount, cardNumber, expMonth, expYear, cvc } = req.body;
    const user = req.user;
    
    // Process with Stripe
    const paymentMethod = await stripe.paymentMethods.create({
      type: 'card',
      card: {
        number: cardNumber,
        exp_month: expMonth,
        exp_year: expYear,
        cvc: cvc
      }
    });
    
    // Create payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Convert to cents
      currency: 'usd',
      payment_method: paymentMethod.id,
      confirm: true,
      description: `Deposit for user ${user.email}`,
      metadata: {
        userId: user._id.toString(),
        email: user.email
      }
    });
    
    if (paymentIntent.status === 'succeeded') {
      // Update user balance
      user.balances.usd += amount;
      await user.save();
      
      // Create deposit record
      const deposit = new Deposit({
        userId: user._id,
        type: 'card',
        amount,
        currency: 'USD',
        status: 'completed',
        cardDetails: {
          last4: cardNumber.slice(-4),
          brand: 'visa', // In production, detect from card number
          chargeId: paymentIntent.id
        }
      });
      await deposit.save();
      
      // Create transaction record
      const transaction = new Transaction({
        userId: user._id,
        type: 'deposit',
        amount,
        currency: 'USD',
        status: 'completed',
        description: 'Credit card deposit',
        metadata: {
          depositId: deposit._id,
          chargeId: paymentIntent.id
        }
      });
      await transaction.save();
      
      res.json({
        success: true,
        message: 'Deposit successful',
        amount,
        newBalance: user.balances.usd
      });
    } else {
      res.status(400).json({
        error: 'Payment failed',
        status: paymentIntent.status
      });
    }
  } catch (error) {
    logger.error('Card payment error:', error);
    res.status(500).json({ error: 'Payment processing failed' });
  }
});

// ==================== KYC ROUTES ====================

// Get KYC status
app.get('/api/kyc/status', authenticate, async (req, res) => {
  try {
    res.json({
      success: true,
      status: req.user.kycStatus,
      data: req.user.kycData
    });
  } catch (error) {
    logger.error('Get KYC status error:', error);
    res.status(500).json({ error: 'Failed to get KYC status' });
  }
});

// Upload identity document
app.post('/api/users/kyc/identity', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const user = req.user;
    
    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: `kyc/${user._id}`,
          resource_type: 'auto',
          public_id: `identity_${Date.now()}`
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      
      stream.end(req.file.buffer);
    });
    
    user.kycData.identityDocument = result.secure_url;
    await user.save();
    
    res.json({
      success: true,
      message: 'Identity document uploaded successfully',
      url: result.secure_url
    });
  } catch (error) {
    logger.error('Upload identity error:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});

// Upload address document
app.post('/api/users/kyc/address', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const user = req.user;
    
    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: `kyc/${user._id}`,
          resource_type: 'auto',
          public_id: `address_${Date.now()}`
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      
      stream.end(req.file.buffer);
    });
    
    user.kycData.addressDocument = result.secure_url;
    await user.save();
    
    res.json({
      success: true,
      message: 'Address document uploaded successfully',
      url: result.secure_url
    });
  } catch (error) {
    logger.error('Upload address error:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});

// Submit KYC
app.post('/api/users/kyc/submit', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    // Check if all documents are uploaded
    if (!user.kycData.identityDocument || !user.kycData.addressDocument) {
      return res.status(400).json({ error: 'Missing required documents' });
    }
    
    user.kycStatus = 'pending';
    user.kycData.submittedAt = new Date();
    await user.save();
    
    // Notify admin
    io.to('admin').emit('kyc_submitted', {
      userId: user._id,
      email: user.email,
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      message: 'KYC submitted for review',
      status: 'pending'
    });
  } catch (error) {
    logger.error('Submit KYC error:', error);
    res.status(500).json({ error: 'Failed to submit KYC' });
  }
});

// ==================== LOAN ROUTES ====================

// Get loan limit
app.get('/api/loans/limit', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    // Calculate loan limit based on owned miners value
    const ownedMiners = await OwnedMiner.find({ userId: user._id }).populate('minerId');
    const totalMinerValue = ownedMiners.reduce((sum, owned) => {
      return sum + (owned.minerId?.price || 0);
    }, 0);
    
    // Loan limit is 50% of miner value
    const loanLimit = totalMinerValue * 0.5;
    const maxLoanAmount = Math.min(loanLimit, 100000); // Cap at $100k
    
    res.json({
      success: true,
      limit: maxLoanAmount,
      available: maxLoanAmount,
      interestRate: 8.5, // Annual percentage
      termOptions: [30, 60, 90] // Days
    });
  } catch (error) {
    logger.error('Get loan limit error:', error);
    res.status(500).json({ error: 'Failed to get loan limit' });
  }
});

// Request loan
app.post('/api/loans', authenticate, [
  body('amount').isFloat({ min: 100, max: 100000 }),
  body('term').isInt({ min: 30, max: 90 }),
  body('collateralMinerId').isMongoId()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { amount, term, collateralMinerId } = req.body;
    const user = req.user;
    
    // Check if miner exists and is owned by user
    const collateralMiner = await OwnedMiner.findOne({
      _id: collateralMinerId,
      userId: user._id
    });
    
    if (!collateralMiner) {
      return res.status(404).json({ error: 'Collateral miner not found' });
    }
    
    // Calculate interest
    const dailyInterestRate = 8.5 / 365 / 100;
    const interest = amount * dailyInterestRate * term;
    const totalRepayment = amount + interest;
    
    // Create loan
    const loan = new Loan({
      userId: user._id,
      amount,
      interestRate: 8.5,
      term,
      dueDate: new Date(Date.now() + term * 86400000), // term in days
      remainingBalance: totalRepayment,
      collateral: collateralMinerId
    });
    await loan.save();
    
    // Credit amount to user
    user.balances.usd += amount;
    await user.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'loan',
      amount,
      currency: 'USD',
      status: 'completed',
      description: 'Loan disbursement',
      metadata: {
        loanId: loan._id,
        term,
        interestRate: 8.5
      }
    });
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Loan approved and disbursed',
      loanId: loan._id,
      amount,
      interest,
      totalRepayment,
      dueDate: loan.dueDate
    });
  } catch (error) {
    logger.error('Request loan error:', error);
    res.status(500).json({ error: 'Failed to process loan request' });
  }
});

// Repay loan
app.post('/api/loans/repay', authenticate, [
  body('loanId').isMongoId(),
  body('amount').isFloat({ min: 10 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { loanId, amount } = req.body;
    const user = req.user;
    
    // Check loan
    const loan = await Loan.findOne({
      _id: loanId,
      userId: user._id,
      status: 'active'
    });
    
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    // Check balance
    if (user.balances.usd < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Update loan
    loan.totalRepaid += amount;
    loan.remainingBalance -= amount;
    
    if (loan.remainingBalance <= 0) {
      loan.status = 'repaid';
      loan.remainingBalance = 0;
    }
    
    await loan.save();
    
    // Deduct from balance
    user.balances.usd -= amount;
    await user.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'loan',
      amount: amount * -1,
      currency: 'USD',
      status: 'completed',
      description: 'Loan repayment',
      metadata: {
        loanId: loan._id,
        remainingBalance: loan.remainingBalance
      }
    });
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Loan repayment successful',
      remainingBalance: loan.remainingBalance,
      totalRepaid: loan.totalRepaid
    });
  } catch (error) {
    logger.error('Repay loan error:', error);
    res.status(500).json({ error: 'Failed to process repayment' });
  }
});

// ==================== CART ROUTES ====================

// Get cart
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    let cart = await Cart.findOne({ userId: req.user._id }).populate('items.minerId');
    
    if (!cart) {
      cart = new Cart({
        userId: req.user._id,
        items: [],
        totalAmount: 0
      });
      await cart.save();
    }
    
    res.json({
      success: true,
      cart
    });
  } catch (error) {
    logger.error('Get cart error:', error);
    res.status(500).json({ error: 'Failed to get cart' });
  }
});

// Add to cart
app.post('/api/cart/add', authenticate, [
  body('minerId').isMongoId(),
  body('quantity').optional().isInt({ min: 1, max: 10 }),
  body('type').isIn(['rent', 'sale'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { minerId, quantity = 1, type } = req.body;
    
    // Check if miner exists
    const miner = await Miner.findOne({
      _id: minerId,
      type,
      status: 'available'
    });
    
    if (!miner) {
      return res.status(404).json({ error: 'Miner not available' });
    }
    
    let cart = await Cart.findOne({ userId: req.user._id });
    
    if (!cart) {
      cart = new Cart({
        userId: req.user._id,
        items: []
      });
    }
    
    // Check if item already in cart
    const existingItemIndex = cart.items.findIndex(
      item => item.minerId.toString() === minerId && item.type === type
    );
    
    if (existingItemIndex > -1) {
      cart.items[existingItemIndex].quantity += quantity;
    } else {
      cart.items.push({
        minerId,
        quantity,
        type
      });
    }
    
    // Calculate total
    cart.totalAmount = cart.items.reduce((total, item) => {
      return total + (miner.price * item.quantity);
    }, 0);
    
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({
      success: true,
      message: 'Item added to cart',
      cart
    });
  } catch (error) {
    logger.error('Add to cart error:', error);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// Checkout
app.post('/api/cart/checkout', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.user._id }).populate('items.minerId');
    
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }
    
    const user = req.user;
    
    // Check balance
    if (user.balances.usd < cart.totalAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Process each item
    for (const item of cart.items) {
      const miner = item.minerId;
      
      // Update miner status
      miner.status = miner.type === 'rent' ? 'rented' : 'sold';
      await miner.save();
      
      // Create owned miner record
      if (miner.type === 'rent') {
        const ownedMiner = new OwnedMiner({
          userId: user._id,
          minerId: miner._id,
          purchaseDate: new Date(),
          expiryDate: new Date(Date.now() + 30 * 86400000), // 30 days
          currentHashRate: miner.hashRate,
          powerConsumption: miner.powerConsumption
        });
        await ownedMiner.save();
      }
      
      // Create transaction
      const transaction = new Transaction({
        userId: user._id,
        type: 'purchase',
        amount: miner.price * item.quantity * -1,
        currency: 'USD',
        status: 'completed',
        description: `Purchased ${miner.name} (${miner.type})`,
        metadata: {
          minerId: miner._id,
          minerName: miner.name,
          type: miner.type,
          quantity: item.quantity
        }
      });
      await transaction.save();
    }
    
    // Deduct from balance
    user.balances.usd -= cart.totalAmount;
    await user.save();
    
    // Clear cart
    cart.items = [];
    cart.totalAmount = 0;
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({
      success: true,
      message: 'Checkout successful',
      totalAmount: cart.totalAmount,
      newBalance: user.balances.usd
    });
  } catch (error) {
    logger.error('Checkout error:', error);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ==================== NEWS ROUTES ====================

// Get news
app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const news = await News.find({ isPublished: true })
      .skip(skip)
      .limit(limit)
      .sort({ publishedAt: -1 });
    
    const total = await News.countDocuments({ isPublished: true });
    
    res.json({
      success: true,
      news,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get news error:', error);
    res.status(500).json({ error: 'Failed to get news' });
  }
});

// ==================== REFERRAL ROUTES ====================

// Validate referral code
app.get('/api/referrals/validate/:code', async (req, res) => {
  try {
    const { code } = req.params;
    
    const user = await User.findOne({ referralCode: code });
    
    if (!user) {
      return res.status(404).json({ error: 'Invalid referral code' });
    }
    
    res.json({
      success: true,
      referrer: {
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    logger.error('Validate referral error:', error);
    res.status(500).json({ error: 'Failed to validate referral code' });
  }
});

// ==================== ANNOUNCEMENT ROUTES ====================

// Get announcements
app.get('/api/announcements', authenticate, async (req, res) => {
  try {
    const announcements = await News.find({
      category: 'announcement',
      isPublished: true
    })
    .sort({ publishedAt: -1 })
    .limit(5);
    
    res.json({
      success: true,
      announcements
    });
  } catch (error) {
    logger.error('Get announcements error:', error);
    res.status(500).json({ error: 'Failed to get announcements' });
  }
});

// ==================== NEWSLETTER ROUTES ====================

// Subscribe to newsletter
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email } = req.body;
    
    // Store in Redis
    await redis.sadd('newsletter:subscribers', email);
    
    res.json({
      success: true,
      message: 'Subscribed to newsletter successfully'
    });
  } catch (error) {
    logger.error('Newsletter subscribe error:', error);
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// ==================== ADMIN ROUTES ====================

// Middleware to check admin
const isAdmin = async (req, res, next) => {
  try {
    const user = req.user;
    
    // In production, check if user has admin role
    const isAdminUser = user.email === process.env.ADMIN_EMAIL;
    
    if (!isAdminUser) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    next();
  } catch (error) {
    logger.error('Admin check error:', error);
    res.status(500).json({ error: 'Admin verification failed' });
  }
};

// Get all withdrawals (admin)
app.get('/api/admin/withdrawals', authenticate, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const { status } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    
    const withdrawals = await Withdrawal.find(filter)
      .populate('userId', 'email firstName lastName')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Withdrawal.countDocuments(filter);
    
    res.json({
      success: true,
      withdrawals,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Admin get withdrawals error:', error);
    res.status(500).json({ error: 'Failed to get withdrawals' });
  }
});

// Update withdrawal status (admin)
app.put('/api/admin/withdrawals/:id', authenticate, isAdmin, [
  body('status').isIn(['processing', 'completed', 'failed', 'cancelled']),
  body('adminNotes').optional().trim().escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { id } = req.params;
    const { status, adminNotes } = req.body;
    
    const withdrawal = await Withdrawal.findById(id).populate('userId');
    
    if (!withdrawal) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }
    
    const oldStatus = withdrawal.status;
    withdrawal.status = status;
    
    if (adminNotes) {
      withdrawal.adminNotes = adminNotes;
    }
    
    if (status === 'completed') {
      withdrawal.completedAt = new Date();
    } else if (status === 'failed' || status === 'cancelled') {
      // Refund amount if withdrawal failed/cancelled
      const user = withdrawal.userId;
      
      if (withdrawal.currency === 'BTC') {
        user.balances.btc += withdrawal.amount;
      } else {
        user.balances.usd += withdrawal.amount;
      }
      
      await user.save();
      
      // Create refund transaction
      const transaction = new Transaction({
        userId: user._id,
        type: withdrawal.type === 'btc' ? 'withdrawal' : 'withdrawal',
        amount: withdrawal.amount,
        currency: withdrawal.currency,
        status: 'completed',
        description: `Refund: ${withdrawal.type} withdrawal ${status}`,
        metadata: {
          withdrawalId: withdrawal._id,
          refund: true
        }
      });
      await transaction.save();
    }
    
    await withdrawal.save();
    
    // Notify user via WebSocket
    io.to(`user:${withdrawal.userId._id}`).emit('withdrawal_update', {
      withdrawalId: withdrawal._id,
      status,
      oldStatus,
      message: `Withdrawal ${status}`
    });
    
    res.json({
      success: true,
      message: 'Withdrawal status updated'
    });
  } catch (error) {
    logger.error('Admin update withdrawal error:', error);
    res.status(500).json({ error: 'Failed to update withdrawal' });
  }
});

// Get all KYC submissions (admin)
app.get('/api/admin/kyc', authenticate, isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const { status } = req.query;
    
    const filter = { kycStatus: status || 'pending' };
    
    const users = await User.find(filter, 'email firstName lastName kycStatus kycData.submittedAt')
      .skip(skip)
      .limit(limit)
      .sort({ 'kycData.submittedAt': 1 });
    
    const total = await User.countDocuments(filter);
    
    res.json({
      success: true,
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Admin get KYC error:', error);
    res.status(500).json({ error: 'Failed to get KYC submissions' });
  }
});

// Update KYC status (admin)
app.put('/api/admin/kyc/:userId', authenticate, isAdmin, [
  body('status').isIn(['verified', 'rejected']),
  body('notes').optional().trim().escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { userId } = req.params;
    const { status, notes } = req.body;
    
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.kycStatus = status;
    
    if (notes) {
      user.kycData.adminNotes = notes;
    }
    
    await user.save();
    
    // Notify user via WebSocket
    io.to(`user:${user._id}`).emit('kyc_update', {
      status,
      message: `KYC ${status}`
    });
    
    res.json({
      success: true,
      message: `KYC ${status}`
    });
  } catch (error) {
    logger.error('Admin update KYC error:', error);
    res.status(500).json({ error: 'Failed to update KYC' });
  }
});

// ==================== SYSTEM ROUTES ====================

// Health check
app.get('/api/health', async (req, res) => {
  try {
    // Check database connection
    await mongoose.connection.db.admin().ping();
    
    // Check Redis connection
    await redis.ping();
    
    res.json({
      status: 'healthy',
      timestamp: new Date(),
      uptime: process.uptime(),
      database: 'connected',
      redis: 'connected',
      memory: process.memoryUsage()
    });
  } catch (error) {
    logger.error('Health check error:', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date()
    });
  }
});

// Bitcoin price endpoint
app.get('/api/bitcoin/price', async (req, res) => {
  try {
    res.json({
      success: true,
      ...bitcoinPriceCache
    });
  } catch (error) {
    logger.error('Bitcoin price error:', error);
    res.status(500).json({ error: 'Failed to get Bitcoin price' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'File upload error: ' + err.message });
  }
  
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  
  // Seed initial data if needed
  seedInitialData();
});

// Seed initial data
async function seedInitialData() {
  try {
    // Check if miners exist
    const minerCount = await Miner.countDocuments();
    
    if (minerCount === 0) {
      const miners = [
        {
          name: 'Antminer S19 XP',
          model: 'S19 XP',
          hashRate: 140,
          powerConsumption: 3010,
          price: 4500,
          dailyProfit: 12.5,
          type: 'sale',
          specifications: {
            algorithm: 'SHA-256',
            noiseLevel: '75 dB',
            dimensions: '400 x 195 x 290 mm',
            weight: '14.2 kg'
          }
        },
        {
          name: 'Antminer S19 Pro',
          model: 'S19 Pro',
          hashRate: 110,
          powerConsumption: 3250,
          price: 3500,
          dailyProfit: 9.8,
          type: 'rent',
          specifications: {
            algorithm: 'SHA-256',
            noiseLevel: '75 dB',
            dimensions: '400 x 195 x 290 mm',
            weight: '13.2 kg'
          }
        },
        {
          name: 'Whatsminer M50',
          model: 'M50',
          hashRate: 118,
          powerConsumption: 3276,
          price: 3800,
          dailyProfit: 10.2,
          type: 'sale',
          specifications: {
            algorithm: 'SHA-256',
            noiseLevel: '75 dB',
            dimensions: '390 x 195 x 290 mm',
            weight: '14.5 kg'
          }
        }
      ];
      
      await Miner.insertMany(miners);
      logger.info('Initial miners seeded');
    }
    
    // Seed news
    const newsCount = await News.countDocuments();
    
    if (newsCount === 0) {
      const news = [
        {
          title: 'Bitcoin Halving 2024: What to Expect',
          content: 'The next Bitcoin halving is expected in April 2024, which will reduce the block reward from 6.25 BTC to 3.125 BTC.',
          category: 'bitcoin',
          author: 'Hashvex Team',
          imageUrl: 'https://res.cloudinary.com/demo/image/upload/v1621234567/bitcoin-halving.jpg'
        },
        {
          title: 'New Mining Facility Launch',
          content: 'We are excited to announce the launch of our new 50MW mining facility in Texas, featuring the latest ASIC technology.',
          category: 'announcement',
          author: 'Hashvex Team'
        },
        {
          title: 'Energy Efficiency Improvements',
          content: 'Our latest hardware upgrades have improved energy efficiency by 15%, reducing costs and environmental impact.',
          category: 'mining',
          author: 'Hashvex Team'
        }
      ];
      
      await News.insertMany(news);
      logger.info('Initial news seeded');
    }
  } catch (error) {
    logger.error('Seeding error:', error);
  }
}
