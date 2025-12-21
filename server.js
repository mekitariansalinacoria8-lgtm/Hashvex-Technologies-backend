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
const WebSocket = require('ws');
const OpenAI = require('openai');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio = require('twilio');
const cron = require('node-cron');
const winston = require('winston');
const expressWinston = require('express-winston');
const compression = require('compression');
const morgan = require('morgan');
const Joi = require('joi');
const { createServer } = require('http');
const { Server } = require('socket.io');

// Initialize Express app
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
    credentials: true
  }
});

// Enhanced Helmet Configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com", "https://res.cloudinary.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://hashvex-technologies-backend.onrender.com", "wss://hashvex-technologies-backend.onrender.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com"]
    }
  },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

// Enhanced CORS configuration
app.use(cors({
  origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'Accept', 'Origin']
}));

// Advanced middleware stack
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Enhanced logging configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// HTTP request logging
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Enhanced rate limiting with Redis store
const redisRateLimiter = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR'
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests from this IP, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true
});

app.use('/api', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/send-otp', authLimiter);

// CSRF protection
const csrfProtection = csrf({ 
  cookie: { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});
app.use(csrfProtection);

// Database connection with enhanced settings and retry logic
const connectWithRetry = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:VB8vFPiZmFnJ8wFm@hashvex.kwnsunt.mongodb.net/?appName=Hashvex', {
      autoIndex: true,
      connectTimeoutMS: 30000,
      socketTimeoutMS: 30000,
      maxPoolSize: 50,
      minPoolSize: 10,
      maxIdleTimeMS: 10000,
      serverSelectionTimeoutMS: 30000,
      retryWrites: true,
      w: 'majority',
      appName: 'Hashvex'
    });
    logger.info('MongoDB connected successfully');
  } catch (err) {
    logger.error('MongoDB connection error:', err);
    setTimeout(connectWithRetry, 5000);
  }
};

connectWithRetry();

// Redis connection with enhanced settings
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  connectTimeout: 10000
});

redis.on('error', (err) => {
  logger.error('Redis error:', err);
});

redis.on('connect', () => {
  logger.info('Redis connected successfully');
});

// Email transporter with enhanced configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
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
  maxMessages: 100,
  rateLimit: 5
});

// Google OAuth client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://hashvex-technologies-backend.onrender.com/api/auth/google/callback'
});

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s';
const JWT_COOKIE_EXPIRES = parseInt(process.env.JWT_COOKIE_EXPIRES) || 7200000;

// Cloudinary configuration for file uploads
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Stripe configuration
stripe.setMaxNetworkRetries(3);

// Twilio configuration for SMS
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// OpenAI configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Database Schemas
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true,
    validate: {
      validator: validator.isEmail,
      message: 'Invalid email format'
    }
  },
  password: { 
    type: String, 
    required: function() { return !this.googleId; },
    minlength: 8
  },
  googleId: { type: String, unique: true, sparse: true },
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  city: { type: String, required: true, trim: true },
  country: { type: String, default: '' },
  phone: { type: String, default: '' },
  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String },
  kycStatus: { 
    type: String, 
    enum: ['pending', 'verified', 'rejected', 'not_submitted'], 
    default: 'not_submitted' 
  },
  kycData: {
    documentType: String,
    documentNumber: String,
    documentFront: String,
    documentBack: String,
    selfie: String,
    addressProof: String,
    submittedAt: Date,
    verifiedAt: Date,
    verifiedBy: String
  },
  walletAddress: { type: String, default: '' },
  referralCode: { type: String, unique: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  balance: {
    btc: { type: Number, default: 0, min: 0 },
    usd: { type: Number, default: 0, min: 0 },
    pendingBtc: { type: Number, default: 0, min: 0 },
    pendingUsd: { type: Number, default: 0, min: 0 }
  },
  settings: {
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    privacy: {
      showBalance: { type: Boolean, default: true },
      showActivity: { type: Boolean, default: false }
    }
  },
  lastLogin: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  apiKeys: [{
    key: String,
    name: String,
    permissions: [String],
    lastUsed: Date,
    createdAt: { type: Date, default: Date.now }
  }],
  devices: [{
    deviceId: String,
    userAgent: String,
    ip: String,
    lastActive: Date,
    location: String
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  if (!this.referralCode) {
    this.referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
  }
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id, 
      email: this.email,
      kycStatus: this.kycStatus
    }, 
    JWT_SECRET, 
    { expiresIn: JWT_EXPIRES_IN }
  );
};

userSchema.methods.incrementLoginAttempts = async function() {
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5) {
    updates.$set = { lockUntil: Date.now() + 15 * 60 * 1000 }; // Lock for 15 minutes
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = async function() {
  return this.updateOne({
    $set: { loginAttempts: 0, lockUntil: null },
    $currentDate: { lastLogin: true }
  });
};

const User = mongoose.model('User', userSchema);

// Miner Schema
const minerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  model: { type: String, required: true },
  hashRate: { type: Number, required: true },
  powerConsumption: { type: Number, required: true },
  price: { type: Number, required: true },
  rentalPrice: { type: Number, required: true },
  availability: { type: Number, default: 0 },
  status: { 
    type: String, 
    enum: ['available', 'rented', 'sold', 'maintenance'], 
    default: 'available' 
  },
  location: { type: String, required: true },
  images: [String],
  specifications: {
    manufacturer: String,
    algorithm: String,
    noiseLevel: Number,
    dimensions: String,
    weight: Number
  },
  profitability: {
    dailyBtc: { type: Number, default: 0 },
    dailyUsd: { type: Number, default: 0 },
    electricityCost: { type: Number, default: 0 },
    maintenanceCost: { type: Number, default: 0 }
  }
}, { timestamps: true });

const Miner = mongoose.model('Miner', minerSchema);

// User Miner Ownership Schema
const userMinerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
  purchaseType: { type: String, enum: ['rent', 'purchase'], required: true },
  purchaseDate: { type: Date, default: Date.now },
  expiryDate: { type: Date },
  pricePaid: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['active', 'expired', 'cancelled', 'pending'], 
    default: 'active' 
  },
  miningStats: {
    totalMined: { type: Number, default: 0 },
    lastPayout: Date,
    uptime: { type: Number, default: 0 }
  },
  configuration: {
    poolAddress: String,
    workerName: String,
    powerMode: { type: String, default: 'normal' }
  }
}, { timestamps: true });

const UserMiner = mongoose.model('UserMiner', userMinerSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'purchase', 'rental', 'mining_reward', 'loan', 'repayment'],
    required: true 
  },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  txHash: { type: String, unique: true, sparse: true },
  address: { type: String },
  description: { type: String },
  metadata: mongoose.Schema.Types.Mixed,
  confirmedAt: { type: Date }
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['btc', 'bank'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'completed', 'rejected', 'cancelled'], 
    default: 'pending' 
  },
  btcAddress: { type: String },
  bankDetails: {
    accountName: String,
    accountNumber: String,
    bankName: String,
    swiftCode: String,
    iban: String
  },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedAt: { type: Date },
  rejectionReason: { type: String }
}, { timestamps: true });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Deposit Schema
const depositSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['btc', 'card', 'bank_transfer'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'completed', 'failed'], 
    default: 'pending' 
  },
  btcAddress: { type: String },
  txHash: { type: String },
  cardDetails: {
    last4: String,
    brand: String,
    chargeId: String
  },
  bankReference: { type: String },
  confirmedAt: { type: Date },
  confirmations: { type: Number, default: 0 }
}, { timestamps: true });

const Deposit = mongoose.model('Deposit', depositSchema);

// Loan Schema
const loanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  collateralAmount: { type: Number, required: true },
  collateralCurrency: { type: String, enum: ['BTC'], required: true },
  interestRate: { type: Number, required: true },
  duration: { type: Number, required: true }, // in days
  status: { 
    type: String, 
    enum: ['pending', 'active', 'repaid', 'defaulted', 'liquidated'], 
    default: 'pending' 
  },
  dueDate: { type: Date, required: true },
  repaidAmount: { type: Number, default: 0 },
  remainingAmount: { type: Number, required: true },
  lateFees: { type: Number, default: 0 }
}, { timestamps: true });

const Loan = mongoose.model('Loan', loanSchema);

// Cart Schema
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
    quantity: { type: Number, default: 1, min: 1 },
    price: { type: Number, required: true },
    purchaseType: { type: String, enum: ['rent', 'purchase'], required: true },
    duration: { type: Number, default: 30 } // days for rental
  }],
  total: { type: Number, default: 0 },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) }
}, { timestamps: true });

const Cart = mongoose.model('Cart', cartSchema);

// News Schema
const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['market', 'technology', 'regulatory', 'company'], 
    required: true 
  },
  tags: [String],
  imageUrl: { type: String },
  views: { type: Number, default: 0 },
  isFeatured: { type: Boolean, default: false }
}, { timestamps: true });

const News = mongoose.model('News', newsSchema);

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  code: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['verification', 'reset', 'two_factor'], 
    required: true 
  },
  expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
  attempts: { type: Number, default: 0, max: 3 },
  verified: { type: Boolean, default: false }
}, { timestamps: true });

const OTP = mongoose.model('OTP', otpSchema);

// Session Schema
const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  deviceInfo: {
    userAgent: String,
    ip: String,
    location: String
  },
  expiresAt: { type: Date, required: true },
  lastActivity: { type: Date, default: Date.now },
  isRevoked: { type: Boolean, default: false }
}, { timestamps: true });

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Session = mongoose.model('Session', sessionSchema);

// Announcement Schema
const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['info', 'warning', 'critical', 'maintenance'], 
    default: 'info' 
  },
  priority: { type: Number, default: 1 },
  isActive: { type: Boolean, default: true },
  startDate: { type: Date, default: Date.now },
  endDate: { type: Date }
}, { timestamps: true });

const Announcement = mongoose.model('Announcement', announcementSchema);

// Middleware for authentication
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if session is valid in Redis
    const sessionValid = await redis.get(`session:${decoded.userId}:${token}`);
    if (!sessionValid) {
      return res.status(401).json({ error: 'Session expired or invalid' });
    }

    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    logger.error('Authentication error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Middleware for KYC verification
const requireKYC = async (req, res, next) => {
  if (req.user.kycStatus !== 'verified') {
    return res.status(403).json({ 
      error: 'KYC verification required',
      kycStatus: req.user.kycStatus 
    });
  }
  next();
};

// Utility functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendEmail = async (to, subject, html) => {
  try {
    const mailOptions = {
      from: `"Hashvex Technologies" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    };

    await transporter.sendMail(mailOptions);
    logger.info(`Email sent to ${to}`);
    return true;
  } catch (error) {
    logger.error('Email sending failed:', error);
    return false;
  }
};

const sendSMS = async (to, message) => {
  if (!process.env.TWILIO_PHONE_NUMBER) {
    logger.warn('Twilio not configured, SMS not sent');
    return false;
  }

  try {
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to
    });
    logger.info(`SMS sent to ${to}`);
    return true;
  } catch (error) {
    logger.error('SMS sending failed:', error);
    return false;
  }
};

const getBitcoinPrice = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
      params: {
        ids: 'bitcoin',
        vs_currencies: 'usd',
        include_market_cap: true,
        include_24hr_vol: true,
        include_24hr_change: true
      },
      timeout: 5000
    });

    if (response.data?.bitcoin?.usd) {
      await redis.set('bitcoin_price', JSON.stringify(response.data.bitcoin), 'EX', 60);
      return response.data.bitcoin;
    }
    
    throw new Error('Invalid response from CoinGecko');
  } catch (error) {
    logger.warn('CoinGecko failed, trying CoinCap:', error.message);
    
    try {
      const response = await axios.get('https://api.coincap.io/v2/assets/bitcoin', {
        timeout: 5000
      });

      if (response.data?.data?.priceUsd) {
        const bitcoinData = {
          usd: parseFloat(response.data.data.priceUsd),
          usd_market_cap: parseFloat(response.data.data.marketCapUsd),
          usd_24h_vol: parseFloat(response.data.data.volumeUsd24Hr),
          usd_24h_change: parseFloat(response.data.data.changePercent24Hr)
        };
        
        await redis.set('bitcoin_price', JSON.stringify(bitcoinData), 'EX', 60);
        return bitcoinData;
      }
    } catch (fallbackError) {
      logger.error('All Bitcoin price APIs failed:', fallbackError.message);
    }

    // Return cached price if available
    const cachedPrice = await redis.get('bitcoin_price');
    if (cachedPrice) {
      return JSON.parse(cachedPrice);
    }

    return { usd: 45000, usd_market_cap: 880000000000, usd_24h_vol: 30000000000, usd_24h_change: 0 };
  }
};

// Generate Bitcoin address for user
const generateBitcoinAddress = async (userId) => {
  // In production, integrate with Bitcoin wallet service like BlockCypher, BitGo, or your own node
  const address = `3${crypto.randomBytes(20).toString('hex')}`; // Example P2SH address
  
  await redis.set(`btc_address:${userId}`, address, 'EX', 86400 * 30); // Store for 30 days
  
  return address;
};

// Process Bitcoin deposit confirmation
const checkBitcoinDeposit = async (address, amount) => {
  // In production, implement actual blockchain monitoring
  // This is a placeholder that simulates confirmation
  const txHash = crypto.randomBytes(32).toString('hex');
  
  return {
    confirmed: true,
    txHash,
    confirmations: 3,
    amount
  };
};

// Routes
// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    redis: redis.status === 'ready' ? 'connected' : 'disconnected',
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Auth Routes
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').trim().notEmpty(),
  body('lastName').trim().notEmpty(),
  body('city').trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, firstName, lastName, city, referralCode } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Validate referral code if provided
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (!referrer) {
        return res.status(400).json({ error: 'Invalid referral code' });
      }
      referredBy = referrer._id;
    }

    // Create user
    const user = new User({
      email,
      password,
      firstName,
      lastName,
      city,
      referredBy
    });

    await user.save();

    // Generate OTP
    const otpCode = generateOTP();
    const otp = new OTP({
      email,
      code: otpCode,
      type: 'verification',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await otp.save();

    // Send verification email
    const emailSent = await sendEmail(
      email,
      'Verify Your Hashvex Account',
      `
        <h2>Welcome to Hashvex Technologies!</h2>
        <p>Your verification code is: <strong>${otpCode}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't create an account, please ignore this email.</p>
      `
    );

    // Generate auth token
    const token = user.generateAuthToken();

    // Store session in Redis
    await redis.set(`session:${user._id}:${token}`, 'active', 'EX', 7200);

    res.status(201).json({
      message: 'Account created successfully. Please verify your email.',
      userId: user._id,
      token,
      requiresOTP: true
    });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(423).json({ 
        error: `Account is locked. Try again in ${remainingTime} minutes` 
      });
    }

    // Check password
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      await user.incrementLoginAttempts();
      
      if (user.loginAttempts >= 4) {
        const remainingAttempts = 5 - user.loginAttempts;
        return res.status(401).json({ 
          error: `Invalid credentials. ${remainingAttempts} attempts remaining before lock` 
        });
      }
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset login attempts
    await user.resetLoginAttempts();

    // Generate token
    const token = user.generateAuthToken();

    // Store session
    await redis.set(`session:${user._id}:${token}`, 'active', 'EX', 7200);

    // Update device info
    const deviceInfo = {
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      location: req.headers['cf-ipcountry'] || 'Unknown'
    };

    await Session.findOneAndUpdate(
      { userId: user._id, token },
      {
        $set: {
          deviceInfo,
          expiresAt: new Date(Date.now() + 7200 * 1000),
          lastActivity: new Date(),
          isRevoked: false
        }
      },
      { upsert: true }
    );

    // Check if 2FA is required
    if (user.twoFactorEnabled) {
      const otpCode = generateOTP();
      const otp = new OTP({
        email: user.email,
        code: otpCode,
        type: 'two_factor',
        expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
      });

      await otp.save();

      // Send 2FA code
      await sendEmail(
        user.email,
        'Your 2FA Code for Hashvex',
        `
          <h2>Two-Factor Authentication</h2>
          <p>Your verification code is: <strong>${otpCode}</strong></p>
          <p>This code will expire in 5 minutes.</p>
        `
      );

      return res.json({
        message: '2FA required',
        requires2FA: true,
        tempToken: token
      });
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        kycStatus: user.kycStatus,
        balance: user.balance
      },
      token
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/send-otp', [
  body('email').isEmail().normalizeEmail(),
  body('type').isIn(['verification', 'reset', 'two_factor'])
], async (req, res) => {
  try {
    const { email, type } = req.body;

    // Check if user exists (except for reset type)
    if (type !== 'reset') {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
    }

    // Delete existing OTPs for this email and type
    await OTP.deleteMany({ email, type });

    // Generate new OTP
    const otpCode = generateOTP();
    const otp = new OTP({
      email,
      code: otpCode,
      type,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await otp.save();

    // Send OTP
    let subject, html;
    switch (type) {
      case 'verification':
        subject = 'Verify Your Hashvex Account';
        html = `
          <h2>Email Verification</h2>
          <p>Your verification code is: <strong>${otpCode}</strong></p>
          <p>This code will expire in 10 minutes.</p>
        `;
        break;
      case 'reset':
        subject = 'Password Reset Code';
        html = `
          <h2>Password Reset</h2>
          <p>Your reset code is: <strong>${otpCode}</strong></p>
          <p>This code will expire in 10 minutes.</p>
        `;
        break;
      case 'two_factor':
        subject = 'Your 2FA Code';
        html = `
          <h2>Two-Factor Authentication</h2>
          <p>Your verification code is: <strong>${otpCode}</strong></p>
          <p>This code will expire in 10 minutes.</p>
        `;
        break;
    }

    const emailSent = await sendEmail(email, subject, html);

    if (emailSent) {
      res.json({ message: 'OTP sent successfully' });
    } else {
      res.status(500).json({ error: 'Failed to send OTP' });
    }
  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-otp', [
  body('email').isEmail().normalizeEmail(),
  body('code').isLength({ min: 6, max: 6 }),
  body('type').isIn(['verification', 'reset', 'two_factor'])
], async (req, res) => {
  try {
    const { email, code, type } = req.body;

    // Find OTP
    const otp = await OTP.findOne({ 
      email, 
      code, 
      type,
      expiresAt: { $gt: new Date() },
      verified: false
    });

    if (!otp) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Check attempts
    if (otp.attempts >= 3) {
      await OTP.deleteOne({ _id: otp._id });
      return res.status(400).json({ error: 'Too many attempts. Please request a new OTP.' });
    }

    // Increment attempts
    otp.attempts += 1;
    
    if (otp.attempts >= 3) {
      await otp.save();
      return res.status(400).json({ error: 'Too many attempts. Please request a new OTP.' });
    }

    // Verify OTP
    otp.verified = true;
    await otp.save();

    // Handle different OTP types
    if (type === 'verification') {
      await User.findOneAndUpdate(
        { email },
        { $set: { isVerified: true } }
      );
    }

    res.json({ 
      message: 'OTP verified successfully',
      verified: true 
    });
  } catch (error) {
    logger.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub: googleId } = payload;

    // Find or create user
    let user = await User.findOne({ 
      $or: [{ email }, { googleId }] 
    });

    if (!user) {
      // Create new user
      user = new User({
        email,
        googleId,
        firstName: given_name,
        lastName: family_name || '',
        city: 'Unknown',
        isVerified: true
      });

      await user.save();
    } else if (!user.googleId) {
      // Link Google account to existing email account
      user.googleId = googleId;
      await user.save();
    }

    // Generate token
    const token = user.generateAuthToken();

    // Store session
    await redis.set(`session:${user._id}:${token}`, 'active', 'EX', 7200);

    // Check if 2FA is required
    if (user.twoFactorEnabled) {
      const otpCode = generateOTP();
      const otp = new OTP({
        email: user.email,
        code: otpCode,
        type: 'two_factor',
        expiresAt: new Date(Date.now() + 5 * 60 * 1000)
      });

      await otp.save();

      await sendEmail(
        user.email,
        'Your 2FA Code for Hashvex',
        `
          <h2>Two-Factor Authentication</h2>
          <p>Your verification code is: <strong>${otpCode}</strong></p>
          <p>This code will expire in 5 minutes.</p>
        `
      );

      return res.json({
        message: '2FA required',
        requires2FA: true,
        tempToken: token
      });
    }

    res.json({
      message: 'Google login successful',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        kycStatus: user.kycStatus,
        balance: user.balance
      },
      token
    });
  } catch (error) {
    logger.error('Google login error:', error);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal that user doesn't exist
      return res.json({ message: 'If an account exists, you will receive a reset email' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    // Store in Redis
    await redis.set(
      `password_reset:${resetToken}`,
      JSON.stringify({
        userId: user._id,
        email: user.email
      }),
      'EX', 3600
    );

    // Send reset email
    const resetUrl = `https://hashvex-technologies.vercel.app/reset-password.html?token=${resetToken}`;
    
    await sendEmail(
      email,
      'Password Reset Request',
      `
        <h2>Password Reset</h2>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="${resetUrl}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    );

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify-reset-token', async (req, res) => {
  try {
    const { token } = req.body;

    const tokenData = await redis.get(`password_reset:${token}`);
    if (!tokenData) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    res.json({ valid: true });
  } catch (error) {
    logger.error('Verify reset token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const { token, password } = req.body;

    // Verify token
    const tokenData = await redis.get(`password_reset:${token}`);
    if (!tokenData) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const { userId, email } = JSON.parse(tokenData);

    // Update password
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.findByIdAndUpdate(userId, { password: hashedPassword });

    // Delete used token
    await redis.del(`password_reset:${token}`);

    // Invalidate all existing sessions
    const sessionKeys = await redis.keys(`session:${userId}:*`);
    if (sessionKeys.length > 0) {
      await redis.del(...sessionKeys);
    }

    // Send confirmation email
    await sendEmail(
      email,
      'Password Reset Successful',
      `
        <h2>Password Reset Successful</h2>
        <p>Your password has been successfully reset.</p>
        <p>If you didn't make this change, please contact support immediately.</p>
      `
    );

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    logger.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // Remove session from Redis
    await redis.del(`session:${req.user._id}:${req.token}`);

    // Remove from database
    await Session.findOneAndUpdate(
      { userId: req.user._id, token: req.token },
      { $set: { isRevoked: true } }
    );

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({ 
    authenticated: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      kycStatus: req.user.kycStatus,
      twoFactorEnabled: req.user.twoFactorEnabled
    }
  });
});

// User Routes
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -twoFactorSecret')
      .lean();

    res.json({ user });
  } catch (error) {
    logger.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/balances', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('balance')
      .lean();

    // Get Bitcoin price for conversion
    const btcPrice = await getBitcoinPrice();
    const totalUsd = user.balance.usd + (user.balance.btc * btcPrice.usd);

    res.json({
      balances: user.balance,
      btcPrice: btcPrice.usd,
      totalUsd
    });
  } catch (error) {
    logger.error('Get balances error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/profile', authenticate, [
  body('firstName').optional().trim().notEmpty(),
  body('lastName').optional().trim().notEmpty(),
  body('phone').optional().trim(),
  body('country').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const updates = {};
    if (req.body.firstName) updates.firstName = req.body.firstName;
    if (req.body.lastName) updates.lastName = req.body.lastName;
    if (req.body.phone) updates.phone = req.body.phone;
    if (req.body.country) updates.country = req.body.country;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret');

    res.json({ 
      message: 'Profile updated successfully',
      user 
    });
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/address', authenticate, [
  body('city').trim().notEmpty(),
  body('country').trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { city, country } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: { city, country } },
      { new: true }
    ).select('-password -twoFactorSecret');

    res.json({ 
      message: 'Address updated successfully',
      user 
    });
  } catch (error) {
    logger.error('Update address error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// KYC Routes
app.get('/api/users/kyc/status', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('kycStatus kycData')
      .lean();

    res.json({
      kycStatus: user.kycStatus,
      submittedAt: user.kycData?.submittedAt,
      verifiedAt: user.kycData?.verifiedAt
    });
  } catch (error) {
    logger.error('Get KYC status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/kyc', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('kycData')
      .lean();

    res.json({ kycData: user.kycData || {} });
  } catch (error) {
    logger.error('Get KYC data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'));
    }
  }
});

app.post('/api/users/kyc/identity', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { documentType, documentNumber } = req.body;
    
    if (!documentType || !documentNumber) {
      return res.status(400).json({ error: 'Document type and number are required' });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'kyc_documents',
          resource_type: 'image',
          format: 'jpg',
          transformation: [
            { quality: 'auto:good' },
            { fetch_format: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );

      uploadStream.end(req.file.buffer);
    });

    // Update user KYC data
    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        'kycData.documentType': documentType,
        'kycData.documentNumber': documentNumber,
        'kycData.documentFront': uploadResult.secure_url,
        'kycStatus': 'pending'
      }
    });

    res.json({ 
      message: 'Identity document uploaded successfully',
      url: uploadResult.secure_url 
    });
  } catch (error) {
    logger.error('Upload identity error:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});

app.post('/api/users/kyc/address', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'kyc_documents',
          resource_type: 'image',
          format: 'jpg',
          transformation: [
            { quality: 'auto:good' },
            { fetch_format: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );

      uploadStream.end(req.file.buffer);
    });

    // Update user KYC data
    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        'kycData.addressProof': uploadResult.secure_url
      }
    });

    res.json({ 
      message: 'Address document uploaded successfully',
      url: uploadResult.secure_url 
    });
  } catch (error) {
    logger.error('Upload address proof error:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});

app.post('/api/users/kyc/facial', authenticate, upload.single('selfie'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No selfie uploaded' });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'kyc_selfies',
          resource_type: 'image',
          format: 'jpg',
          transformation: [
            { quality: 'auto:good' },
            { fetch_format: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );

      uploadStream.end(req.file.buffer);
    });

    // Update user KYC data
    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        'kycData.selfie': uploadResult.secure_url
      }
    });

    res.json({ 
      message: 'Facial verification uploaded successfully',
      url: uploadResult.secure_url 
    });
  } catch (error) {
    logger.error('Upload facial verification error:', error);
    res.status(500).json({ error: 'Failed to upload selfie' });
  }
});

app.post('/api/users/kyc/submit', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Check if all required documents are uploaded
    if (!user.kycData?.documentFront || !user.kycData?.addressProof || !user.kycData?.selfie) {
      return res.status(400).json({ 
        error: 'Please upload all required documents before submission' 
      });
    }

    // Update submission timestamp
    await User.findByIdAndUpdate(req.user._id, {
      $set: {
        'kycData.submittedAt': new Date(),
        'kycStatus': 'pending'
      }
    });

    // Notify admin about KYC submission (in production, integrate with admin panel)
    await sendEmail(
      process.env.ADMIN_EMAIL || 'admin@hashvex.com',
      'New KYC Submission',
      `
        <h2>New KYC Submission</h2>
        <p>User: ${user.email}</p>
        <p>Name: ${user.firstName} ${user.lastName}</p>
        <p>Submitted at: ${new Date().toISOString()}</p>
        <p>Please review in the admin panel.</p>
      `
    );

    res.json({ message: 'KYC submitted successfully for review' });
  } catch (error) {
    logger.error('Submit KYC error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/records', authenticate, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;

    // Verify credentials
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ verified: true });
  } catch (error) {
    logger.error('Verify records error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Two-Factor Authentication Routes
app.get('/api/users/two-factor', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('twoFactorEnabled')
      .lean();

    // Generate QR code if 2FA is not enabled
    let qrCodeUrl = null;
    if (!user.twoFactorEnabled) {
      const secret = speakeasy.generateSecret({
        name: `Hashvex:${req.user.email}`
      });

      await User.findByIdAndUpdate(req.user._id, {
        $set: { twoFactorSecret: secret.base32 }
      });

      qrCodeUrl = secret.otpauth_url;
    }

    res.json({
      twoFactorEnabled: user.twoFactorEnabled,
      qrCodeUrl
    });
  } catch (error) {
    logger.error('Get 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/two-factor/enable', authenticate, [
  body('code').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const { code } = req.body;

    const user = await User.findById(req.user._id);
    if (!user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not set up' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    user.twoFactorEnabled = true;
    await user.save();

    // Send backup codes
    const backupCodes = Array.from({ length: 10 }, () => 
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    await redis.set(
      `backup_codes:${req.user._id}`,
      JSON.stringify(backupCodes),
      'EX', 86400 * 30 // 30 days
    );

    // Send backup codes via email
    await sendEmail(
      user.email,
      '2FA Enabled - Backup Codes',
      `
        <h2>Two-Factor Authentication Enabled</h2>
        <p>Your account is now protected with 2FA.</p>
        <h3>Backup Codes:</h3>
        <p>Save these codes in a secure place. Each code can be used once.</p>
        <ul>
          ${backupCodes.map(code => `<li><code>${code}</code></li>`).join('')}
        </ul>
        <p><strong>Warning:</strong> These codes will not be shown again.</p>
      `
    );

    res.json({ 
      message: '2FA enabled successfully',
      backupCodes 
    });
  } catch (error) {
    logger.error('Enable 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/two-factor/disable', authenticate, [
  body('code').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const { code } = req.body;

    const user = await User.findById(req.user._id);
    
    // Verify with current 2FA code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!verified) {
      // Check backup codes
      const backupCodes = await redis.get(`backup_codes:${req.user._id}`);
      if (backupCodes) {
        const codes = JSON.parse(backupCodes);
        const index = codes.indexOf(code);
        if (index === -1) {
          return res.status(400).json({ error: 'Invalid verification code' });
        }
        
        // Remove used backup code
        codes.splice(index, 1);
        await redis.set(
          `backup_codes:${req.user._id}`,
          JSON.stringify(codes),
          'EX', 86400 * 30
        );
      } else {
        return res.status(400).json({ error: 'Invalid verification code' });
      }
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();

    // Remove backup codes
    await redis.del(`backup_codes:${req.user._id}`);

    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    logger.error('Disable 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Device Management Routes
app.get('/api/users/devices', authenticate, async (req, res) => {
  try {
    const sessions = await Session.find({ 
      userId: req.user._id,
      isRevoked: false,
      expiresAt: { $gt: new Date() }
    })
    .sort({ lastActivity: -1 })
    .limit(10)
    .lean();

    res.json({ devices: sessions });
  } catch (error) {
    logger.error('Get devices error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/devices/:deviceId/revoke', authenticate, async (req, res) => {
  try {
    const { deviceId } = req.params;

    await Session.findByIdAndUpdate(deviceId, {
      $set: { isRevoked: true }
    });

    // Remove from Redis if it's the current session
    const session = await Session.findById(deviceId);
    if (session) {
      await redis.del(`session:${req.user._id}:${session.token}`);
    }

    res.json({ message: 'Device session revoked' });
  } catch (error) {
    logger.error('Revoke device error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Activity Logs
app.get('/api/users/activity', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const activities = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments({ userId: req.user._id });

    res.json({
      activities,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get activity error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Notification Preferences
app.get('/api/users/notifications', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('settings.notifications')
      .lean();

    res.json({ preferences: user.settings.notifications });
  } catch (error) {
    logger.error('Get notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/notifications', authenticate, [
  body('email').optional().isBoolean(),
  body('sms').optional().isBoolean(),
  body('push').optional().isBoolean()
], async (req, res) => {
  try {
    const updates = {};
    if (typeof req.body.email === 'boolean') updates['settings.notifications.email'] = req.body.email;
    if (typeof req.body.sms === 'boolean') updates['settings.notifications.sms'] = req.body.sms;
    if (typeof req.body.push === 'boolean') updates['settings.notifications.push'] = req.body.push;

    await User.findByIdAndUpdate(req.user._id, { $set: updates });

    res.json({ message: 'Notification preferences updated' });
  } catch (error) {
    logger.error('Update notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API Keys Management
app.get('/api/users/api-keys', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('apiKeys')
      .lean();

    res.json({ apiKeys: user.apiKeys || [] });
  } catch (error) {
    logger.error('Get API keys error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/api-keys', authenticate, [
  body('name').trim().notEmpty(),
  body('permissions').isArray()
], async (req, res) => {
  try {
    const { name, permissions } = req.body;

    // Validate permissions
    const validPermissions = ['read', 'write', 'trade', 'withdraw'];
    const invalidPermissions = permissions.filter(p => !validPermissions.includes(p));
    
    if (invalidPermissions.length > 0) {
      return res.status(400).json({ 
        error: `Invalid permissions: ${invalidPermissions.join(', ')}` 
      });
    }

    const apiKey = crypto.randomBytes(32).toString('hex');
    const apiKeyData = {
      key: apiKey,
      name,
      permissions,
      createdAt: new Date()
    };

    await User.findByIdAndUpdate(req.user._id, {
      $push: { apiKeys: apiKeyData }
    });

    // Store hashed key in Redis for validation
    const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
    await redis.set(
      `api_key:${hashedKey}`,
      JSON.stringify({
        userId: req.user._id,
        permissions
      }),
      'EX', 86400 * 365 // 1 year
    );

    res.json({ 
      message: 'API key created successfully',
      apiKey,
      apiKeyData: { ...apiKeyData, key: '***' + apiKey.slice(-4) }
    });
  } catch (error) {
    logger.error('Create API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/users/api-keys/:keyId', authenticate, async (req, res) => {
  try {
    const { keyId } = req.params;

    const user = await User.findById(req.user._id);
    const apiKey = user.apiKeys.find(key => key._id.toString() === keyId);
    
    if (!apiKey) {
      return res.status(404).json({ error: 'API key not found' });
    }

    // Remove from user
    user.apiKeys = user.apiKeys.filter(key => key._id.toString() !== keyId);
    await user.save();

    // Remove from Redis
    const hashedKey = crypto.createHash('sha256').update(apiKey.key).digest('hex');
    await redis.del(`api_key:${hashedKey}`);

    res.json({ message: 'API key revoked successfully' });
  } catch (error) {
    logger.error('Delete API key error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Balance Routes
app.get('/api/balances', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('balance')
      .lean();

    const btcPrice = await getBitcoinPrice();
    const totalUsd = user.balance.usd + (user.balance.btc * btcPrice.usd);

    res.json({
      btc: user.balance.btc,
      usd: user.balance.usd,
      pendingBtc: user.balance.pendingBtc,
      pendingUsd: user.balance.pendingUsd,
      btcPrice: btcPrice.usd,
      totalUsd,
      totalBtc: user.balance.btc + (user.balance.usd / btcPrice.usd)
    });
  } catch (error) {
    logger.error('Get balances error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Withdrawal Routes
app.get('/api/withdrawals/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const withdrawals = await Withdrawal.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Withdrawal.countDocuments({ userId: req.user._id });

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/withdrawals/btc', authenticate, requireKYC, [
  body('amount').isFloat({ min: 0.0001 }),
  body('address').isLength({ min: 26, max: 35 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, address } = req.body;
    const user = await User.findById(req.user._id);

    // Validate Bitcoin address format
    if (!/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address) && 
        !/^bc1[ac-hj-np-z02-9]{11,71}$/.test(address)) {
      return res.status(400).json({ error: 'Invalid Bitcoin address format' });
    }

    // Check balance
    if (user.balance.btc < amount) {
      return res.status(400).json({ error: 'Insufficient BTC balance' });
    }

    // Calculate fee (0.0005 BTC or 1%, whichever is higher)
    const fee = Math.max(0.0005, amount * 0.01);
    const netAmount = amount - fee;

    // Create withdrawal record
    const withdrawal = new Withdrawal({
      userId: user._id,
      type: 'btc',
      amount,
      currency: 'BTC',
      btcAddress: address,
      fee,
      netAmount,
      status: 'pending'
    });

    await withdrawal.save();

    // Deduct from balance
    user.balance.btc -= amount;
    user.balance.pendingBtc += amount;
    await user.save();

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: -amount,
      currency: 'BTC',
      status: 'pending',
      address,
      description: `BTC withdrawal to ${address}`,
      metadata: { withdrawalId: withdrawal._id, fee }
    });

    await transaction.save();

    // Notify admin for approval (in production)
    await sendEmail(
      process.env.ADMIN_EMAIL || 'admin@hashvex.com',
      'BTC Withdrawal Request - Approval Required',
      `
        <h2>New BTC Withdrawal Request</h2>
        <p>User: ${user.email}</p>
        <p>Amount: ${amount} BTC</p>
        <p>Address: ${address}</p>
        <p>Net Amount: ${netAmount} BTC (Fee: ${fee} BTC)</p>
        <p>Withdrawal ID: ${withdrawal._id}</p>
        <p>Please review and process in the admin panel.</p>
      `
    );

    // Simulate processing (in production, integrate with Bitcoin wallet service)
    setTimeout(async () => {
      try {
        withdrawal.status = 'processing';
        await withdrawal.save();

        // Simulate blockchain transaction
        const txHash = crypto.randomBytes(32).toString('hex');
        
        setTimeout(async () => {
          withdrawal.status = 'completed';
          withdrawal.approvedAt = new Date();
          await withdrawal.save();

          // Update user balance
          await User.findByIdAndUpdate(user._id, {
            $inc: { 'balance.pendingBtc': -amount }
          });

          // Update transaction
          await Transaction.findByIdAndUpdate(transaction._id, {
            $set: { 
              status: 'completed',
              txHash,
              confirmedAt: new Date()
            }
          });

          // Send confirmation email
          await sendEmail(
            user.email,
            'BTC Withdrawal Completed',
            `
              <h2>BTC Withdrawal Completed</h2>
              <p>Your withdrawal of ${amount} BTC has been processed.</p>
              <p>Transaction Hash: ${txHash}</p>
              <p>Net Amount: ${netAmount} BTC (Fee: ${fee} BTC)</p>
              <p>Sent to: ${address}</p>
              <p>If you didn't make this withdrawal, please contact support immediately.</p>
            `
          );
        }, 30000); // Simulate 30 second confirmation time
      } catch (error) {
        logger.error('Withdrawal processing error:', error);
      }
    }, 5000); // Simulate 5 second processing delay

    res.json({
      message: 'Withdrawal request submitted for processing',
      withdrawalId: withdrawal._id,
      amount,
      fee,
      netAmount,
      estimatedTime: '30-60 minutes'
    });
  } catch (error) {
    logger.error('BTC withdrawal error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/withdrawals/bank', authenticate, requireKYC, [
  body('amount').isFloat({ min: 10 }),
  body('accountName').trim().notEmpty(),
  body('accountNumber').trim().notEmpty(),
  body('bankName').trim().notEmpty(),
  body('swiftCode').optional().trim(),
  body('iban').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, accountName, accountNumber, bankName, swiftCode, iban } = req.body;
    const user = await User.findById(req.user._id);

    // Check balance (convert BTC to USD if needed)
    const btcPrice = await getBitcoinPrice();
    const availableUsd = user.balance.usd + (user.balance.btc * btcPrice.usd);
    
    if (availableUsd < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Calculate fee (25 USD or 2%, whichever is higher)
    const fee = Math.max(25, amount * 0.02);
    const netAmount = amount - fee;

    // Determine which balance to deduct from
    let btcToSell = 0;
    let usdToDeduct = amount;
    
    if (user.balance.usd < amount) {
      btcToSell = (amount - user.balance.usd) / btcPrice.usd;
      usdToDeduct = user.balance.usd;
    }

    // Create withdrawal record
    const withdrawal = new Withdrawal({
      userId: user._id,
      type: 'bank',
      amount,
      currency: 'USD',
      bankDetails: {
        accountName,
        accountNumber,
        bankName,
        swiftCode,
        iban
      },
      fee,
      netAmount,
      status: 'pending'
    });

    await withdrawal.save();

    // Update balances
    const updates = {
      'balance.usd': user.balance.usd - usdToDeduct,
      'balance.pendingUsd': user.balance.pendingUsd + usdToDeduct
    };

    if (btcToSell > 0) {
      updates['balance.btc'] = user.balance.btc - btcToSell;
      updates['balance.pendingBtc'] = user.balance.pendingBtc + btcToSell;
    }

    await User.findByIdAndUpdate(user._id, { $set: updates });

    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount: -amount,
      currency: 'USD',
      status: 'pending',
      description: `Bank withdrawal to ${bankName}`,
      metadata: { 
        withdrawalId: withdrawal._id,
        fee,
        bankDetails: { accountName, bankName }
      }
    });

    await transaction.save();

    // Notify admin for approval
    await sendEmail(
      process.env.ADMIN_EMAIL || 'admin@hashvex.com',
      'Bank Withdrawal Request - Approval Required',
      `
        <h2>New Bank Withdrawal Request</h2>
        <p>User: ${user.email}</p>
        <p>Amount: $${amount} USD</p>
        <p>Bank: ${bankName}</p>
        <p>Account: ${accountName} (${accountNumber})</p>
        <p>Net Amount: $${netAmount} USD (Fee: $${fee} USD)</p>
        <p>Withdrawal ID: ${withdrawal._id}</p>
        <p>Please review and process in the admin panel.</p>
      `
    );

    // Simulate processing (in production, integrate with bank API)
    setTimeout(async () => {
      try {
        withdrawal.status = 'processing';
        await withdrawal.save();

        setTimeout(async () => {
          withdrawal.status = 'completed';
          withdrawal.approvedAt = new Date();
          await withdrawal.save();

          // Update pending balances
          const pendingUpdate = {
            'balance.pendingUsd': user.balance.pendingUsd - usdToDeduct
          };

          if (btcToSell > 0) {
            pendingUpdate['balance.pendingBtc'] = user.balance.pendingBtc - btcToSell;
          }

          await User.findByIdAndUpdate(user._id, { $set: pendingUpdate });

          // Update transaction
          await Transaction.findByIdAndUpdate(transaction._id, {
            $set: { 
              status: 'completed',
              confirmedAt: new Date()
            }
          });

          // Send confirmation email
          await sendEmail(
            user.email,
            'Bank Withdrawal Completed',
            `
              <h2>Bank Withdrawal Completed</h2>
              <p>Your withdrawal of $${amount} USD has been processed.</p>
              <p>Net Amount: $${netAmount} USD (Fee: $${fee} USD)</p>
              <p>Sent to: ${accountName} at ${bankName}</p>
              <p>Account: ${accountNumber}</p>
              <p>Funds should arrive in 3-5 business days.</p>
              <p>If you didn't make this withdrawal, please contact support immediately.</p>
            `
          );
        }, 60000); // Simulate 1 minute processing
      } catch (error) {
        logger.error('Bank withdrawal processing error:', error);
      }
    }, 5000);

    res.json({
      message: 'Bank withdrawal request submitted',
      withdrawalId: withdrawal._id,
      amount,
      fee,
      netAmount,
      estimatedTime: '3-5 business days'
    });
  } catch (error) {
    logger.error('Bank withdrawal error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Deposit Routes
app.get('/api/deposits/btc-address', authenticate, async (req, res) => {
  try {
    // Generate or retrieve BTC address for user
    let address = await redis.get(`btc_address:${req.user._id}`);
    
    if (!address) {
      address = await generateBitcoinAddress(req.user._id);
    }

    // Get current Bitcoin price
    const btcPrice = await getBitcoinPrice();

    res.json({
      address,
      qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${address}`,
      btcPrice: btcPrice.usd,
      minimumDeposit: 0.0001,
      note: 'Send only Bitcoin (BTC) to this address. Other cryptocurrencies will be lost.'
    });
  } catch (error) {
    logger.error('Get BTC address error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/deposits/btc-status', authenticate, async (req, res) => {
  try {
    const { address } = req.body;
    
    if (!address) {
      return res.status(400).json({ error: 'Address is required' });
    }

    // Check if this address belongs to the user
    const userAddress = await redis.get(`btc_address:${req.user._id}`);
    if (address !== userAddress) {
      return res.status(400).json({ error: 'Invalid address' });
    }

    // Check for confirmed deposits (in production, monitor blockchain)
    const deposit = await Deposit.findOne({
      userId: req.user._id,
      btcAddress: address,
      status: { $in: ['pending', 'confirmed'] }
    }).sort({ createdAt: -1 });

    if (!deposit) {
      return res.json({ 
        status: 'no_deposit',
        message: 'No pending deposit found for this address' 
      });
    }

    // Simulate confirmation (in production, check blockchain)
    if (deposit.status === 'pending') {
      const confirmations = deposit.confirmations + 1;
      
      if (confirmations >= 3) {
        deposit.status = 'confirmed';
        deposit.confirmedAt = new Date();
        
        // Credit user's balance
        await User.findByIdAndUpdate(req.user._id, {
          $inc: { 'balance.btc': deposit.amount }
        });

        // Create transaction record
        const transaction = new Transaction({
          userId: req.user._id,
          type: 'deposit',
          amount: deposit.amount,
          currency: 'BTC',
          status: 'completed',
          txHash: deposit.txHash || `sim_${crypto.randomBytes(16).toString('hex')}`,
          address: deposit.btcAddress,
          description: 'BTC deposit',
          confirmedAt: new Date()
        });

        await transaction.save();

        // Update deposit
        deposit.status = 'completed';
      } else {
        deposit.confirmations = confirmations;
      }

      await deposit.save();
    }

    res.json({
      status: deposit.status,
      amount: deposit.amount,
      confirmations: deposit.confirmations,
      requiredConfirmations: 3,
      txHash: deposit.txHash,
      createdAt: deposit.createdAt,
      confirmedAt: deposit.confirmedAt
    });
  } catch (error) {
    logger.error('Check BTC status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/deposits/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const deposits = await Deposit.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Deposit.countDocuments({ userId: req.user._id });

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Simulate BTC deposit webhook (in production, this would be from blockchain listener)
app.post('/api/webhooks/btc-deposit', async (req, res) => {
  try {
    const { address, amount, txHash, confirmations } = req.body;

    // Verify webhook signature (in production)
    const signature = req.headers['x-signature'];
    if (!signature || signature !== process.env.WEBHOOK_SECRET) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Find user by address
    const userId = await redis.get(`address_user:${address}`);
    if (!userId) {
      return res.status(404).json({ error: 'Address not found' });
    }

    // Check for duplicate deposit
    const existingDeposit = await Deposit.findOne({ txHash });
    if (existingDeposit) {
      return res.json({ message: 'Deposit already processed' });
    }

    // Create deposit record
    const deposit = new Deposit({
      userId,
      type: 'btc',
      amount,
      currency: 'BTC',
      btcAddress: address,
      txHash,
      confirmations,
      status: confirmations >= 3 ? 'confirmed' : 'pending'
    });

    await deposit.save();

    if (confirmations >= 3) {
      // Credit balance
      await User.findByIdAndUpdate(userId, {
        $inc: { 'balance.btc': amount }
      });

      // Create transaction
      const transaction = new Transaction({
        userId,
        type: 'deposit',
        amount,
        currency: 'BTC',
        status: 'completed',
        txHash,
        address,
        description: 'BTC deposit',
        confirmedAt: new Date()
      });

      await transaction.save();

      // Send notification
      const user = await User.findById(userId);
      await sendEmail(
        user.email,
        'BTC Deposit Received',
        `
          <h2>BTC Deposit Confirmed</h2>
          <p>You have received ${amount} BTC.</p>
          <p>Transaction Hash: ${txHash}</p>
          <p>New Balance: ${user.balance.btc + amount} BTC</p>
        `
      );
    }

    res.json({ message: 'Deposit recorded', depositId: deposit._id });
  } catch (error) {
    logger.error('BTC deposit webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Card Payment Routes
app.post('/api/payments/store-card', authenticate, async (req, res) => {
  try {
    const { cardNumber, expMonth, expYear, cvc } = req.body;

    // In production, use Stripe or other payment processor
    // This is a simplified version
    const last4 = cardNumber.slice(-4);
    const brand = cardNumber.startsWith('4') ? 'Visa' : 
                  cardNumber.startsWith('5') ? 'Mastercard' : 
                  cardNumber.startsWith('3') ? 'American Express' : 'Unknown';

    // Simulate storing in payment processor
    const chargeId = `ch_${crypto.randomBytes(12).toString('hex')}`;

    // Store in Redis (in production, use secure vault)
    await redis.set(
      `card:${req.user._id}:${last4}`,
      JSON.stringify({
        last4,
        brand,
        chargeId,
        expMonth,
        expYear
      }),
      'EX', 86400 * 365 // 1 year
    );

    res.json({
      message: 'Card stored successfully',
      card: { last4, brand }
    });
  } catch (error) {
    logger.error('Store card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/payments/card-deposit', authenticate, [
  body('amount').isFloat({ min: 10 }),
  body('last4').isLength(4)
], async (req, res) => {
  try {
    const { amount, last4 } = req.body;

    // Get card from Redis
    const cardData = await redis.get(`card:${req.user._id}:${last4}`);
    if (!cardData) {
      return res.status(400).json({ error: 'Card not found' });
    }

    // In production, process with Stripe
    const card = JSON.parse(cardData);
    const chargeId = `ch_${crypto.randomBytes(12).toString('hex')}`;

    // Simulate processing delay
    setTimeout(async () => {
      try {
        // Create deposit record
        const deposit = new Deposit({
          userId: req.user._id,
          type: 'card',
          amount,
          currency: 'USD',
          status: 'completed',
          cardDetails: {
            last4: card.last4,
            brand: card.brand,
            chargeId
          }
        });

        await deposit.save();

        // Credit user balance
        await User.findByIdAndUpdate(req.user._id, {
          $inc: { 'balance.usd': amount }
        });

        // Create transaction
        const transaction = new Transaction({
          userId: req.user._id,
          type: 'deposit',
          amount,
          currency: 'USD',
          status: 'completed',
          description: `Card deposit (${card.brand} ****${card.last4})`,
          metadata: { chargeId },
          confirmedAt: new Date()
        });

        await transaction.save();

        // Send confirmation
        const user = await User.findById(req.user._id);
        await sendEmail(
          user.email,
          'Card Deposit Successful',
          `
            <h2>Deposit Confirmed</h2>
            <p>You have deposited $${amount} USD via ${card.brand} card.</p>
            <p>Transaction ID: ${chargeId}</p>
            <p>New Balance: $${user.balance.usd + amount} USD</p>
          `
        );
      } catch (error) {
        logger.error('Card deposit processing error:', error);
      }
    }, 2000);

    res.json({
      message: 'Deposit processing',
      amount,
      estimatedTime: '2-3 seconds',
      transactionId: chargeId
    });
  } catch (error) {
    logger.error('Card deposit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Miner Routes
app.get('/api/miners/rent', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;

    const miners = await Miner.find({ 
      status: 'available',
      availability: { $gt: 0 }
    })
    .skip(skip)
    .limit(limit)
    .lean();

    const total = await Miner.countDocuments({ 
      status: 'available',
      availability: { $gt: 0 }
    });

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/miners/sale', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;

    const miners = await Miner.find({ 
      status: 'available'
    })
    .skip(skip)
    .limit(limit)
    .lean();

    const total = await Miner.countDocuments({ 
      status: 'available'
    });

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/miners/owned', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const userMiners = await UserMiner.find({ 
      userId: req.user._id,
      status: 'active'
    })
    .populate('minerId')
    .skip(skip)
    .limit(limit)
    .lean();

    const total = await UserMiner.countDocuments({ 
      userId: req.user._id,
      status: 'active'
    });

    res.json({
      miners: userMiners,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get owned miners error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/miners/:id', authenticate, async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id).lean();
    
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    // Get current Bitcoin price for profitability calculation
    const btcPrice = await getBitcoinPrice();
    const dailyUsd = miner.profitability.dailyBtc * btcPrice.usd;
    const monthlyUsd = dailyUsd * 30;
    const yearlyUsd = dailyUsd * 365;

    const enhancedMiner = {
      ...miner,
      profitability: {
        ...miner.profitability,
        dailyUsd,
        monthlyUsd,
        yearlyUsd,
        roiDays: miner.price / dailyUsd
      }
    };

    res.json({ miner: enhancedMiner });
  } catch (error) {
    logger.error('Get miner error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/miners/:id/extend', authenticate, [
  body('duration').isInt({ min: 30, max: 365 })
], async (req, res) => {
  try {
    const { duration } = req.body;
    const userMiner = await UserMiner.findOne({
      userId: req.user._id,
      minerId: req.params.id,
      status: 'active',
      purchaseType: 'rent'
    }).populate('minerId');

    if (!userMiner) {
      return res.status(404).json({ error: 'Miner not found or not rented' });
    }

    const extensionCost = userMiner.minerId.rentalPrice * (duration / 30);
    
    // Check balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < extensionCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Process payment
    user.balance.usd -= extensionCost;
    await user.save();

    // Extend rental
    const newExpiry = userMiner.expiryDate ? 
      new Date(userMiner.expiryDate.getTime() + duration * 24 * 60 * 60 * 1000) :
      new Date(Date.now() + duration * 24 * 60 * 60 * 1000);
    
    userMiner.expiryDate = newExpiry;
    userMiner.pricePaid += extensionCost;
    await userMiner.save();

    // Create transaction
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'rental',
      amount: -extensionCost,
      currency: 'USD',
      status: 'completed',
      description: `Extended rental for ${userMiner.minerId.name} (${duration} days)`,
      metadata: { 
        minerId: userMiner.minerId._id,
        duration,
        newExpiry 
      }
    });

    await transaction.save();

    res.json({
      message: 'Rental extended successfully',
      newExpiry,
      extensionCost,
      remainingBalance: user.balance.usd
    });
  } catch (error) {
    logger.error('Extend miner error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Cart Routes
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    let cart = await Cart.findOne({ 
      userId: req.user._id,
      expiresAt: { $gt: new Date() }
    }).populate('items.minerId');

    if (!cart) {
      cart = new Cart({
        userId: req.user._id,
        items: [],
        total: 0
      });
      await cart.save();
    }

    res.json({ cart });
  } catch (error) {
    logger.error('Get cart error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/add', authenticate, [
  body('minerId').isMongoId(),
  body('quantity').optional().isInt({ min: 1 }),
  body('purchaseType').isIn(['rent', 'purchase']),
  body('duration').optional().isInt({ min: 30, max: 365 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { minerId, quantity = 1, purchaseType, duration = 30 } = req.body;

    // Check miner availability
    const miner = await Miner.findById(minerId);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    if (miner.availability < quantity) {
      return res.status(400).json({ error: 'Insufficient miner availability' });
    }

    // Calculate price
    const price = purchaseType === 'rent' ? 
      miner.rentalPrice * (duration / 30) * quantity :
      miner.price * quantity;

    // Find or create cart
    let cart = await Cart.findOne({ 
      userId: req.user._id,
      expiresAt: { $gt: new Date() }
    });

    if (!cart) {
      cart = new Cart({
        userId: req.user._id,
        items: [],
        total: 0
      });
    }

    // Check if item already in cart
    const existingItemIndex = cart.items.findIndex(
      item => item.minerId.toString() === minerId && item.purchaseType === purchaseType
    );

    if (existingItemIndex > -1) {
      // Update existing item
      cart.items[existingItemIndex].quantity += quantity;
      cart.items[existingItemIndex].price = price / quantity * cart.items[existingItemIndex].quantity;
    } else {
      // Add new item
      cart.items.push({
        minerId,
        quantity,
        price: price / quantity,
        purchaseType,
        duration: purchaseType === 'rent' ? duration : undefined
      });
    }

    // Recalculate total
    cart.total = cart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    cart.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // Extend expiry

    await cart.save();

    res.json({
      message: 'Item added to cart',
      cart
    });
  } catch (error) {
    logger.error('Add to cart error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/cart/checkout', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ 
      userId: req.user._id,
      expiresAt: { $gt: new Date() }
    }).populate('items.minerId');

    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const user = await User.findById(req.user._id);

    // Validate cart items availability and calculate total
    let total = 0;
    const itemsToProcess = [];

    for (const item of cart.items) {
      if (item.minerId.availability < item.quantity) {
        return res.status(400).json({ 
          error: `Insufficient availability for ${item.minerId.name}` 
        });
      }

      const itemTotal = item.price * item.quantity;
      total += itemTotal;
      itemsToProcess.push(item);
    }

    // Check balance
    if (user.balance.usd < total) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Process each item
    const processedItems = [];

    for (const item of itemsToProcess) {
      // Deduct from miner availability
      await Miner.findByIdAndUpdate(item.minerId._id, {
        $inc: { availability: -item.quantity }
      });

      // Create user miner record(s)
      for (let i = 0; i < item.quantity; i++) {
        const userMiner = new UserMiner({
          userId: user._id,
          minerId: item.minerId._id,
          purchaseType: item.purchaseType,
          pricePaid: item.price,
          expiryDate: item.purchaseType === 'rent' ? 
            new Date(Date.now() + item.duration * 24 * 60 * 60 * 1000) : 
            undefined,
          status: 'active'
        });

        await userMiner.save();
        processedItems.push(userMiner);
      }

      // Create transaction
      const transaction = new Transaction({
        userId: user._id,
        type: item.purchaseType === 'rent' ? 'rental' : 'purchase',
        amount: -item.price * item.quantity,
        currency: 'USD',
        status: 'completed',
        description: `${item.purchaseType === 'rent' ? 'Rented' : 'Purchased'} ${item.quantity}x ${item.minerId.name}`,
        metadata: { 
          minerId: item.minerId._id,
          quantity: item.quantity,
          purchaseType: item.purchaseType 
        }
      });

      await transaction.save();
    }

    // Deduct from user balance
    user.balance.usd -= total;
    await user.save();

    // Clear cart
    cart.items = [];
    cart.total = 0;
    await cart.save();

    // Send confirmation email
    await sendEmail(
      user.email,
      'Order Confirmation',
      `
        <h2>Order Confirmed</h2>
        <p>Thank you for your order!</p>
        <p>Total: $${total} USD</p>
        <h3>Items:</h3>
        <ul>
          ${itemsToProcess.map(item => `
            <li>
              ${item.quantity}x ${item.minerId.name} (${item.purchaseType}) - $${item.price * item.quantity} USD
            </li>
          `).join('')}
        </ul>
        <p>Your miners are now active in your dashboard.</p>
      `
    );

    res.json({
      message: 'Checkout successful',
      orderId: crypto.randomBytes(8).toString('hex'),
      total,
      processedItems: processedItems.length,
      remainingBalance: user.balance.usd
    });
  } catch (error) {
    logger.error('Checkout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Transaction Routes
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments({ userId: req.user._id });

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Loan Routes
app.get('/api/loans/limit', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Calculate loan limit based on BTC collateral
    const btcPrice = await getBitcoinPrice();
    const collateralValue = user.balance.btc * btcPrice.usd;
    const loanLimit = collateralValue * 0.5; // 50% LTV
    
    const activeLoans = await Loan.find({ 
      userId: req.user._id,
      status: 'active'
    });

    const totalBorrowed = activeLoans.reduce((sum, loan) => sum + loan.remainingAmount, 0);
    const available = Math.max(0, loanLimit - totalBorrowed);

    res.json({
      loanLimit,
      totalBorrowed,
      available,
      ltvRatio: 0.5,
      collateralValue,
      btcPrice: btcPrice.usd
    });
  } catch (error) {
    logger.error('Get loan limit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/loans', authenticate, [
  body('amount').isFloat({ min: 100 }),
  body('duration').isInt({ min: 7, max: 365 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, duration } = req.body;
    const user = await User.findById(req.user._id);

    // Check loan eligibility
    const btcPrice = await getBitcoinPrice();
    const collateralValue = user.balance.btc * btcPrice.usd;
    const loanLimit = collateralValue * 0.5;

    const activeLoans = await Loan.find({ 
      userId: req.user._id,
      status: 'active'
    });

    const totalBorrowed = activeLoans.reduce((sum, loan) => sum + loan.remainingAmount, 0);
    const available = loanLimit - totalBorrowed;

    if (amount > available) {
      return res.status(400).json({ 
        error: `Loan amount exceeds available limit. Maximum: $${available}` 
      });
    }

    // Calculate collateral required
    const collateralRequired = (amount / 0.5) / btcPrice.usd; // 50% LTV
    
    if (user.balance.btc < collateralRequired) {
      return res.status(400).json({ 
        error: `Insufficient BTC collateral. Required: ${collateralRequired} BTC` 
      });
    }

    // Lock collateral
    user.balance.btc -= collateralRequired;
    user.balance.pendingBtc += collateralRequired;
    await user.save();

    // Create loan
    const interestRate = 0.12; // 12% APR
    const totalRepayment = amount * (1 + (interestRate * duration / 365));
    
    const loan = new Loan({
      userId: user._id,
      amount,
      currency: 'USD',
      collateralAmount: collateralRequired,
      collateralCurrency: 'BTC',
      interestRate,
      duration,
      status: 'active',
      dueDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000),
      remainingAmount: totalRepayment
    });

    await loan.save();

    // Credit loan amount
    user.balance.usd += amount;
    await user.save();

    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'loan',
      amount,
      currency: 'USD',
      status: 'completed',
      description: `Loan disbursement - ${duration} days at ${interestRate * 100}% APR`,
      metadata: { 
        loanId: loan._id,
        collateralAmount: collateralRequired,
        totalRepayment 
      }
    });

    await transaction.save();

    res.json({
      message: 'Loan approved and disbursed',
      loanId: loan._id,
      amount,
      totalRepayment,
      dueDate: loan.dueDate,
      collateralLocked: collateralRequired,
      remainingBalance: user.balance.usd
    });
  } catch (error) {
    logger.error('Create loan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/loans/repay', authenticate, [
  body('loanId').isMongoId(),
  body('amount').isFloat({ min: 1 })
], async (req, res) => {
  try {
    const { loanId, amount } = req.body;
    const user = await User.findById(req.user._id);

    // Find loan
    const loan = await Loan.findOne({
      _id: loanId,
      userId: req.user._id,
      status: 'active'
    });

    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }

    if (user.balance.usd < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Process repayment
    user.balance.usd -= amount;
    loan.repaidAmount += amount;
    loan.remainingAmount -= amount;

    // Check if loan is fully repaid
    if (loan.remainingAmount <= 0) {
      loan.status = 'repaid';
      
      // Release collateral
      user.balance.pendingBtc -= loan.collateralAmount;
      user.balance.btc += loan.collateralAmount;
    }

    await Promise.all([user.save(), loan.save()]);

    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'repayment',
      amount: -amount,
      currency: 'USD',
      status: 'completed',
      description: `Loan repayment for loan ${loanId.slice(-8)}`,
      metadata: { loanId, remainingAmount: loan.remainingAmount }
    });

    await transaction.save();

    res.json({
      message: 'Repayment successful',
      repaid: amount,
      remaining: loan.remainingAmount,
      status: loan.status,
      collateralReleased: loan.status === 'repaid' ? loan.collateralAmount : 0
    });
  } catch (error) {
    logger.error('Repay loan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// News Routes
app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const news = await News.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await News.countDocuments();

    // Increment views for featured news
    const featuredIds = news.filter(n => n.isFeatured).map(n => n._id);
    if (featuredIds.length > 0) {
      await News.updateMany(
        { _id: { $in: featuredIds } },
        { $inc: { views: 1 } }
      );
    }

    res.json({
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Newsletter Subscription
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const { email } = req.body;

    // Store in Redis
    const subscribed = await redis.sadd('newsletter_subscribers', email);
    
    if (subscribed === 1) {
      await sendEmail(
        email,
        'Welcome to Hashvex Newsletter',
        `
          <h2>Welcome to Hashvex Technologies!</h2>
          <p>Thank you for subscribing to our newsletter.</p>
          <p>You'll receive updates about:</p>
          <ul>
            <li>New miner releases</li>
            <li>Market insights</li>
            <li>Platform updates</li>
            <li>Special offers</li>
          </ul>
          <p>Stay tuned for valuable content!</p>
        `
      );

      res.json({ message: 'Subscribed successfully' });
    } else {
      res.json({ message: 'Already subscribed' });
    }
  } catch (error) {
    logger.error('Newsletter subscription error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Referral Routes
app.get('/api/referrals/validate/:code', async (req, res) => {
  try {
    const { code } = req.params;

    const user = await User.findOne({ referralCode: code });
    if (!user) {
      return res.status(404).json({ valid: false, error: 'Invalid referral code' });
    }

    res.json({ 
      valid: true, 
      referrer: {
        name: `${user.firstName} ${user.lastName}`,
        code
      }
    });
  } catch (error) {
    logger.error('Validate referral error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Announcements
app.get('/api/announcements', authenticate, async (req, res) => {
  try {
    const announcements = await Announcement.find({
      isActive: true,
      $or: [
        { endDate: { $exists: false } },
        { endDate: { $gt: new Date() } }
      ]
    })
    .sort({ priority: -1, createdAt: -1 })
    .limit(10)
    .lean();

    res.json({ announcements });
  } catch (error) {
    logger.error('Get announcements error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Bitcoin Price Endpoint
app.get('/api/bitcoin/price', async (req, res) => {
  try {
    const priceData = await getBitcoinPrice();
    res.json(priceData);
  } catch (error) {
    logger.error('Get Bitcoin price error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WebSocket for real-time updates
io.on('connection', (socket) => {
  logger.info('New WebSocket connection:', socket.id);

  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        socket.userId = user._id;
        socket.join(`user:${user._id}`);
        socket.emit('authenticated', { userId: user._id });
        
        logger.info(`User ${user._id} connected via WebSocket`);
      }
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });

  socket.on('subscribe:bitcoin', () => {
    socket.join('bitcoin_price');
  });

  socket.on('disconnect', () => {
    logger.info('WebSocket disconnected:', socket.id);
  });
});

// Broadcast Bitcoin price updates
setInterval(async () => {
  try {
    const priceData = await getBitcoinPrice();
    io.to('bitcoin_price').emit('bitcoin:price', priceData);
  } catch (error) {
    logger.error('WebSocket price update error:', error);
  }
}, 30000); // Every 30 seconds

// Cron jobs for maintenance tasks
cron.schedule('0 0 * * *', async () => {
  logger.info('Running daily maintenance tasks');
  
  try {
    // Update miner profitability based on current Bitcoin price
    const btcPrice = await getBitcoinPrice();
    const miners = await Miner.find();
    
    for (const miner of miners) {
      const dailyBtc = calculateMinerProfitability(miner.hashRate);
      const dailyUsd = dailyBtc * btcPrice.usd;
      
      await Miner.findByIdAndUpdate(miner._id, {
        $set: {
          'profitability.dailyBtc': dailyBtc,
          'profitability.dailyUsd': dailyUsd
        }
      });
    }
    
    // Check for expired rentals
    const expiredRentals = await UserMiner.find({
      purchaseType: 'rent',
      expiryDate: { $lte: new Date() },
      status: 'active'
    });
    
    for (const rental of expiredRentals) {
      rental.status = 'expired';
      await rental.save();
      
      // Notify user
      const user = await User.findById(rental.userId);
      if (user) {
        await sendEmail(
          user.email,
          'Miner Rental Expired',
          `
            <h2>Miner Rental Expired</h2>
            <p>Your rental for miner ${rental.minerId} has expired.</p>
            <p>Please renew your rental to continue mining.</p>
          `
        );
      }
    }
    
    logger.info('Daily maintenance completed');
  } catch (error) {
    logger.error('Daily maintenance error:', error);
  }
});

// Calculate miner profitability (simplified)
function calculateMinerProfitability(hashRate) {
  // Simplified calculation - in production, use actual pool data
  const networkDifficulty = 80000000000000; // Example
  const blockReward = 6.25;
  const secondsPerDay = 86400;
  
  const dailyBtc = (hashRate / networkDifficulty) * blockReward * secondsPerDay;
  return dailyBtc;
}

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Validation Error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.code === 11000) {
    return res.status(409).json({ 
      error: 'Duplicate entry',
      field: Object.keys(err.keyPattern)[0]
    });
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
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  
  // Schedule initial Bitcoin price fetch
  getBitcoinPrice().then(price => {
    logger.info(`Initial Bitcoin price: $${price.usd}`);
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  
  try {
    await mongoose.connection.close();
    await redis.quit();
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
  } catch (error) {
    logger.error('Graceful shutdown error:', error);
    process.exit(1);
  }
});

module.exports = { app, server };
