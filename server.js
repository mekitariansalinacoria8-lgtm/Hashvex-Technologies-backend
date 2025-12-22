require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Redis = require('ioredis');
const { body, validationResult, param } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const { BlobServiceClient } = require('@azure/storage-blob');

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

// ============================ MIDDLEWARE ============================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com", "https://*.dropbox.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://hashvex-technologies-backend.onrender.com", "https://api.coingecko.com", "https://api.coincap.io"],
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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
  handler: (req, res) => {
    res.status(429).json({ success: false, message: 'Too many requests, please try again later' });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  skipSuccessfulRequests: false
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

// File upload
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|pdf/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    if (mimetype && extname) return cb(null, true);
    cb(new Error('Only image (JPEG, PNG) and PDF files are allowed'));
  }
});

// ============================ DATABASE CONNECTION ============================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:Gd6RQK8mVRn5BuBi@cluster0.fvvirw2.mongodb.net/hashvex?retryWrites=true&w=majority&wtimeoutMS=5000';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  maxPoolSize: 100,
  minPoolSize: 10
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => Math.min(times * 100, 3000),
  maxRetriesPerRequest: 3,
  connectTimeout: 10000
});

redis.on('error', (err) => console.error('❌ Redis error:', err.message));
redis.on('connect', () => console.log('✅ Redis connected'));

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  },
  pool: true,
  maxConnections: 10
});

// Google OAuth
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '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'
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const REFRESH_SECRET = process.env.REFRESH_SECRET || crypto.randomBytes(64).toString('hex');

// API URLs
const COINGECKO_API = 'https://api.coingecko.com/api/v3';
const COINCAP_API = 'https://api.coincap.io/v2';

// ============================ SCHEMAS ============================

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: function() { return !this.googleId; }, minlength: 8, select: false },
  googleId: { type: String, index: true, sparse: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: String,
  city: String,
  country: String,
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  dateOfBirth: Date,
  role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: String,
  referralCode: { type: String, unique: true, sparse: true },
  referredBy: String,
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'not_submitted'], default: 'not_submitted' },
  kycData: {
    documentType: String,
    documentNumber: String,
    documentFront: String,
    documentBack: String,
    selfie: String,
    submittedAt: Date,
    verifiedAt: Date,
    verifiedBy: mongoose.Schema.Types.ObjectId
  },
  walletAddress: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  penalties: [{
    amount: Number,
    reason: String,
    date: Date,
    resolved: { type: Boolean, default: false },
    resolvedAt: Date
  }]
}, { timestamps: true });

// Balance Schema
const balanceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  btc: { type: Number, default: 0, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  usd: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  pendingBtc: { type: Number, default: 0, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  pendingUsd: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  totalDeposited: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  totalWithdrawn: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  miningBalance: { type: Number, default: 0, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  loanBalance: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  penaltyBalance: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  lastPenaltyDate: Date,
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Miner Schema
const minerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  model: { type: String, required: true },
  hashRate: { type: Number, required: true },
  powerConsumption: Number,
  efficiency: Number,
  price: { type: Number, required: true, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  dailyProfit: { type: Number, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  monthlyProfit: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  roiDays: Number,
  type: { type: String, enum: ['rent', 'sale'], required: true },
  rentalPeriod: { type: Number, default: 30 },
  quantity: { type: Number, default: 1 },
  available: { type: Boolean, default: true },
  image: String,
  description: String,
  specifications: mongoose.Schema.Types.Mixed
}, { timestamps: true });

// Owned Miner Schema
const ownedMinerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
  purchaseType: { type: String, enum: ['rent', 'purchase'], required: true },
  purchaseDate: { type: Date, default: Date.now },
  expiryDate: Date,
  status: { type: String, enum: ['active', 'expired', 'suspended'], default: 'active' },
  dailyEarnings: { type: Number, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  totalEarned: { type: Number, default: 0, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  miningAddress: String,
  nextPayout: Date,
  contractDetails: mongoose.Schema.Types.Mixed,
  lastPayoutDate: Date
}, { timestamps: true });

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'mining_payout', 'loan', 'repayment', 'purchase', 'rental', 'penalty', 'penalty_resolution'], required: true },
  amount: { type: Number, required: true, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  txHash: { type: String, index: true, sparse: true },
  walletAddress: String,
  bankDetails: mongoose.Schema.Types.Mixed,
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date
}, { timestamps: true });

// Deposit Schema
const depositSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  method: { type: String, enum: ['bitcoin', 'bank_transfer', 'credit_card', 'crypto'], required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'completed', 'failed'], default: 'pending' },
  btcAddress: { type: String, index: true, sparse: true },
  confirmations: { type: Number, default: 0 },
  requiredConfirmations: { type: Number, default: 3 },
  cardDetails: {
    cardNumber: String,
    cardHolder: String,
    expiryDate: String,
    cvv: String,
    billingAddress: String
  },
  bankDetails: mongoose.Schema.Types.Mixed,
  transactionId: { type: String, unique: true, sparse: true },
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  fillsPenaltyGap: { type: Boolean, default: false },
  penaltyAmountCovered: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) }
}, { timestamps: true });

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  method: { type: String, enum: ['bitcoin', 'bank_transfer'], required: true },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'rejected', 'cancelled'], default: 'pending' },
  btcAddress: String,
  bankDetails: {
    accountName: String,
    accountNumber: String,
    bankName: String,
    routingNumber: String,
    swiftCode: String,
    iban: String
  },
  fee: { type: Number, default: 0, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  netAmount: { type: Number, get: v => parseFloat(v.toFixed(8)), set: v => parseFloat(v.toFixed(8)) },
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date
}, { timestamps: true });

// Loan Schema
const loanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  currency: { type: String, enum: ['BTC', 'USD'], default: 'USD' },
  term: { type: Number, required: true },
  interestRate: { type: Number, required: true, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  monthlyPayment: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  totalRepayment: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  purpose: String,
  collateral: { type: mongoose.Schema.Types.ObjectId, ref: 'OwnedMiner' },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'active', 'completed', 'defaulted'], default: 'pending' },
  approvedAmount: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  approvedBy: mongoose.Schema.Types.ObjectId,
  approvedAt: Date,
  disbursedAt: Date,
  nextPaymentDate: Date,
  paymentsMade: { type: Number, default: 0 },
  remainingBalance: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  lateFees: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  adminNotes: String
}, { timestamps: true });

// Cart Schema
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  items: [{
    minerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner' },
    quantity: { type: Number, default: 1, min: 1 },
    price: { type: Number, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
    type: String,
    rentalPeriod: Number
  }],
  total: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  type: { type: String, enum: ['verification', 'reset', 'two_factor'], required: true },
  expiresAt: { type: Date, required: true, index: { expires: '5m' } },
  attempts: { type: Number, default: 0 },
  verified: { type: Boolean, default: false }
}, { timestamps: true });

// Card Schema
const cardSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  cardNumber: { type: String, required: true },
  cardHolder: { type: String, required: true },
  expiryDate: { type: String, required: true },
  cvv: { type: String, required: true },
  billingAddress: { type: String, required: true },
  type: { type: String, enum: ['visa', 'mastercard', 'amex', 'discover'] },
  lastFour: String,
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

// Penalty Schema
const penaltySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  reason: { type: String, required: true, enum: ['late_loan_payment', 'service_fee', 'administrative', 'policy_violation', 'other'] },
  description: String,
  status: { type: String, enum: ['active', 'resolved', 'partially_resolved'], default: 'active' },
  resolvedAmount: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)), set: v => parseFloat(v.toFixed(2)) },
  resolvedAt: Date,
  resolvedBy: mongoose.Schema.Types.ObjectId,
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

// News Schema
const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, enum: ['announcement', 'update', 'maintenance', 'feature'], default: 'announcement' },
  image: String,
  author: String,
  isPublished: { type: Boolean, default: true },
  publishedAt: Date,
  views: { type: Number, default: 0 }
}, { timestamps: true });

// Announcement Schema
const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  priority: { type: Number, default: 1 },
  isActive: { type: Boolean, default: true },
  startDate: Date,
  endDate: Date,
  targetUsers: [{ type: String }]
}, { timestamps: true });

// API Key Schema
const apiKeySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  key: { type: String, required: true, unique: true },
  secret: { type: String, required: true },
  permissions: [{ type: String }],
  isActive: { type: Boolean, default: true },
  lastUsed: Date,
  expiresAt: Date
}, { timestamps: true });

// Device Schema
const deviceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  deviceId: { type: String, required: true },
  deviceName: String,
  browser: String,
  os: String,
  ipAddress: String,
  location: String,
  lastActive: { type: Date, default: Date.now },
  isTrusted: { type: Boolean, default: false }
}, { timestamps: true });

// Notification Preferences Schema
const notificationPrefSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  email: {
    deposits: { type: Boolean, default: true },
    withdrawals: { type: Boolean, default: true },
    miningPayouts: { type: Boolean, default: true },
    securityAlerts: { type: Boolean, default: true },
    newsletter: { type: Boolean, default: false }
  },
  push: {
    deposits: { type: Boolean, default: true },
    withdrawals: { type: Boolean, default: true },
    miningPayouts: { type: Boolean, default: true },
    securityAlerts: { type: Boolean, default: true }
  },
  sms: {
    securityAlerts: { type: Boolean, default: false }
  }
}, { timestamps: true });

// Activity Log Schema
const activityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  ipAddress: String,
  userAgent: String,
  details: mongoose.Schema.Types.Mixed,
  status: { type: String, enum: ['success', 'failed'], default: 'success' }
}, { timestamps: true });

// Create models
const User = mongoose.model('User', userSchema);
const Balance = mongoose.model('Balance', balanceSchema);
const Miner = mongoose.model('Miner', minerSchema);
const OwnedMiner = mongoose.model('OwnedMiner', ownedMinerSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Loan = mongoose.model('Loan', loanSchema);
const Cart = mongoose.model('Cart', cartSchema);
const OTP = mongoose.model('OTP', otpSchema);
const Card = mongoose.model('Card', cardSchema);
const Penalty = mongoose.model('Penalty', penaltySchema);
const News = mongoose.model('News', newsSchema);
const Announcement = mongoose.model('Announcement', announcementSchema);
const ApiKey = mongoose.model('ApiKey', apiKeySchema);
const Device = mongoose.model('Device', deviceSchema);
const NotificationPref = mongoose.model('NotificationPref', notificationPrefSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// ============================ UTILITY FUNCTIONS ============================

// Generate JWT Token
const generateToken = (userId, role = 'user') => {
  return jwt.sign(
    { userId, role, iat: Math.floor(Date.now() / 1000) },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
  );
};

// Verify JWT Token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// Authenticate Middleware
const authenticate = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    }
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
    
    const user = await User.findById(decoded.userId).select('-password -twoFactorSecret');
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, message: 'User not found or inactive.' });
    }
    
    req.user = user;
    req.userId = user._id;
    req.userRole = user.role;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ success: false, message: 'Authentication failed.' });
  }
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required.' });
  }
  next();
};

// Get Bitcoin Price
const getBitcoinPrice = async () => {
  try {
    const cacheKey = 'bitcoin_price';
    const cachedPrice = await redis.get(cacheKey);
    
    if (cachedPrice) {
      return JSON.parse(cachedPrice);
    }
    
    try {
      const response = await axios.get(
        `${COINGECKO_API}/simple/price?ids=bitcoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true`,
        { timeout: 5000 }
      );
      
      const priceData = {
        price: response.data.bitcoin.usd,
        marketCap: response.data.bitcoin.usd_market_cap,
        volume: response.data.bitcoin.usd_24h_vol,
        change24h: response.data.bitcoin.usd_24h_change,
        source: 'coingecko'
      };
      
      await redis.setex(cacheKey, 30, JSON.stringify(priceData));
      return priceData;
    } catch (coingeckoError) {
      // Fallback to CoinCap
      const response = await axios.get(`${COINCAP_API}/assets/bitcoin`, { timeout: 5000 });
      const priceData = {
        price: parseFloat(response.data.data.priceUsd),
        marketCap: parseFloat(response.data.data.marketCapUsd),
        volume: parseFloat(response.data.data.volumeUsd24Hr),
        change24h: parseFloat(response.data.data.changePercent24Hr),
        source: 'coincap'
      };
      
      await redis.setex(cacheKey, 30, JSON.stringify(priceData));
      return priceData;
    }
  } catch (error) {
    console.error('Error fetching Bitcoin price:', error);
    return {
      price: 45000,
      marketCap: 880000000000,
      volume: 30000000000,
      change24h: 1.5,
      source: 'fallback'
    };
  }
};

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send Email
const sendEmail = async (to, subject, html) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@hashvex.com',
      to,
      subject,
      html
    };
    
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('Failed to send email:', error);
    return false;
  }
};

// ============================ MISSING ENDPOINTS ============================

// 1. Withdrawal Endpoints (From WITHDRAWAL page)
app.post('/api/withdrawals/btc', authenticate, [
  body('amount').isFloat({ min: 0.0001 }),
  body('address').isString().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { amount, address } = req.body;
    
    // Check KYC status
    const user = await User.findById(req.userId);
    if (user.kycStatus !== 'verified') {
      return res.status(403).json({ 
        success: false, 
        message: 'KYC verification required for withdrawals' 
      });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.btc < amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient BTC balance' 
      });
    }
    
    // Check penalty balance
    if (balance.penaltyBalance > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please resolve your penalties before withdrawing' 
      });
    }
    
    const withdrawalFee = amount * 0.001; // 0.1% fee
    const netAmount = amount - withdrawalFee;
    
    // Create withdrawal
    const withdrawal = new Withdrawal({
      userId: req.userId,
      amount,
      currency: 'BTC',
      method: 'bitcoin',
      status: 'pending',
      btcAddress: address,
      fee: withdrawalFee,
      netAmount
    });
    
    await withdrawal.save();
    
    // Update balance
    balance.btc -= amount;
    balance.pendingBtc += amount;
    await balance.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.userId,
      type: 'withdrawal',
      amount,
      currency: 'BTC',
      status: 'pending',
      description: 'BTC withdrawal request',
      metadata: { withdrawalId: withdrawal._id, address }
    });
    
    await transaction.save();
    
    res.json({ 
      success: true, 
      message: 'Withdrawal request submitted',
      withdrawalId: withdrawal._id,
      netAmount,
      fee: withdrawalFee
    });
  } catch (error) {
    console.error('BTC withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Failed to process withdrawal' });
  }
});

app.post('/api/withdrawals/bank', authenticate, [
  body('amount').isFloat({ min: 10 }),
  body('accountName').notEmpty(),
  body('accountNumber').notEmpty(),
  body('bankName').notEmpty(),
  body('routingNumber').optional(),
  body('swiftCode').optional(),
  body('iban').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { amount, accountName, accountNumber, bankName, routingNumber, swiftCode, iban } = req.body;
    
    // Check KYC status
    const user = await User.findById(req.userId);
    if (user.kycStatus !== 'verified') {
      return res.status(403).json({ 
        success: false, 
        message: 'KYC verification required for withdrawals' 
      });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient USD balance' 
      });
    }
    
    // Check penalty balance
    if (balance.penaltyBalance > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please resolve your penalties before withdrawing' 
      });
    }
    
    const withdrawalFee = amount * 0.02; // 2% fee
    const netAmount = amount - withdrawalFee;
    
    // Create withdrawal
    const withdrawal = new Withdrawal({
      userId: req.userId,
      amount,
      currency: 'USD',
      method: 'bank_transfer',
      status: 'pending',
      bankDetails: {
        accountName,
        accountNumber,
        bankName,
        routingNumber,
        swiftCode,
        iban
      },
      fee: withdrawalFee,
      netAmount
    });
    
    await withdrawal.save();
    
    // Update balance
    balance.usd -= amount;
    balance.pendingUsd += amount;
    await balance.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.userId,
      type: 'withdrawal',
      amount,
      currency: 'USD',
      status: 'pending',
      description: 'Bank withdrawal request',
      metadata: { withdrawalId: withdrawal._id, bankName }
    });
    
    await transaction.save();
    
    res.json({ 
      success: true, 
      message: 'Bank withdrawal request submitted',
      withdrawalId: withdrawal._id,
      netAmount,
      fee: withdrawalFee,
      estimatedDelivery: '3-5 business days'
    });
  } catch (error) {
    console.error('Bank withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Failed to process withdrawal' });
  }
});

app.get('/api/withdrawals/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const withdrawals = await Withdrawal.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Withdrawal.countDocuments({ userId: req.userId });
    
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
    console.error('Get withdrawal history error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch withdrawal history' });
  }
});

// 2. KYC Endpoints (From multiple pages)
app.get('/api/kyc/status', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('kycStatus kycData');
    
    res.json({
      success: true,
      status: user.kycStatus,
      data: user.kycData,
      requirements: {
        identity: !user.kycData?.documentFront,
        address: !user.kycData?.documentBack,
        selfie: !user.kycData?.selfie
      }
    });
  } catch (error) {
    console.error('Get KYC status error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch KYC status' });
  }
});

app.post('/api/kyc/identity', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    const { documentType, documentNumber } = req.body;
    
    // In production, upload to cloud storage
    const documentUrl = `https://storage.hashvex.com/kyc/${req.userId}/${Date.now()}_${req.file.originalname}`;
    
    await User.findByIdAndUpdate(req.userId, {
      $set: {
        'kycData.documentType': documentType,
        'kycData.documentNumber': documentNumber,
        'kycData.documentFront': documentUrl,
        'kycData.submittedAt': new Date()
      },
      kycStatus: 'pending'
    });
    
    res.json({
      success: true,
      message: 'Identity document uploaded successfully',
      documentUrl
    });
  } catch (error) {
    console.error('KYC identity upload error:', error);
    res.status(500).json({ success: false, message: 'Failed to upload identity document' });
  }
});

app.post('/api/kyc/address', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    const documentUrl = `https://storage.hashvex.com/kyc/${req.userId}/${Date.now()}_address_${req.file.originalname}`;
    
    await User.findByIdAndUpdate(req.userId, {
      $set: {
        'kycData.documentBack': documentUrl
      }
    });
    
    res.json({
      success: true,
      message: 'Address document uploaded successfully',
      documentUrl
    });
  } catch (error) {
    console.error('KYC address upload error:', error);
    res.status(500).json({ success: false, message: 'Failed to upload address document' });
  }
});

app.post('/api/kyc/facial', authenticate, upload.single('selfie'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No selfie uploaded' });
    }
    
    const selfieUrl = `https://storage.hashvex.com/kyc/${req.userId}/${Date.now()}_selfie_${req.file.originalname}`;
    
    await User.findByIdAndUpdate(req.userId, {
      $set: {
        'kycData.selfie': selfieUrl
      }
    });
    
    res.json({
      success: true,
      message: 'Facial verification completed',
      selfieUrl
    });
  } catch (error) {
    console.error('KYC facial verification error:', error);
    res.status(500).json({ success: false, message: 'Failed to process facial verification' });
  }
});

app.post('/api/kyc/submit', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user.kycData?.documentFront || !user.kycData?.documentBack || !user.kycData?.selfie) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please complete all KYC steps before submission' 
      });
    }
    
    user.kycStatus = 'pending';
    await user.save();
    
    res.json({
      success: true,
      message: 'KYC submitted for review. Please allow 24-48 hours for verification.'
    });
  } catch (error) {
    console.error('KYC submit error:', error);
    res.status(500).json({ success: false, message: 'Failed to submit KYC' });
  }
});

// 3. Deposit Endpoints (From DEPOSIT page)
app.get('/api/deposits/btc-address', authenticate, async (req, res) => {
  try {
    // Generate unique BTC address for user
    const user = await User.findById(req.userId);
    if (!user.walletAddress) {
      // In production, generate via blockchain API
      const walletAddress = `1${crypto.randomBytes(20).toString('hex').slice(0, 33)}`;
      user.walletAddress = walletAddress;
      await user.save();
    }
    
    // Generate QR code
    const qrCodeData = await QRCode.toDataURL(user.walletAddress);
    
    res.json({
      success: true,
      address: user.walletAddress,
      qrCode: qrCodeData,
      instructions: 'Send only Bitcoin (BTC) to this address. Do not send other cryptocurrencies.'
    });
  } catch (error) {
    console.error('Get BTC address error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate BTC address' });
  }
});

app.post('/api/deposits/btc-status', authenticate, async (req, res) => {
  try {
    const { address } = req.body;
    
    const deposit = await Deposit.findOne({ 
      userId: req.userId, 
      btcAddress: address,
      status: { $in: ['pending', 'confirmed'] }
    });
    
    if (!deposit) {
      return res.json({
        success: true,
        status: 'no_deposit',
        message: 'No pending deposit found for this address'
      });
    }
    
    const btcPrice = await getBitcoinPrice();
    const usdValue = deposit.amount * btcPrice.price;
    
    res.json({
      success: true,
      status: deposit.status,
      amount: deposit.amount,
      confirmations: deposit.confirmations,
      requiredConfirmations: deposit.requiredConfirmations,
      usdValue,
      transactionId: deposit.transactionId,
      createdAt: deposit.createdAt
    });
  } catch (error) {
    console.error('BTC status check error:', error);
    res.status(500).json({ success: false, message: 'Failed to check deposit status' });
  }
});

app.get('/api/deposits/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const deposits = await Deposit.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Deposit.countDocuments({ userId: req.userId });
    
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
    console.error('Get deposit history error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch deposit history' });
  }
});

// 4. Cart Endpoints (From INDEX.HTML)
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.userId })
      .populate('items.minerId');
    
    if (!cart) {
      const newCart = new Cart({
        userId: req.userId,
        items: [],
        total: 0
      });
      await newCart.save();
      
      return res.json({
        success: true,
        cart: newCart,
        itemCount: 0,
        total: 0
      });
    }
    
    res.json({
      success: true,
      cart,
      itemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
      total: cart.total
    });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch cart' });
  }
});

app.post('/api/cart/add', authenticate, [
  body('minerId').isMongoId(),
  body('quantity').isInt({ min: 1 }),
  body('type').isIn(['rent', 'sale']),
  body('rentalPeriod').optional().isInt({ min: 30, max: 365 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { minerId, quantity, type, rentalPeriod } = req.body;
    
    // Get miner details
    const miner = await Miner.findById(minerId);
    if (!miner || !miner.available) {
      return res.status(404).json({ success: false, message: 'Miner not available' });
    }
    
    if (miner.type !== type) {
      return res.status(400).json({ success: false, message: 'Invalid miner type' });
    }
    
    // Calculate price
    let price = miner.price;
    if (type === 'rent' && rentalPeriod) {
      price = miner.price * (rentalPeriod / 30); // Monthly price × months
    }
    
    // Find or create cart
    let cart = await Cart.findOne({ userId: req.userId });
    if (!cart) {
      cart = new Cart({
        userId: req.userId,
        items: [],
        total: 0
      });
    }
    
    // Check if item already in cart
    const existingItemIndex = cart.items.findIndex(
      item => item.minerId.toString() === minerId && item.type === type
    );
    
    if (existingItemIndex > -1) {
      cart.items[existingItemIndex].quantity += quantity;
      cart.items[existingItemIndex].price = price;
    } else {
      cart.items.push({
        minerId,
        quantity,
        price,
        type,
        rentalPeriod: type === 'rent' ? (rentalPeriod || 30) : undefined
      });
    }
    
    // Recalculate total
    cart.total = cart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    cart.updatedAt = new Date();
    
    await cart.save();
    
    res.json({
      success: true,
      message: 'Item added to cart',
      cart,
      itemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
      total: cart.total
    });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to add item to cart' });
  }
});

app.post('/api/cart/checkout', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.userId }).populate('items.minerId');
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ success: false, message: 'Cart is empty' });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < cart.total) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient balance',
        required: cart.total,
        available: balance?.usd || 0
      });
    }
    
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Process each item
      for (const item of cart.items) {
        const miner = item.minerId;
        
        if (miner.quantity < item.quantity) {
          throw new Error(`Insufficient stock for ${miner.name}`);
        }
        
        // Update miner quantity
        miner.quantity -= item.quantity;
        await miner.save({ session });
        
        // Create owned miner record
        const ownedMiner = new OwnedMiner({
          userId: req.userId,
          minerId: miner._id,
          purchaseType: item.type,
          purchaseDate: new Date(),
          expiryDate: item.type === 'rent' ? 
            new Date(Date.now() + (item.rentalPeriod || 30) * 24 * 60 * 60 * 1000) : 
            null,
          status: 'active',
          dailyEarnings: miner.dailyProfit,
          contractDetails: {
            price: item.price,
            quantity: item.quantity,
            rentalPeriod: item.rentalPeriod
          }
        });
        
        await ownedMiner.save({ session });
        
        // Create transaction
        const transaction = new Transaction({
          userId: req.userId,
          type: item.type === 'rent' ? 'rental' : 'purchase',
          amount: item.price * item.quantity,
          currency: 'USD',
          status: 'completed',
          description: `${item.type === 'rent' ? 'Rental' : 'Purchase'} of ${miner.name}`,
          metadata: {
            minerId: miner._id,
            quantity: item.quantity,
            ownedMinerId: ownedMiner._id
          }
        });
        
        await transaction.save({ session });
      }
      
      // Update balance
      balance.usd -= cart.total;
      await balance.save({ session });
      
      // Clear cart
      cart.items = [];
      cart.total = 0;
      await cart.save({ session });
      
      await session.commitTransaction();
      
      res.json({
        success: true,
        message: 'Checkout completed successfully',
        purchasedItems: cart.items.length,
        total: cart.total
      });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    console.error('Checkout error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Checkout failed',
      error: error.message 
    });
  }
});

// 5. Miner Endpoints (From INDEX.HTML and DASHBOARD)
app.get('/api/miners/rent', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ 
      type: 'rent',
      available: true,
      quantity: { $gt: 0 }
    })
      .sort({ price: 1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Miner.countDocuments({ 
      type: 'rent',
      available: true,
      quantity: { $gt: 0 }
    });
    
    const btcPrice = await getBitcoinPrice();
    
    res.json({
      success: true,
      miners: miners.map(miner => ({
        ...miner.toObject(),
        btcPrice: btcPrice.price,
        dailyProfitUSD: miner.dailyProfit * btcPrice.price
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get rent miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch miners' });
  }
});

app.get('/api/miners/sale', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 6;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ 
      type: 'sale',
      available: true,
      quantity: { $gt: 0 }
    })
      .sort({ price: 1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Miner.countDocuments({ 
      type: 'sale',
      available: true,
      quantity: { $gt: 0 }
    });
    
    const btcPrice = await getBitcoinPrice();
    
    res.json({
      success: true,
      miners: miners.map(miner => ({
        ...miner.toObject(),
        btcPrice: btcPrice.price,
        monthlyProfitUSD: miner.monthlyProfit * btcPrice.price
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get sale miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch miners' });
  }
});

app.get('/api/miners/owned', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const ownedMiners = await OwnedMiner.find({ userId: req.userId })
      .populate('minerId')
      .sort({ purchaseDate: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await OwnedMiner.countDocuments({ userId: req.userId });
    
    const btcPrice = await getBitcoinPrice();
    
    // Calculate totals
    const totalEarned = ownedMiners.reduce((sum, miner) => sum + (miner.totalEarned || 0), 0);
    const dailyEarnings = ownedMiners.reduce((sum, miner) => sum + (miner.dailyEarnings || 0), 0);
    
    res.json({
      success: true,
      miners: ownedMiners,
      totals: {
        count: total,
        totalEarned,
        dailyEarnings,
        dailyEarningsUSD: dailyEarnings * btcPrice.price,
        active: ownedMiners.filter(m => m.status === 'active').length
      },
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get owned miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch owned miners' });
  }
});

app.get('/api/miners/:id', async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    const btcPrice = await getBitcoinPrice();
    
    res.json({
      success: true,
      miner: {
        ...miner.toObject(),
        btcPrice: btcPrice.price,
        dailyProfitUSD: miner.dailyProfit * btcPrice.price,
        monthlyProfitUSD: miner.monthlyProfit * btcPrice.price
      }
    });
  } catch (error) {
    console.error('Get miner details error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch miner details' });
  }
});

app.post('/api/miners/:id/extend', authenticate, [
  body('months').isInt({ min: 1, max: 12 })
], async (req, res) => {
  try {
    const { months } = req.body;
    
    const ownedMiner = await OwnedMiner.findOne({
      _id: req.params.id,
      userId: req.userId,
      purchaseType: 'rent'
    }).populate('minerId');
    
    if (!ownedMiner) {
      return res.status(404).json({ success: false, message: 'Rental miner not found' });
    }
    
    const extensionCost = ownedMiner.minerId.price * months;
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < extensionCost) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient balance for extension',
        required: extensionCost,
        available: balance?.usd || 0
      });
    }
    
    // Extend expiry date
    const currentExpiry = ownedMiner.expiryDate || new Date();
    ownedMiner.expiryDate = new Date(currentExpiry.getTime() + (months * 30 * 24 * 60 * 60 * 1000));
    await ownedMiner.save();
    
    // Update balance
    balance.usd -= extensionCost;
    await balance.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.userId,
      type: 'rental',
      amount: extensionCost,
      currency: 'USD',
      status: 'completed',
      description: `Rental extension for ${months} month(s)`,
      metadata: {
        ownedMinerId: ownedMiner._id,
        monthsExtended: months,
        newExpiry: ownedMiner.expiryDate
      }
    });
    
    await transaction.save();
    
    res.json({
      success: true,
      message: `Rental extended by ${months} month(s)`,
      newExpiry: ownedMiner.expiryDate,
      cost: extensionCost
    });
  } catch (error) {
    console.error('Extend rental error:', error);
    res.status(500).json({ success: false, message: 'Failed to extend rental' });
  }
});

// 6. Transaction Endpoints (From DASHBOARD)
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Transaction.countDocuments({ userId: req.userId });
    
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
    console.error('Get transactions error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

// 7. Loan Endpoints (From DASHBOARD)
app.get('/api/loans/limit', authenticate, async (req, res) => {
  try {
    const balance = await Balance.findOne({ userId: req.userId });
    const ownedMiners = await OwnedMiner.find({ 
      userId: req.userId,
      status: 'active',
      purchaseType: 'purchase'
    }).populate('minerId');
    
    const totalMinerValue = ownedMiners.reduce((sum, miner) => {
      return sum + (miner.minerId?.price || 0);
    }, 0);
    
    const loanLimit = totalMinerValue * 0.5; // 50% of miner value
    
    res.json({
      success: true,
      loanLimit,
      availableBalance: balance?.usd || 0,
      collateralValue: totalMinerValue,
      eligible: loanLimit > 1000 // Minimum $1000 loan
    });
  } catch (error) {
    console.error('Get loan limit error:', error);
    res.status(500).json({ success: false, message: 'Failed to calculate loan limit' });
  }
});

app.post('/api/loans', authenticate, [
  body('amount').isFloat({ min: 1000 }),
  body('term').isInt({ min: 3, max: 36 }),
  body('purpose').optional().trim(),
  body('collateralId').optional().isMongoId()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { amount, term, purpose, collateralId } = req.body;
    
    // Check loan limit
    const limitResponse = await Loan.findOne({ 
      userId: req.userId,
      status: { $in: ['pending', 'active'] }
    });
    
    if (limitResponse) {
      return res.status(400).json({ 
        success: false, 
        message: 'You already have an active or pending loan' 
      });
    }
    
    // Calculate interest (10% annual)
    const interestRate = 10;
    const monthlyInterest = interestRate / 12 / 100;
    const monthlyPayment = (amount * monthlyInterest) / (1 - Math.pow(1 + monthlyInterest, -term));
    const totalRepayment = monthlyPayment * term;
    
    const loan = new Loan({
      userId: req.userId,
      amount,
      term,
      interestRate,
      monthlyPayment,
      totalRepayment,
      purpose,
      collateral: collateralId,
      status: 'pending',
      remainingBalance: totalRepayment
    });
    
    await loan.save();
    
    res.json({
      success: true,
      message: 'Loan application submitted',
      loanId: loan._id,
      terms: {
        amount,
        term,
        interestRate,
        monthlyPayment,
        totalRepayment
      }
    });
  } catch (error) {
    console.error('Apply for loan error:', error);
    res.status(500).json({ success: false, message: 'Failed to apply for loan' });
  }
});

app.post('/api/loans/repay', authenticate, [
  body('loanId').isMongoId(),
  body('amount').isFloat({ min: 1 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { loanId, amount } = req.body;
    
    const loan = await Loan.findOne({
      _id: loanId,
      userId: req.userId,
      status: 'active'
    });
    
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Active loan not found' });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < amount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient balance for repayment',
        required: amount,
        available: balance?.usd || 0
      });
    }
    
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update loan
      loan.paymentsMade += 1;
      loan.remainingBalance -= amount;
      
      if (loan.remainingBalance <= 0) {
        loan.status = 'completed';
        loan.remainingBalance = 0;
      }
      
      loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await loan.save({ session });
      
      // Update balance
      balance.usd -= amount;
      await balance.save({ session });
      
      // Create transaction
      const transaction = new Transaction({
        userId: req.userId,
        type: 'repayment',
        amount,
        currency: 'USD',
        status: 'completed',
        description: 'Loan repayment',
        metadata: {
          loanId: loan._id,
          paymentNumber: loan.paymentsMade
        }
      });
      
      await transaction.save({ session });
      
      await session.commitTransaction();
      
      res.json({
        success: true,
        message: 'Loan repayment successful',
        remainingBalance: loan.remainingBalance,
        paymentsMade: loan.paymentsMade,
        nextPaymentDate: loan.nextPaymentDate
      });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    console.error('Loan repayment error:', error);
    res.status(500).json({ success: false, message: 'Failed to process loan repayment' });
  }
});

// 8. News Endpoints (From INDEX.HTML)
app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const news = await News.find({ isPublished: true })
      .sort({ publishedAt: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
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
    console.error('Get news error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch news' });
  }
});

// 9. Referral Endpoints (From USER REGISTRATION)
app.get('/api/referrals/validate/:code', async (req, res) => {
  try {
    const { code } = req.params;
    
    const user = await User.findOne({ referralCode: code });
    
    if (!user) {
      return res.json({
        success: false,
        valid: false,
        message: 'Invalid referral code'
      });
    }
    
    res.json({
      success: true,
      valid: true,
      referrer: {
        name: `${user.firstName} ${user.lastName}`,
        joinedDate: user.createdAt
      }
    });
  } catch (error) {
    console.error('Validate referral error:', error);
    res.status(500).json({ success: false, message: 'Failed to validate referral code' });
  }
});

// 10. Newsletter Endpoints
app.post('/api/newsletter/subscribe', [
  body('email').isEmail().normalizeEmail(),
  body('name').optional().trim()
], async (req, res) => {
  try {
    const { email, name } = req.body;
    
    // In production, save to database or email service
    console.log(`Newsletter subscription: ${email} - ${name}`);
    
    res.json({
      success: true,
      message: 'Successfully subscribed to newsletter'
    });
  } catch (error) {
    console.error('Newsletter subscription error:', error);
    res.status(500).json({ success: false, message: 'Failed to subscribe' });
  }
});

// 11. Auth Verification (From multiple pages)
app.get('/api/auth/verify', authenticate, async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        role: req.user.role,
        isVerified: req.user.isVerified,
        kycStatus: req.user.kycStatus
      }
    });
  } catch (error) {
    console.error('Auth verify error:', error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// 12. OTP Endpoints (From LOGIN and USER REGISTRATION)
app.post('/api/auth/send-otp', [
  body('email').isEmail().normalizeEmail(),
  body('type').isIn(['verification', 'reset', 'two_factor'])
], async (req, res) => {
  try {
    const { email, type } = req.body;
    
    // Check if user exists for verification OTP
    if (type === 'verification') {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
    }
    
    const otp = generateOTP();
    const otpRecord = new OTP({
      email,
      otp,
      type,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });
    
    await otpRecord.save();
    
    // Send email
    let subject, html;
    switch (type) {
      case 'verification':
        subject = 'Verify Your Hashvex Account';
        html = `<h2>Account Verification</h2><p>Your verification code: <strong>${otp}</strong></p>`;
        break;
      case 'reset':
        subject = 'Password Reset Code';
        html = `<h2>Password Reset</h2><p>Your reset code: <strong>${otp}</strong></p>`;
        break;
      case 'two_factor':
        subject = '2FA Verification Code';
        html = `<h2>Two-Factor Authentication</h2><p>Your verification code: <strong>${otp}</strong></p>`;
        break;
    }
    
    await sendEmail(email, subject, html);
    
    res.json({
      success: true,
      message: 'OTP sent successfully',
      expiresIn: '10 minutes'
    });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

app.post('/api/auth/verify-otp', [
  body('email').isEmail().normalizeEmail(),
  body('otp').isLength({ min: 6, max: 6 }),
  body('type').isIn(['verification', 'reset', 'two_factor'])
], async (req, res) => {
  try {
    const { email, otp, type } = req.body;
    
    const otpRecord = await OTP.findOne({
      email,
      otp,
      type,
      expiresAt: { $gt: new Date() },
      verified: false
    });
    
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }
    
    otpRecord.verified = true;
    await otpRecord.save();
    
    // For verification, update user
    if (type === 'verification') {
      await User.findOneAndUpdate(
        { email },
        { isVerified: true }
      );
    }
    
    res.json({
      success: true,
      message: 'OTP verified successfully'
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'Failed to verify OTP' });
  }
});

// 13. Password Reset Endpoints (From PASSWORD RESET page)
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user exists for security
      return res.json({
        success: true,
        message: 'If an account exists, a reset email has been sent'
      });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour
    await user.save();
    
    const resetUrl = `https://hashvex-technologies.vercel.app/reset-password?token=${resetToken}`;
    
    await sendEmail(email, 'Password Reset Request', `
      <h2>Password Reset</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 1 hour.</p>
    `);
    
    res.json({
      success: true,
      message: 'Password reset email sent'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Failed to process request' });
  }
});

app.post('/api/auth/verify-reset-token', [
  body('token').notEmpty()
], async (req, res) => {
  try {
    const { token } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }
    
    res.json({
      success: true,
      email: user.email,
      valid: true
    });
  } catch (error) {
    console.error('Verify reset token error:', error);
    res.status(500).json({ success: false, message: 'Failed to verify token' });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
], async (req, res) => {
  try {
    const { token, password } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

// 14. Google Auth Endpoints (From LOGIN and USER REGISTRATION)
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
    let user = await User.findOne({ 
      $or: [{ email }, { googleId }] 
    });
    
    if (!user) {
      // Create new user
      const referralCode = 'HVX' + crypto.randomBytes(4).toString('hex').toUpperCase();
      
      user = new User({
        email,
        googleId,
        firstName: given_name,
        lastName: family_name || '',
        referralCode,
        isVerified: true
      });
      
      await user.save();
      
      // Create balance
      const balance = new Balance({
        userId: user._id,
        btc: 0,
        usd: 0
      });
      await balance.save();
      
      // Create cart
      const cart = new Cart({
        userId: user._id,
        items: [],
        total: 0
      });
      await cart.save();
    } else if (!user.googleId) {
      // Link Google account to existing email
      user.googleId = googleId;
      await user.save();
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      const otp = generateOTP();
      const otpRecord = new OTP({
        email: user.email,
        otp,
        type: 'two_factor',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000)
      });
      
      await otpRecord.save();
      
      await sendEmail(user.email, 'Hashvex 2FA Verification', `
        <h2>Two-Factor Authentication Required</h2>
        <p>Your 2FA verification code: <strong>${otp}</strong></p>
      `);
      
      return res.json({
        success: true,
        requires2FA: true,
        email: user.email,
        message: '2FA required. Check your email for verification code.'
      });
    }
    
    // Generate JWT
    const jwtToken = generateToken(user._id, user.role);
    
    res.json({
      success: true,
      token: jwtToken,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus
      }
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ success: false, message: 'Google authentication failed' });
  }
});

// 15. Logout Endpoint (From LOGOUT page)
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // In production, you might want to add token to blacklist
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Logout failed' });
  }
});

// 16. Account Settings Endpoints (From ACCOUNT SETTINGS page)
app.get('/api/users/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password -twoFactorSecret');
    const balance = await Balance.findOne({ userId: req.userId });
    
    res.json({
      success: true,
      user,
      balance: balance || {
        btc: 0,
        usd: 0,
        penaltyBalance: 0
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

app.put('/api/users/profile', authenticate, [
  body('firstName').optional().trim(),
  body('lastName').optional().trim(),
  body('phone').optional().trim(),
  body('city').optional().trim(),
  body('country').optional().trim(),
  body('dateOfBirth').optional().isISO8601()
], async (req, res) => {
  try {
    const updates = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret');
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

app.put('/api/users/address', authenticate, [
  body('street').optional().trim(),
  body('city').optional().trim(),
  body('state').optional().trim(),
  body('zipCode').optional().trim(),
  body('country').optional().trim()
], async (req, res) => {
  try {
    const addressUpdates = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: { address: addressUpdates } },
      { new: true }
    ).select('-password -twoFactorSecret');
    
    res.json({
      success: true,
      message: 'Address updated successfully',
      address: user.address
    });
  } catch (error) {
    console.error('Update address error:', error);
    res.status(500).json({ success: false, message: 'Failed to update address' });
  }
});

app.get('/api/users/kyc', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('kycStatus kycData');
    
    res.json({
      success: true,
      kyc: {
        status: user.kycStatus,
        data: user.kycData,
        submittedAt: user.kycData?.submittedAt,
        verifiedAt: user.kycData?.verifiedAt
      }
    });
  } catch (error) {
    console.error('Get KYC error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch KYC data' });
  }
});

app.get('/api/users/two-factor', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('twoFactorEnabled twoFactorSecret');
    
    if (!user.twoFactorEnabled) {
      // Generate new secret if 2FA not enabled
      const secret = speakeasy.generateSecret({
        name: `Hashvex (${user.email})`
      });
      
      user.twoFactorSecret = secret.base32;
      await user.save();
      
      return res.json({
        success: true,
        enabled: false,
        secret: secret.base32,
        qrCode: secret.otpauth_url
      });
    }
    
    res.json({
      success: true,
      enabled: true
    });
  } catch (error) {
    console.error('Get 2FA error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch 2FA settings' });
  }
});

app.post('/api/users/two-factor/enable', authenticate, [
  body('token').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const { token } = req.body;
    
    const user = await User.findById(req.userId).select('twoFactorSecret');
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token
    });
    
    if (!verified) {
      return res.status(400).json({ success: false, message: 'Invalid token' });
    }
    
    user.twoFactorEnabled = true;
    await user.save();
    
    res.json({
      success: true,
      message: 'Two-factor authentication enabled'
    });
  } catch (error) {
    console.error('Enable 2FA error:', error);
    res.status(500).json({ success: false, message: 'Failed to enable 2FA' });
  }
});

app.post('/api/users/two-factor/disable', authenticate, [
  body('token').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const { token } = req.body;
    
    const user = await User.findById(req.userId).select('twoFactorSecret twoFactorEnabled');
    
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ success: false, message: '2FA is not enabled' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token
    });
    
    if (!verified) {
      return res.status(400).json({ success: false, message: 'Invalid token' });
    }
    
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();
    
    res.json({
      success: true,
      message: 'Two-factor authentication disabled'
    });
  } catch (error) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({ success: false, message: 'Failed to disable 2FA' });
  }
});

app.get('/api/users/devices', authenticate, async (req, res) => {
  try {
    const devices = await Device.find({ userId: req.userId })
      .sort({ lastActive: -1 })
      .limit(10);
    
    res.json({
      success: true,
      devices
    });
  } catch (error) {
    console.error('Get devices error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch devices' });
  }
});

app.get('/api/users/activity', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const activities = await ActivityLog.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await ActivityLog.countDocuments({ userId: req.userId });
    
    res.json({
      success: true,
      activities,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get activity error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch activity logs' });
  }
});

app.get('/api/users/notifications', authenticate, async (req, res) => {
  try {
    const preferences = await NotificationPref.findOne({ userId: req.userId });
    
    if (!preferences) {
      // Create default preferences
      const defaultPrefs = new NotificationPref({
        userId: req.userId,
        email: {
          deposits: true,
          withdrawals: true,
          miningPayouts: true,
          securityAlerts: true,
          newsletter: false
        },
        push: {
          deposits: true,
          withdrawals: true,
          miningPayouts: true,
          securityAlerts: true
        },
        sms: {
          securityAlerts: false
        }
      });
      
      await defaultPrefs.save();
      
      return res.json({
        success: true,
        preferences: defaultPrefs
      });
    }
    
    res.json({
      success: true,
      preferences
    });
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch notification preferences' });
  }
});

app.put('/api/users/notifications', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    
    const preferences = await NotificationPref.findOneAndUpdate(
      { userId: req.userId },
      { $set: updates },
      { new: true, upsert: true }
    );
    
    res.json({
      success: true,
      message: 'Notification preferences updated',
      preferences
    });
  } catch (error) {
    console.error('Update notifications error:', error);
    res.status(500).json({ success: false, message: 'Failed to update notification preferences' });
  }
});

app.get('/api/users/api-keys', authenticate, async (req, res) => {
  try {
    const apiKeys = await ApiKey.find({ 
      userId: req.userId,
      isActive: true 
    }).select('-secret');
    
    res.json({
      success: true,
      apiKeys
    });
  } catch (error) {
    console.error('Get API keys error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch API keys' });
  }
});

app.post('/api/users/api-keys', authenticate, [
  body('name').notEmpty().trim(),
  body('permissions').optional().isArray()
], async (req, res) => {
  try {
    const { name, permissions = ['read'] } = req.body;
    
    const apiKey = crypto.randomBytes(32).toString('hex');
    const secret = crypto.randomBytes(64).toString('hex');
    
    const keyRecord = new ApiKey({
      userId: req.userId,
      name,
      key: `hvx_${apiKey}`,
      secret,
      permissions,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
    });
    
    await keyRecord.save();
    
    res.json({
      success: true,
      message: 'API key created',
      apiKey: keyRecord.key,
      secret, // Only show once
      permissions: keyRecord.permissions,
      expiresAt: keyRecord.expiresAt
    });
  } catch (error) {
    console.error('Create API key error:', error);
    res.status(500).json({ success: false, message: 'Failed to create API key' });
  }
});

app.delete('/api/users/api-keys/:keyId', authenticate, async (req, res) => {
  try {
    const { keyId } = req.params;
    
    const result = await ApiKey.findOneAndUpdate(
      { 
        _id: keyId,
        userId: req.userId 
      },
      { isActive: false }
    );
    
    if (!result) {
      return res.status(404).json({ success: false, message: 'API key not found' });
    }
    
    res.json({
      success: true,
      message: 'API key revoked'
    });
  } catch (error) {
    console.error('Revoke API key error:', error);
    res.status(500).json({ success: false, message: 'Failed to revoke API key' });
  }
});

// 17. Announcements Endpoint (From ACCOUNT SETTINGS)
app.get('/api/announcements', authenticate, async (req, res) => {
  try {
    const announcements = await Announcement.find({
      isActive: true,
      $or: [
        { targetUsers: [] }, // General announcements
        { targetUsers: req.user.email },
        { targetUsers: 'all' }
      ],
      $and: [
        { startDate: { $lte: new Date() } },
        { endDate: { $gte: new Date() } }
      ]
    })
      .sort({ priority: -1, createdAt: -1 })
      .limit(5);
    
    res.json({
      success: true,
      announcements
    });
  } catch (error) {
    console.error('Get announcements error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch announcements' });
  }
});

// 18. Auth Records Endpoint (From ACCOUNT SETTINGS)
app.post('/api/auth/records', authenticate, async (req, res) => {
  try {
    const { action, details } = req.body;
    
    const activityLog = new ActivityLog({
      userId: req.userId,
      action,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details,
      status: 'success'
    });
    
    await activityLog.save();
    
    res.json({
      success: true,
      message: 'Activity logged'
    });
  } catch (error) {
    console.error('Log activity error:', error);
    res.status(500).json({ success: false, message: 'Failed to log activity' });
  }
});

// 19. Admin Endpoints (From ADMIN page)
const adminAuth = [authenticate, requireAdmin];




// Admin Login Endpoint - Fixes 401 error
app.post('/api/admin/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin user
    const user = await User.findOne({ 
      email: email.toLowerCase(),
      role: 'admin' 
    }).select('+password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid admin credentials' 
      });
    }
    
    if (!user.isActive) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin account deactivated' 
      });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid admin credentials' 
      });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate admin token
    const token = jwt.sign(
      { 
        userId: user._id, 
        role: user.role,
        isAdmin: true
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      token,
      admin: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ success: false, message: 'Admin login failed' });
  }
});

app.get('/api/admin/verify', ...adminAuth, async (req, res) => {
  try {
    res.json({
      success: true,
      admin: {
        id: req.user._id,
        email: req.user.email,
        name: `${req.user.firstName} ${req.user.lastName}`,
        role: req.user.role
      }
    });
  } catch (error) {
    console.error('Admin verify error:', error);
    res.status(500).json({ success: false, message: 'Admin verification failed' });
  }
});

app.get('/api/admin/dashboard/stats', ...adminAuth, async (req, res) => {
  try {
    const [
      totalUsers,
      activeUsers,
      totalDeposits,
      totalWithdrawals,
      pendingKYC,
      activeLoans,
      availableMiners
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isActive: true, lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }),
      Transaction.aggregate([{ $match: { type: 'deposit', status: 'completed' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]),
      Transaction.aggregate([{ $match: { type: 'withdrawal', status: 'completed' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]),
      User.countDocuments({ kycStatus: 'pending' }),
      Loan.countDocuments({ status: 'active' }),
      Miner.countDocuments({ available: true, quantity: { $gt: 0 } })
    ]);
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        pendingKYC,
        activeLoans,
        availableMiners
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch admin stats' });
  }
});

app.get('/api/admin/users', ...adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const users = await User.find()
      .select('-password -twoFactorSecret')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await User.countDocuments();
    
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
    console.error('Admin get users error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

app.get('/api/admin/kyc/pending', ...adminAuth, async (req, res) => {
  try {
    const pendingKYC = await User.find({ 
      kycStatus: 'pending',
      'kycData.submittedAt': { $exists: true }
    })
      .select('firstName lastName email kycData submittedAt')
      .sort({ 'kycData.submittedAt': 1 });
    
    res.json({
      success: true,
      pendingKYC,
      count: pendingKYC.length
    });
  } catch (error) {
    console.error('Admin get pending KYC error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch pending KYC' });
  }
});

app.put('/api/admin/kyc/:userId', ...adminAuth, [
  body('status').isIn(['verified', 'rejected']),
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { userId } = req.params;
    const { status, notes } = req.body;
    
    const user = await User.findByIdAndUpdate(
      userId,
      {
        kycStatus: status,
        'kycData.verifiedAt': new Date(),
        'kycData.verifiedBy': req.userId,
        'kycData.adminNotes': notes
      },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Send notification email
    if (status === 'verified') {
      await sendEmail(user.email, 'KYC Verification Approved', `
        <h2>KYC Verification Approved</h2>
        <p>Your KYC verification has been approved. You can now access all platform features including withdrawals.</p>
      `);
    } else {
      await sendEmail(user.email, 'KYC Verification Rejected', `
        <h2>KYC Verification Rejected</h2>
        <p>Your KYC verification has been rejected. Please submit valid documents to complete verification.</p>
        ${notes ? `<p><strong>Notes:</strong> ${notes}</p>` : ''}
      `);
    }
    
    res.json({
      success: true,
      message: `KYC ${status} successfully`,
      user
    });
  } catch (error) {
    console.error('Admin update KYC error:', error);
    res.status(500).json({ success: false, message: 'Failed to update KYC status' });
  }
});

app.get('/api/admin/deposits', ...adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const status = req.query.status;
    
    const query = { type: 'deposit' };
    if (status) query.status = status;
    
    const deposits = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Transaction.countDocuments(query);
    
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
    console.error('Admin get deposits error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch deposits' });
  }
});

app.get('/api/admin/withdrawals', ...adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const status = req.query.status;
    
    const query = { type: 'withdrawal' };
    if (status) query.status = status;
    
    const withdrawals = await Transaction.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Transaction.countDocuments(query);
    
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
    console.error('Admin get withdrawals error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch withdrawals' });
  }
});

app.put('/api/admin/transactions/:id', ...adminAuth, [
  body('status').isIn(['completed', 'rejected', 'cancelled']),
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;
    
    const transaction = await Transaction.findById(id);
    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }
    
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Update transaction
      transaction.status = status;
      transaction.processedBy = req.userId;
      transaction.processedAt = new Date();
      transaction.adminNotes = notes;
      await transaction.save({ session });
      
      if (transaction.type === 'withdrawal') {
        const withdrawal = await Withdrawal.findOne({ _id: transaction.metadata?.withdrawalId }).session(session);
        if (withdrawal) {
          withdrawal.status = status === 'completed' ? 'completed' : 'rejected';
          withdrawal.processedBy = req.userId;
          withdrawal.processedAt = new Date();
          withdrawal.adminNotes = notes;
          await withdrawal.save({ session });
          
          // Update balance if rejected
          if (status === 'rejected') {
            const balance = await Balance.findOne({ userId: transaction.userId }).session(session);
            if (balance) {
              if (transaction.currency === 'BTC') {
                balance.btc += transaction.amount;
                balance.pendingBtc -= transaction.amount;
              } else {
                balance.usd += transaction.amount;
                balance.pendingUsd -= transaction.amount;
              }
              await balance.save({ session });
            }
          }
        }
      }
      
      await session.commitTransaction();
      
      res.json({
        success: true,
        message: `Transaction ${status} successfully`,
        transaction
      });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    console.error('Admin update transaction error:', error);
    res.status(500).json({ success: false, message: 'Failed to update transaction' });
  }
});

app.get('/api/admin/miners/sale', ...adminAuth, async (req, res) => {
  try {
    const miners = await Miner.find({ type: 'sale' })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      miners
    });
  } catch (error) {
    console.error('Admin get sale miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch sale miners' });
  }
});

app.get('/api/admin/miners/rent', ...adminAuth, async (req, res) => {
  try {
    const miners = await Miner.find({ type: 'rent' })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      miners
    });
  } catch (error) {
    console.error('Admin get rent miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch rent miners' });
  }
});

app.post('/api/admin/miners', ...adminAuth, [
  body('name').notEmpty(),
  body('model').notEmpty(),
  body('hashRate').isFloat({ min: 1 }),
  body('price').isFloat({ min: 0 }),
  body('type').isIn(['rent', 'sale']),
  body('quantity').isInt({ min: 1 }),
  body('dailyProfit').optional().isFloat({ min: 0 }),
  body('description').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const minerData = req.body;
    
    const miner = new Miner({
      ...minerData,
      available: true
    });
    
    await miner.save();
    
    res.json({
      success: true,
      message: 'Miner created successfully',
      miner
    });
  } catch (error) {
    console.error('Admin create miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to create miner' });
  }
});

app.put('/api/admin/miners/:id', ...adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const miner = await Miner.findByIdAndUpdate(
      id,
      { $set: updates },
      { new: true, runValidators: true }
    );
    
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    res.json({
      success: true,
      message: 'Miner updated successfully',
      miner
    });
  } catch (error) {
    console.error('Admin update miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to update miner' });
  }
});

app.delete('/api/admin/miners/:id', ...adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    const miner = await Miner.findById(id);
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    // Check if miner is owned by anyone
    const ownedCount = await OwnedMiner.countDocuments({ minerId: id, status: 'active' });
    if (ownedCount > 0) {
      return res.status(400).json({ 
        success: false, 
        message: `Cannot delete miner that is currently owned by ${ownedCount} user(s)` 
      });
    }
    
    miner.available = false;
    await miner.save();
    
    res.json({
      success: true,
      message: 'Miner marked as unavailable'
    });
  } catch (error) {
    console.error('Admin delete miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete miner' });
  }
});

app.get('/api/admin/loans', ...adminAuth, async (req, res) => {
  try {
    const status = req.query.status;
    const query = status ? { status } : {};
    
    const loans = await Loan.find(query)
      .populate('userId', 'firstName lastName email')
      .populate('collateral')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({
      success: true,
      loans
    });
  } catch (error) {
    console.error('Admin get loans error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch loans' });
  }
});

app.put('/api/admin/loans/:id', ...adminAuth, [
  body('status').isIn(['approved', 'rejected', 'active', 'defaulted']),
  body('approvedAmount').optional().isFloat({ min: 0 }),
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const { id } = req.params;
    const { status, approvedAmount, notes } = req.body;
    
    const loan = await Loan.findById(id);
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }
    
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      loan.status = status;
      loan.adminNotes = notes;
      
      if (status === 'approved') {
        loan.approvedAmount = approvedAmount || loan.amount;
        loan.approvedBy = req.userId;
        loan.approvedAt = new Date();
        loan.disbursedAt = new Date();
        loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        
        // Add funds to user's balance
        const balance = await Balance.findOne({ userId: loan.userId }).session(session);
        if (balance) {
          balance.usd += loan.approvedAmount;
          balance.loanBalance += loan.approvedAmount;
          await balance.save({ session });
        }
        
        // Create transaction
        const transaction = new Transaction({
          userId: loan.userId,
          type: 'loan',
          amount: loan.approvedAmount,
          currency: 'USD',
          status: 'completed',
          description: 'Loan disbursement',
          metadata: { loanId: loan._id }
        });
        
        await transaction.save({ session });
      }
      
      await loan.save({ session });
      await session.commitTransaction();
      
      res.json({
        success: true,
        message: `Loan ${status} successfully`,
        loan
      });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    console.error('Admin update loan error:', error);
    res.status(500).json({ success: false, message: 'Failed to update loan' });
  }
});

app.post('/api/admin/notifications/send', ...adminAuth, [
  body('title').notEmpty(),
  body('message').notEmpty(),
  body('type').isIn(['info', 'warning', 'success', 'error']),
  body('targetUsers').optional().isArray(),
  body('priority').optional().isInt({ min: 1, max: 5 })
], async (req, res) => {
  try {
    const { title, message, type, targetUsers = [], priority = 1 } = req.body;
    
    const announcement = new Announcement({
      title,
      message,
      type,
      priority,
      targetUsers,
      isActive: true,
      startDate: new Date(),
      endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 1 week
    });
    
    await announcement.save();
    
    // Send email notifications to targeted users
    if (targetUsers.length > 0 && targetUsers[0] !== 'all') {
      const users = await User.find({ email: { $in: targetUsers } });
      
      for (const user of users) {
        await sendEmail(user.email, title, `
          <h2>${title}</h2>
          <p>${message}</p>
          <p><em>This is an automated message from Hashvex Technologies.</em></p>
        `);
      }
    }
    
    res.json({
      success: true,
      message: 'Notification sent successfully',
      announcement
    });
  } catch (error) {
    console.error('Admin send notification error:', error);
    res.status(500).json({ success: false, message: 'Failed to send notification' });
  }
});

app.get('/api/admin/settings', ...adminAuth, async (req, res) => {
  try {
    // In production, store settings in database
    const defaultSettings = {
      platform: {
        name: 'Hashvex Technologies',
        maintenance: false,
        registrationOpen: true,
        withdrawalFee: 0.001, // 0.1%
        depositFee: 0,
        minDeposit: 10,
        minWithdrawal: 0.0001
      },
      bitcoin: {
        confirmationsRequired: 3,
        autoWithdrawalEnabled: true,
        withdrawalLimit: 10
      },
      email: {
        notificationsEnabled: true,
        supportEmail: 'support@hashvex.com'
      }
    };
    
    res.json({
      success: true,
      settings: defaultSettings
    });
  } catch (error) {
    console.error('Admin get settings error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', ...adminAuth, async (req, res) => {
  try {
    const updates = req.body;
    
    // In production, save to database
    console.log('Settings updated:', updates);
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: updates
    });
  } catch (error) {
    console.error('Admin update settings error:', error);
    res.status(500).json({ success: false, message: 'Failed to update settings' });
  }
});

// ============================ SERVER STARTUP ============================
const PORT = process.env.PORT || 5000;

// Health check
app.get('/health', async (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'unknown',
    redis: 'unknown'
  };
  
  try {
    await mongoose.connection.db.admin().ping();
    health.database = 'connected';
    
    await redis.ping();
    health.redis = 'connected';
    
    res.json(health);
  } catch (error) {
    health.status = 'DEGRADED';
    health.database = 'error';
    health.error = error.message;
    res.status(503).json(health);
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      success: false, 
      message: `File upload error: ${err.message}` 
    });
  }
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      success: false, 
      message: 'Validation error',
      errors: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'MongoError' && err.code === 11000) {
    return res.status(409).json({ 
      success: false, 
      message: 'Duplicate key error' 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// WebSocket for real-time updates
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('subscribe', (data) => {
    if (data.userId) {
      socket.join(`user:${data.userId}`);
    }
    if (data.channel === 'bitcoin_price') {
      socket.join('bitcoin_price');
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Broadcast Bitcoin price updates
setInterval(async () => {
  try {
    const priceData = await getBitcoinPrice();
    io.to('bitcoin_price').emit('bitcoin_price_update', {
      ...priceData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error broadcasting Bitcoin price:', error);
  }
}, 30000);

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
  console.log(`✅ Redis: ${redis.status === 'ready' ? 'Connected' : 'Disconnected'}`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
const shutdown = async (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  httpServer.close(() => console.log('HTTP server closed'));
  io.close(() => console.log('WebSocket server closed'));
  await redis.quit();
  await mongoose.connection.close(false);
  process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
