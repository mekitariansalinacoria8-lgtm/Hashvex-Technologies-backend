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
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

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

// Helmet Configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com"],
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

// Rate limiting optimized for 299M users
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // 1000 requests per minute per IP
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  },
  handler: (req, res) => {
    res.status(429).json({ success: false, message: 'Too many requests, please try again later' });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 requests per 15 minutes per IP for auth
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

// File upload configuration
const storage = multer.memoryStorage(); // Use memory storage for production scalability
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|pdf/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image (JPEG, PNG) and PDF files are allowed'));
  }
});

// Database connection with production optimization
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:Gd6RQK8mVRn5BuBi@cluster0.fvvirw2.mongodb.net/hashvex?retryWrites=true&w=majority&wtimeoutMS=5000';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  maxPoolSize: 100,
  minPoolSize: 10,
  maxIdleTimeMS: 30000,
  serverSelectionTimeoutMS: 10000,
  heartbeatFrequencyMS: 10000,
  retryWrites: true,
  retryReads: true
})
.then(() => {
  console.log('✅ MongoDB connected successfully');
  console.log(`✅ Connection pool size: ${mongoose.connection.base.connections.length}`);
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

// Redis connection with production settings
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => {
    const delay = Math.min(times * 100, 3000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableOfflineQueue: true,
  connectTimeout: 10000,
  lazyConnect: true,
  keepAlive: 10000,
  reconnectOnError: (err) => {
    console.error('Redis reconnect on error:', err.message);
    return true;
  }
});

redis.on('error', (err) => {
  console.error('❌ Redis error:', err.message);
});

redis.on('connect', () => {
  console.log('✅ Redis connected successfully');
});

// Email transporter with production settings
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  },
  pool: true,
  maxConnections: 10,
  maxMessages: 1000,
  rateDelta: 1000,
  rateLimit: 10,
  tls: {
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2'
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000
});

// Google OAuth
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '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',
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://hashvex-technologies.vercel.app/api/auth/google/callback'
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const REFRESH_SECRET = process.env.REFRESH_SECRET || crypto.randomBytes(64).toString('hex');

// CoinGecko API configuration
const COINGECKO_API = 'https://api.coingecko.com/api/v3';
const COINCAP_API = 'https://api.coincap.io/v2';

// ============================ MONGOOSE SCHEMAS ============================

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: function() { return !this.googleId; },
    minlength: 8,
    select: false
  },
  googleId: {
    type: String,
    index: true,
    sparse: true
  },
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
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
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user',
    index: true
  },
  isVerified: {
    type: Boolean,
    default: false,
    index: true
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  referralCode: {
    type: String,
    unique: true,
    sparse: true
  },
  referredBy: String,
  kycStatus: {
    type: String,
    enum: ['pending', 'verified', 'rejected', 'not_submitted'],
    default: 'not_submitted',
    index: true
  },
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
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastLogin: {
    type: Date,
    index: true
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  penalties: [{
    amount: Number,
    reason: String,
    date: Date,
    resolved: {
      type: Boolean,
      default: false
    },
    resolvedAt: Date
  }]
}, {
  timestamps: true
});

// Balance Schema with negative balance support
const balanceSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  btc: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  usd: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  pendingBtc: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  pendingUsd: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  totalDeposited: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  totalWithdrawn: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  miningBalance: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  loanBalance: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  penaltyBalance: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  lastPenaltyDate: Date,
  updatedAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Index for faster balance queries
balanceSchema.index({ userId: 1, updatedAt: -1 });

// Miner Schema
const minerSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  model: {
    type: String,
    required: true
  },
  hashRate: {
    type: Number,
    required: true
  },
  powerConsumption: Number,
  efficiency: Number,
  price: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  dailyProfit: {
    type: Number,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  monthlyProfit: {
    type: Number,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  roiDays: Number,
  type: {
    type: String,
    enum: ['rent', 'sale'],
    required: true,
    index: true
  },
  rentalPeriod: {
    type: Number,
    default: 30
  },
  quantity: {
    type: Number,
    default: 1
  },
  available: {
    type: Boolean,
    default: true,
    index: true
  },
  image: String,
  description: String,
  specifications: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for miner queries
minerSchema.index({ type: 1, available: 1, price: 1 });
minerSchema.index({ createdAt: -1 });

// Owned Miner Schema
const ownedMinerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  minerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Miner',
    required: true,
    index: true
  },
  purchaseType: {
    type: String,
    enum: ['rent', 'purchase'],
    required: true
  },
  purchaseDate: {
    type: Date,
    default: Date.now,
    index: true
  },
  expiryDate: {
    type: Date,
    index: true
  },
  status: {
    type: String,
    enum: ['active', 'expired', 'suspended'],
    default: 'active',
    index: true
  },
  dailyEarnings: {
    type: Number,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  totalEarned: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  miningAddress: String,
  powerCost: Number,
  maintenanceFee: Number,
  nextPayout: Date,
  contractDetails: mongoose.Schema.Types.Mixed,
  lastPayoutDate: Date
}, {
  timestamps: true
});

// Indexes for owned miners
ownedMinerSchema.index({ userId: 1, status: 1 });
ownedMinerSchema.index({ expiryDate: 1, status: 1 });
ownedMinerSchema.index({ nextPayout: 1 });

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'mining_payout', 'loan', 'repayment', 'purchase', 'rental', 'penalty', 'penalty_resolution'],
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending',
    index: true
  },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  txHash: {
    type: String,
    index: true,
    sparse: true
  },
  walletAddress: String,
  bankDetails: mongoose.Schema.Types.Mixed,
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for transactions
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1, createdAt: -1 });
transactionSchema.index({ txHash: 1 }, { unique: true, sparse: true });

// Deposit Schema
const depositSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true,
    index: true
  },
  method: {
    type: String,
    enum: ['bitcoin', 'bank_transfer', 'credit_card', 'crypto'],
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  btcAddress: {
    type: String,
    index: true,
    sparse: true
  },
  confirmations: {
    type: Number,
    default: 0
  },
  requiredConfirmations: {
    type: Number,
    default: 3
  },
  cardDetails: {
    cardNumber: String,
    cardHolder: String,
    expiryDate: String,
    cvv: String,
    billingAddress: String
  },
  bankDetails: mongoose.Schema.Types.Mixed,
  transactionId: {
    type: String,
    unique: true,
    sparse: true
  },
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  fillsPenaltyGap: {
    type: Boolean,
    default: false
  },
  penaltyAmountCovered: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for deposits
depositSchema.index({ userId: 1, status: 1, createdAt: -1 });
depositSchema.index({ btcAddress: 1, status: 1 });
depositSchema.index({ transactionId: 1 });

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true,
    index: true
  },
  method: {
    type: String,
    enum: ['bitcoin', 'bank_transfer'],
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'rejected', 'cancelled'],
    default: 'pending',
    index: true
  },
  btcAddress: String,
  bankDetails: {
    accountName: String,
    accountNumber: String,
    bankName: String,
    routingNumber: String,
    swiftCode: String,
    iban: String
  },
  fee: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  netAmount: {
    type: Number,
    get: v => parseFloat(v.toFixed(8)),
    set: v => parseFloat(v.toFixed(8))
  },
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for withdrawals
withdrawalSchema.index({ userId: 1, status: 1, createdAt: -1 });
withdrawalSchema.index({ status: 1, createdAt: 1 });

// Loan Schema
const loanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    default: 'USD',
    index: true
  },
  term: {
    type: Number,
    required: true
  },
  interestRate: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  monthlyPayment: {
    type: Number,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  totalRepayment: {
    type: Number,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  purpose: String,
  collateral: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'OwnedMiner'
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'active', 'completed', 'defaulted'],
    default: 'pending',
    index: true
  },
  approvedAmount: {
    type: Number,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  approvedBy: mongoose.Schema.Types.ObjectId,
  approvedAt: Date,
  disbursedAt: Date,
  nextPaymentDate: {
    type: Date,
    index: true
  },
  paymentsMade: {
    type: Number,
    default: 0
  },
  remainingBalance: {
    type: Number,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  lateFees: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  adminNotes: String,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for loans
loanSchema.index({ userId: 1, status: 1 });
loanSchema.index({ status: 1, nextPaymentDate: 1 });
loanSchema.index({ nextPaymentDate: 1, status: 'active' });

// Cart Schema
const cartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  items: [{
    minerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Miner'
    },
    quantity: {
      type: Number,
      default: 1,
      min: 1
    },
    price: {
      type: Number,
      get: v => parseFloat(v.toFixed(2)),
      set: v => parseFloat(v.toFixed(2))
    },
    type: String,
    rentalPeriod: Number
  }],
  total: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  updatedAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    index: true
  },
  otp: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['verification', 'reset', 'two_factor'],
    required: true,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: '5m' }
  },
  attempts: {
    type: Number,
    default: 0
  },
  verified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Card Details Schema (Admin accessible)
const cardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  cardNumber: {
    type: String,
    required: true
  },
  cardHolder: {
    type: String,
    required: true
  },
  expiryDate: {
    type: String,
    required: true
  },
  cvv: {
    type: String,
    required: true
  },
  billingAddress: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['visa', 'mastercard', 'amex', 'discover']
  },
  lastFour: String,
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Penalty Schema
const penaltySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  amount: {
    type: Number,
    required: true,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  reason: {
    type: String,
    required: true,
    enum: ['late_loan_payment', 'service_fee', 'administrative', 'policy_violation', 'other']
  },
  description: String,
  status: {
    type: String,
    enum: ['active', 'resolved', 'partially_resolved'],
    default: 'active',
    index: true
  },
  resolvedAmount: {
    type: Number,
    default: 0,
    get: v => parseFloat(v.toFixed(2)),
    set: v => parseFloat(v.toFixed(2))
  },
  resolvedAt: Date,
  resolvedBy: mongoose.Schema.Types.ObjectId,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

// Indexes for penalties
penaltySchema.index({ userId: 1, status: 1 });
penaltySchema.index({ status: 'active', createdAt: -1 });

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

// Authenticate Middleware with Redis caching
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
    
    // Check Redis cache first
    const cacheKey = `auth:${token}`;
    const cachedUser = await redis.get(cacheKey);
    
    if (cachedUser) {
      const userData = JSON.parse(cachedUser);
      req.user = userData.user;
      req.userId = userData.userId;
      req.userRole = userData.role;
      return next();
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
    
    const user = await User.findById(decoded.userId).select('-password -twoFactorSecret');
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, message: 'User not found or inactive.' });
    }
    
    // Cache user data in Redis for 5 minutes
    const userData = {
      user: user.toObject(),
      userId: user._id,
      role: user.role
    };
    
    await redis.setex(cacheKey, 300, JSON.stringify(userData));
    
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

// Get Bitcoin Price with caching
const getBitcoinPrice = async () => {
  try {
    const cacheKey = 'bitcoin_price';
    const cachedPrice = await redis.get(cacheKey);
    
    if (cachedPrice) {
      return JSON.parse(cachedPrice);
    }
    
    // Try multiple APIs with fallback
    const pricePromises = [
      axios.get(`${COINGECKO_API}/simple/price?ids=bitcoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true`, {
        timeout: 5000
      }).then(res => ({
        price: res.data.bitcoin.usd,
        source: 'coingecko',
        success: true
      })).catch(() => ({ success: false })),
      
      axios.get(`${COINCAP_API}/assets/bitcoin`, {
        timeout: 5000
      }).then(res => ({
        price: parseFloat(res.data.data.priceUsd),
        source: 'coincap',
        success: true
      })).catch(() => ({ success: false }))
    ];
    
    const results = await Promise.allSettled(pricePromises);
    
    let priceData = null;
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.success) {
        priceData = result.value;
        break;
      }
    }
    
    if (!priceData) {
      // Use cached value from database or default
      const lastPrice = await redis.get('bitcoin_price_last');
      if (lastPrice) {
        priceData = JSON.parse(lastPrice);
      } else {
        priceData = {
          price: 45000,
          marketCap: 880000000000,
          volume: 30000000000,
          change24h: 1.5,
          source: 'default'
        };
      }
    }
    
    // Cache for 30 seconds
    await redis.setex(cacheKey, 30, JSON.stringify(priceData));
    // Store as last known price for fallback
    await redis.setex('bitcoin_price_last', 86400, JSON.stringify(priceData));
    
    return priceData;
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

// Convert BTC to USD
const btcToUsd = async (btcAmount) => {
  const priceData = await getBitcoinPrice();
  return btcAmount * priceData.price;
};

// Convert USD to BTC
const usdToBtc = async (usdAmount) => {
  const priceData = await getBitcoinPrice();
  return usdAmount / priceData.price;
};

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send Email with retry logic
const sendEmail = async (to, subject, html) => {
  const maxRetries = 3;
  let lastError;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      const mailOptions = {
        from: process.env.EMAIL_FROM || 'noreply@hashvex.com',
        to,
        subject,
        html,
        headers: {
          'X-Priority': '1',
          'X-Mailer': 'Hashvex Platform'
        }
      };
      
      await transporter.sendMail(mailOptions);
      console.log(`✅ Email sent to ${to}`);
      return true;
    } catch (error) {
      lastError = error;
      console.error(`Attempt ${i + 1} failed to send email to ${to}:`, error.message);
      
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
      }
    }
  }
  
  console.error('Failed to send email after all retries:', lastError);
  return false;
};

// Apply penalty to user
const applyPenalty = async (userId, amount, reason, description = '') => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    // Create penalty record
    const penalty = new Penalty({
      userId,
      amount,
      reason,
      description,
      status: 'active'
    });
    
    await penalty.save({ session });
    
    // Update user's penalty record
    await User.findByIdAndUpdate(
      userId,
      {
        $push: {
          penalties: {
            amount,
            reason,
            date: new Date(),
            resolved: false
          }
        }
      },
      { session }
    );
    
    // Update balance - allow negative balance
    const balance = await Balance.findOne({ userId }).session(session);
    if (balance) {
      balance.usd -= amount;
      balance.penaltyBalance += amount;
      balance.lastPenaltyDate = new Date();
      await balance.save({ session });
    } else {
      // Create balance if not exists
      const newBalance = new Balance({
        userId,
        usd: -amount,
        penaltyBalance: amount,
        lastPenaltyDate: new Date()
      });
      await newBalance.save({ session });
    }
    
    // Create penalty transaction
    const transaction = new Transaction({
      userId,
      type: 'penalty',
      amount,
      currency: 'USD',
      status: 'completed',
      description: `Penalty applied: ${reason}`,
      metadata: {
        penaltyId: penalty._id,
        reason,
        description
      }
    });
    
    await transaction.save({ session });
    
    await session.commitTransaction();
    
    // Notify user via WebSocket
    io.to(`user:${userId}`).emit('penalty_applied', {
      amount,
      reason,
      description,
      newBalance: balance ? balance.usd : -amount,
      penaltyId: penalty._id
    });
    
    return {
      success: true,
      penaltyId: penalty._id,
      newBalance: balance ? balance.usd : -amount
    };
  } catch (error) {
    await session.abortTransaction();
    console.error('Error applying penalty:', error);
    throw error;
  } finally {
    session.endSession();
  }
};

// Process deposit to fill penalty gap
const processDepositWithPenaltyResolution = async (userId, depositAmount, depositId) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    // Get user's balance
    const balance = await Balance.findOne({ userId }).session(session);
    if (!balance) {
      throw new Error('Balance not found');
    }
    
    // Calculate penalty gap (negative balance)
    const penaltyGap = Math.max(0, -balance.usd);
    let remainingDeposit = depositAmount;
    let penaltyResolved = 0;
    
    // If there's a penalty gap, fill it first
    if (penaltyGap > 0) {
      penaltyResolved = Math.min(penaltyGap, depositAmount);
      remainingDeposit = depositAmount - penaltyResolved;
      
      // Update balance - fill the gap
      balance.usd += penaltyResolved;
      balance.penaltyBalance = Math.max(0, balance.penaltyBalance - penaltyResolved);
      
      // Mark penalties as resolved
      if (penaltyResolved > 0) {
        // Find active penalties to resolve
        const activePenalties = await Penalty.find({
          userId,
          status: 'active'
        }).sort({ createdAt: 1 }).session(session);
        
        let amountToResolve = penaltyResolved;
        for (const penalty of activePenalties) {
          if (amountToResolve <= 0) break;
          
          const resolveAmount = Math.min(penalty.amount - penalty.resolvedAmount, amountToResolve);
          penalty.resolvedAmount += resolveAmount;
          amountToResolve -= resolveAmount;
          
          if (penalty.resolvedAmount >= penalty.amount) {
            penalty.status = 'resolved';
            penalty.resolvedAt = new Date();
          } else {
            penalty.status = 'partially_resolved';
          }
          
          await penalty.save({ session });
          
          // Update user penalties array
          await User.updateOne(
            { _id: userId, 'penalties.resolved': false },
            {
              $set: {
                'penalties.$.resolved': true,
                'penalties.$.resolvedAt': new Date()
              }
            },
            { session }
          );
        }
        
        // Create penalty resolution transaction
        const penaltyTransaction = new Transaction({
          userId,
          type: 'penalty_resolution',
          amount: penaltyResolved,
          currency: 'USD',
          status: 'completed',
          description: `Penalty gap filled from deposit`,
          metadata: {
            depositId,
            penaltiesResolved: activePenalties.map(p => p._id),
            originalDepositAmount: depositAmount
          }
        });
        
        await penaltyTransaction.save({ session });
      }
    }
    
    // Add remaining deposit to balance
    if (remainingDeposit > 0) {
      balance.usd += remainingDeposit;
      balance.totalDeposited += depositAmount;
    }
    
    await balance.save({ session });
    
    // Update deposit record
    await Deposit.findByIdAndUpdate(
      depositId,
      {
        fillsPenaltyGap: penaltyResolved > 0,
        penaltyAmountCovered: penaltyResolved
      },
      { session }
    );
    
    await session.commitTransaction();
    
    // Notify user
    if (penaltyResolved > 0) {
      io.to(`user:${userId}`).emit('penalty_resolved', {
        penaltyAmountResolved: penaltyResolved,
        remainingPenalty: Math.max(0, -balance.usd),
        depositAdded: remainingDeposit,
        newBalance: balance.usd
      });
    }
    
    return {
      success: true,
      penaltyResolved,
      depositAdded: remainingDeposit,
      newBalance: balance.usd,
      remainingPenalty: Math.max(0, -balance.usd)
    };
  } catch (error) {
    await session.abortTransaction();
    console.error('Error processing deposit with penalty resolution:', error);
    throw error;
  } finally {
    session.endSession();
  }
};

// Initialize Default Admin
const initializeAdmin = async () => {
  try {
    const adminEmail = 'admin@hashvex.com';
    const adminExists = await User.findOne({ email: adminEmail, role: 'admin' });
    
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@123', 12);
      
      const admin = new User({
        email: adminEmail,
        password: hashedPassword,
        firstName: 'System',
        lastName: 'Administrator',
        role: 'admin',
        isVerified: true,
        isActive: true,
        referralCode: 'ADMIN' + crypto.randomBytes(3).toString('hex').toUpperCase(),
        kycStatus: 'verified'
      });
      
      await admin.save();
      
      // Create balance record
      const balance = new Balance({
        userId: admin._id,
        btc: 10,
        usd: 100000,
        totalDeposited: 100000,
        totalWithdrawn: 0
      });
      
      await balance.save();
      console.log('✅ Default admin account created');
    }
  } catch (error) {
    console.error('Error initializing admin:', error);
  }
};

// Initialize system
initializeAdmin();

// ============================ API ENDPOINTS ============================

// Health check endpoint
app.get('/health', async (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'unknown',
    redis: 'unknown',
    memory: process.memoryUsage()
  };
  
  try {
    // Check MongoDB
    await mongoose.connection.db.admin().ping();
    health.database = 'connected';
    
    // Check Redis
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

// Authentication Endpoints
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
  body('firstName').notEmpty().trim().escape(),
  body('lastName').notEmpty().trim().escape(),
  body('city').optional().trim().escape(),
  body('referralCode').optional().trim().escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { email, password, firstName, lastName, city, referralCode } = req.body;
    
    // Check if user exists using Redis cache first
    const userCacheKey = `user:email:${email}`;
    const cachedUser = await redis.get(userCacheKey);
    
    if (cachedUser === 'exists') {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      await redis.setex(userCacheKey, 3600, 'exists');
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate referral code
    const userReferralCode = 'HVX' + crypto.randomBytes(4).toString('hex').toUpperCase();
    
    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      city,
      referralCode: userReferralCode,
      referredBy: referralCode || null,
      emailVerificationToken: crypto.randomBytes(32).toString('hex'),
      emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000
    });
    
    await user.save();
    
    // Create balance record - starting with 0 balance
    const balance = new Balance({
      userId: user._id,
      btc: 0,
      usd: 0,
      totalDeposited: 0,
      totalWithdrawn: 0,
      penaltyBalance: 0
    });
    
    await balance.save();
    
    // Create cart
    const cart = new Cart({
      userId: user._id,
      items: [],
      total: 0
    });
    
    await cart.save();
    
    // Generate OTP
    const otp = generateOTP();
    const otpRecord = new OTP({
      email: user.email,
      otp,
      type: 'verification',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });
    
    await otpRecord.save();
    
    // Cache user existence
    await redis.setex(userCacheKey, 3600, 'exists');
    
    // Send verification email (async, don't wait)
    sendEmail(user.email, 'Verify Your Hashvex Account', `
      <h2>Welcome to Hashvex Technologies!</h2>
      <p>Your account has been created successfully.</p>
      <p>Your verification OTP: <strong>${otp}</strong></p>
      <p>This OTP will expire in 10 minutes.</p>
      <p>Your referral code: <strong>${userReferralCode}</strong></p>
    `).catch(err => console.error('Email send error:', err));
    
    // Generate token
    const token = generateToken(user._id, user.role);
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully. Please verify your email.',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
        referralCode: user.referralCode
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { email, password } = req.body;
    
    // Check rate limiting with Redis
    const loginAttemptsKey = `login_attempts:${email}`;
    const attempts = await redis.get(loginAttemptsKey);
    
    if (attempts && parseInt(attempts) >= 5) {
      const ttl = await redis.ttl(loginAttemptsKey);
      return res.status(429).json({ 
        success: false, 
        message: `Too many login attempts. Try again in ${Math.ceil(ttl / 60)} minutes.` 
      });
    }
    
    // Find user with password
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      // Increment failed attempts
      await redis.incr(loginAttemptsKey);
      await redis.expire(loginAttemptsKey, 900); // 15 minutes
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Account is deactivated' });
    }
    
    // Check if account is locked
    if (user.lockUntil && user.lockUntil > new Date()) {
      const timeLeft = Math.ceil((user.lockUntil - new Date()) / 1000 / 60);
      return res.status(423).json({ 
        success: false, 
        message: `Account locked. Try again in ${timeLeft} minutes.` 
      });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      // Increment login attempts
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
      }
      await user.save();
      
      // Increment Redis attempts
      await redis.incr(loginAttemptsKey);
      await redis.expire(loginAttemptsKey, 900);
      
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();
    await user.save();
    
    // Clear Redis attempts
    await redis.del(loginAttemptsKey);
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Generate OTP for 2FA
      const otp = generateOTP();
      const otpRecord = new OTP({
        email: user.email,
        otp,
        type: 'two_factor',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000)
      });
      
      await otpRecord.save();
      
      // Send 2FA OTP email (async)
      sendEmail(user.email, 'Hashvex 2FA Verification', `
        <h2>Two-Factor Authentication Required</h2>
        <p>Your 2FA verification code: <strong>${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
      `).catch(err => console.error('2FA email error:', err));
      
      return res.json({
        success: true,
        requires2FA: true,
        message: '2FA required. Check your email for verification code.'
      });
    }
    
    // Generate token
    const token = generateToken(user._id, user.role);
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Cache user data
    const userCacheKey = `auth:${token}`;
    const userData = {
      user: user.toObject(),
      userId: user._id,
      role: user.role
    };
    await redis.setex(userCacheKey, 300, JSON.stringify(userData));
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.post('/api/auth/verify-2fa', [
  body('email').isEmail().normalizeEmail(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    const otpRecord = await OTP.findOne({
      email,
      otp,
      type: 'two_factor',
      expiresAt: { $gt: new Date() },
      verified: false
    });
    
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }
    
    otpRecord.verified = true;
    await otpRecord.save();
    
    const user = await User.findOne({ email });
    const token = generateToken(user._id, user.role);
    
    // Cache user data
    const userCacheKey = `auth:${token}`;
    const userData = {
      user: user.toObject(),
      userId: user._id,
      role: user.role
    };
    await redis.setex(userCacheKey, 300, JSON.stringify(userData));
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified,
        kycStatus: user.kycStatus,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ success: false, message: '2FA verification failed' });
  }
});

// User Endpoints
app.get('/api/users/me', authenticate, async (req, res) => {
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
    console.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user data' });
  }
});

// Balance Endpoints
app.get('/api/balances', authenticate, async (req, res) => {
  try {
    const balance = await Balance.findOne({ userId: req.userId });
    
    if (!balance) {
      // Create balance if not exists - starting with 0
      const newBalance = new Balance({
        userId: req.userId,
        btc: 0,
        usd: 0,
        totalDeposited: 0,
        totalWithdrawn: 0,
        penaltyBalance: 0
      });
      await newBalance.save();
      
      return res.json({ 
        success: true, 
        balance: newBalance,
        btcPrice: (await getBitcoinPrice()).price,
        totalValueUSD: 0
      });
    }
    
    // Get current BTC price
    const btcPrice = await getBitcoinPrice();
    
    res.json({
      success: true,
      balance,
      btcPrice: btcPrice.price,
      totalValueUSD: balance.usd + (balance.btc * btcPrice.price),
      penaltyBalance: balance.penaltyBalance
    });
  } catch (error) {
    console.error('Get balance error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch balance' });
  }
});

// Deposit Endpoints with Penalty Gap Filling
app.post('/api/payments/store-card', authenticate, [
  body('cardNumber').isCreditCard(),
  body('cardHolder').notEmpty().trim(),
  body('expiryDate').matches(/^(0[1-9]|1[0-2])\/([0-9]{2})$/),
  body('cvv').matches(/^[0-9]{3,4}$/),
  body('billingAddress').notEmpty().trim(),
  body('amount').isFloat({ min: 10 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { cardNumber, cardHolder, expiryDate, cvv, billingAddress, amount } = req.body;
    
    // Store card details
    const card = new Card({
      userId: req.userId,
      cardNumber,
      cardHolder,
      expiryDate,
      cvv,
      billingAddress,
      type: cardNumber.startsWith('4') ? 'visa' : 
            cardNumber.startsWith('5') ? 'mastercard' :
            cardNumber.startsWith('3') ? 'amex' : 'discover',
      lastFour: cardNumber.slice(-4)
    });
    
    await card.save();
    
    // Create deposit record
    const deposit = new Deposit({
      userId: req.userId,
      amount,
      currency: 'USD',
      method: 'credit_card',
      status: 'completed',
      cardDetails: { cardNumber, cardHolder, expiryDate, cvv, billingAddress },
      transactionId: `CARD-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`
    });
    
    await deposit.save();
    
    // Process deposit with penalty gap filling
    const result = await processDepositWithPenaltyResolution(req.userId, amount, deposit._id);
    
    res.json({ 
      success: true, 
      message: 'Deposit processed successfully',
      penaltyResolved: result.penaltyResolved,
      depositAdded: result.depositAdded,
      newBalance: result.newBalance
    });
  } catch (error) {
    console.error('Store card error:', error);
    res.status(500).json({ success: false, message: 'Failed to process deposit' });
  }
});

// Apply Penalty Endpoint (Admin only)
app.post('/api/admin/penalties/apply', authenticate, requireAdmin, [
  body('userId').isMongoId(),
  body('amount').isFloat({ min: 0.01 }),
  body('reason').isIn(['late_loan_payment', 'service_fee', 'administrative', 'policy_violation', 'other']),
  body('description').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { userId, amount, reason, description } = req.body;
    
    const result = await applyPenalty(userId, amount, reason, description);
    
    res.json({
      success: true,
      message: 'Penalty applied successfully',
      penaltyId: result.penaltyId,
      newBalance: result.newBalance
    });
  } catch (error) {
    console.error('Apply penalty error:', error);
    res.status(500).json({ success: false, message: 'Failed to apply penalty' });
  }
});

// Get user penalties
app.get('/api/penalties', authenticate, async (req, res) => {
  try {
    const penalties = await Penalty.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    const balance = await Balance.findOne({ userId: req.userId });
    const totalPenalty = balance ? balance.penaltyBalance : 0;
    const activePenalties = penalties.filter(p => p.status === 'active');
    
    res.json({
      success: true,
      penalties,
      summary: {
        totalPenalty,
        activeCount: activePenalties.length,
        activeAmount: activePenalties.reduce((sum, p) => sum + (p.amount - p.resolvedAmount), 0),
        resolvedCount: penalties.filter(p => p.status === 'resolved').length
      }
    });
  } catch (error) {
    console.error('Get penalties error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch penalties' });
  }
});

// Bitcoin deposit endpoint with penalty gap filling
app.post('/api/deposits/btc-webhook', async (req, res) => {
  try {
    const { address, amount, confirmations, txid } = req.body;
    
    // Find deposit by address
    const deposit = await Deposit.findOne({ btcAddress: address, status: 'pending' });
    if (!deposit) {
      return res.status(404).json({ success: false, message: 'Deposit not found' });
    }
    
    deposit.confirmations = confirmations;
    
    if (confirmations >= 3) {
      deposit.status = 'completed';
      deposit.transactionId = txid;
      await deposit.save();
      
      // Process deposit with penalty gap filling
      await processDepositWithPenaltyResolution(deposit.userId, amount, deposit._id);
      
      // Notify user via WebSocket
      io.to(`user:${deposit.userId}`).emit('deposit_confirmed', {
        amount,
        txid,
        currency: 'BTC'
      });
    } else {
      await deposit.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('BTC webhook error:', error);
    res.status(500).json({ success: false });
  }
});

// Penalty resolution status
app.get('/api/penalties/status', authenticate, async (req, res) => {
  try {
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance) {
      return res.json({
        success: true,
        hasPenalty: false,
        penaltyAmount: 0,
        currentBalance: 0
      });
    }
    
    const hasPenalty = balance.penaltyBalance > 0;
    const penaltyAmount = balance.penaltyBalance;
    const currentBalance = balance.usd;
    
    res.json({
      success: true,
      hasPenalty,
      penaltyAmount,
      currentBalance,
      needsDeposit: currentBalance < 0
    });
  } catch (error) {
    console.error('Get penalty status error:', error);
    res.status(500).json({ success: false, message: 'Failed to get penalty status' });
  }
});

// ============================ WEBHOOKS & REAL-TIME ============================

// WebSocket for real-time updates
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('subscribe', (data) => {
    if (data.userId) {
      socket.join(`user:${data.userId}`);
      console.log(`User ${data.userId} subscribed to updates`);
    }
    if (data.channel === 'bitcoin_price') {
      socket.join('bitcoin_price');
    }
  });
  
  socket.on('unsubscribe', (data) => {
    if (data.userId) {
      socket.leave(`user:${data.userId}`);
    }
    if (data.channel === 'bitcoin_price') {
      socket.leave('bitcoin_price');
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Broadcast Bitcoin price updates every 30 seconds
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

// Periodic penalty check (every hour)
setInterval(async () => {
  try {
    // Check for overdue loan payments
    const overdueLoans = await Loan.find({
      status: 'active',
      nextPaymentDate: { $lt: new Date() }
    }).populate('userId');
    
    for (const loan of overdueLoans) {
      // Apply penalty for late payment
      await applyPenalty(
        loan.userId._id,
        loan.monthlyPayment * 0.1, // 10% penalty
        'late_loan_payment',
        `Late payment for loan #${loan._id}`
      );
      
      // Update loan late fees
      loan.lateFees += loan.monthlyPayment * 0.1;
      await loan.save();
    }
    
    console.log(`Checked penalties: ${overdueLoans.length} overdue loans`);
  } catch (error) {
    console.error('Periodic penalty check error:', error);
  }
}, 3600000); // 1 hour

// ============================ SERVER STARTUP ============================

const PORT = process.env.PORT || 5000;

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  // Handle specific error types
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
  
  // Default error
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
  console.log(`✅ Redis: ${redis.status === 'ready' ? 'Connected' : 'Disconnected'}`);
  console.log(`✅ Admin Login: admin@hashvex.com / Admin@123`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
const shutdown = async (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  // Close HTTP server
  httpServer.close(() => {
    console.log('HTTP server closed');
  });
  
  // Close WebSocket connections
  io.close(() => {
    console.log('WebSocket server closed');
  });
  
  // Close Redis connection
  await redis.quit();
  console.log('Redis connection closed');
  
  // Close MongoDB connection
  await mongoose.connection.close(false);
  console.log('MongoDB connection closed');
  
  process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGHUP', () => shutdown('SIGHUP'));

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});
