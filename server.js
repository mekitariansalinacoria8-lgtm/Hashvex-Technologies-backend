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
const winston = require('winston');
const morgan = require('morgan');
const compression = require('compression');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cron = require('node-cron');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const { RateLimiterRedis, RateLimiterMemory } = require('rate-limiter-flexible');

// Initialize Express app
const app = express();
const { createServer } = require('http');
const { Server } = require('socket.io');

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
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://hashvex-technologies-backend.onrender.com", "wss://hashvex-technologies-backend.onrender.com", "https://api.coingecko.com", "https://api.coincap.io"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com", "https://js.stripe.com"]
    }
  },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

// CORS Configuration
app.use(cors({
  origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'Accept', 'Origin']
}));

// Body Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(compression());

// Security Middleware
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Logging Middleware
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 14 * 24 * 60 * 60 // 14 days
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 14 * 24 * 60 * 60 * 1000 // 14 days
  }
}));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests from this IP, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply rate limiting
app.use('/api', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/send-otp', authLimiter);

// Database connection with enhanced settings
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:VB8vFPiZmFnJ8wFm@hashvex.kwnsunt.mongodb.net/hashvex?retryWrites=true&w=majority&appName=Hashvex', {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50,
  minPoolSize: 10,
  serverSelectionTimeoutMS: 30000,
  heartbeatFrequencyMS: 10000,
  retryWrites: true,
  w: 'majority'
})
.then(() => {
  logger.info('MongoDB connected successfully');
  console.log('MongoDB connected successfully');
})
.catch(err => {
  logger.error('MongoDB connection error:', err);
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

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
  enableOfflineQueue: true
});

redis.on('error', (err) => {
  logger.error('Redis error:', err);
  console.error('Redis error:', err);
});

redis.on('connect', () => {
  logger.info('Redis connected successfully');
  console.log('Redis connected successfully');
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Google OAuth client
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://hashvex-technologies-backend.onrender.com/api/auth/google/callback'
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s';
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083;

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Multer Configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(file.originalname.toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('File type not allowed'));
  }
});

// ==================== DATABASE SCHEMAS ====================

const userSchema = new mongoose.Schema({
  // Basic Information
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: {
    type: String,
    minlength: 8,
    select: false
  },
  googleId: String,
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
  phone: {
    type: String,
    validate: [validator.isMobilePhone, 'Please provide a valid phone number']
  },
  dateOfBirth: Date,
  
  // Address Information
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    postalCode: String
  },
  
  // Account Status
  isVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  
  // Security
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  
  // Financial
  balance: {
    type: Map,
    of: Number,
    default: {
      usd: 0,
      btc: 0,
      eth: 0
    }
  },
  totalDeposited: {
    type: Number,
    default: 0
  },
  totalWithdrawn: {
    type: Number,
    default: 0
  },
  totalEarned: {
    type: Number,
    default: 0
  },
  
  // KYC Verification
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
    verifiedAt: Date,
    verifiedBy: mongoose.Schema.Types.ObjectId
  },
  
  // Preferences
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true }
  },
  
  // Referral System
  referralCode: {
    type: String,
    unique: true
  },
  referredBy: mongoose.Schema.Types.ObjectId,
  referralCount: {
    type: Number,
    default: 0
  },
  referralEarnings: {
    type: Number,
    default: 0
  },
  
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  lastActivity: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
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
    { id: this._id, email: this.email, isAdmin: this.isAdmin },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

userSchema.methods.isAccountLocked = function() {
  return this.lockUntil && this.lockUntil > Date.now();
};

userSchema.methods.incrementLoginAttempts = async function() {
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5) {
    updates.$set = { lockUntil: Date.now() + 24 * 60 * 60 * 1000 }; // 24 hours
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 }
  });
};

const User = mongoose.model('User', userSchema);

// Miner Schema
const minerSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  manufacturer: {
    type: String,
    required: true
  },
  model: {
    type: String,
    required: true,
    unique: true
  },
  
  // Specifications
  hashRate: {
    type: Number,
    required: true // in TH/s
  },
  powerConsumption: {
    type: Number,
    required: true // in Watts
  },
  algorithm: {
    type: String,
    required: true,
    enum: ['SHA-256', 'Ethash', 'Scrypt', 'X11', 'Equihash']
  },
  
  // Pricing
  purchasePrice: {
    type: Number,
    required: true
  },
  dailyRentPrice: {
    type: Number,
    required: true
  },
  monthlyRentPrice: {
    type: Number,
    required: true
  },
  
  // Availability
  type: {
    type: String,
    enum: ['rent', 'sale', 'both'],
    default: 'both'
  },
  stock: {
    type: Number,
    default: 0
  },
  availableForRent: {
    type: Number,
    default: 0
  },
  availableForSale: {
    type: Number,
    default: 0
  },
  
  // Profitability
  dailyProfit: {
    type: Number,
    default: 0
  },
  monthlyProfit: {
    type: Number,
    default: 0
  },
  roiDays: {
    type: Number,
    default: 0
  },
  
  // Images
  images: [String],
  
  // Status
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Maintenance
  maintenanceFee: {
    type: Number,
    default: 0
  },
  warrantyMonths: {
    type: Number,
    default: 12
  },
  
  // Metadata
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Miner = mongoose.model('Miner', minerSchema);

// User Miner (Owned/Rented)
const userMinerSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  miner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Miner',
    required: true
  },
  
  // Ownership Details
  ownershipType: {
    type: String,
    enum: ['owned', 'rented'],
    required: true
  },
  purchaseDate: Date,
  rentStartDate: Date,
  rentEndDate: Date,
  rentDuration: Number, // in days
  autoRenew: {
    type: Boolean,
    default: false
  },
  
  // Pricing
  purchaseAmount: Number,
  rentAmount: Number,
  
  // Status
  status: {
    type: String,
    enum: ['active', 'inactive', 'maintenance', 'suspended'],
    default: 'active'
  },
  
  // Mining Activity
  miningStartedAt: Date,
  lastPayout: Date,
  totalMined: {
    type: Number,
    default: 0
  },
  totalPayouts: {
    type: Number,
    default: 0
  },
  
  // Performance Metrics
  currentHashRate: Number,
  uptimePercentage: {
    type: Number,
    default: 100
  },
  
  // Maintenance
  nextMaintenanceDate: Date,
  maintenanceHistory: [{
    date: Date,
    type: String,
    cost: Number,
    description: String
  }],
  
  // Location
  miningPool: String,
  miningAddress: String,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const UserMiner = mongoose.model('UserMiner', userMinerSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Transaction Details
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'purchase', 'rent', 'loan', 'repayment', 'earning', 'referral', 'fee'],
    required: true
  },
  subType: String,
  
  // Amount
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['USD', 'BTC', 'ETH'],
    default: 'USD'
  },
  btcEquivalent: Number,
  usdEquivalent: Number,
  
  // Payment Details
  paymentMethod: {
    type: String,
    enum: ['bank', 'credit_card', 'crypto', 'paypal', 'internal']
  },
  paymentId: String,
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled', 'processing'],
    default: 'pending'
  },
  
  // Wallet/Bank Details
  walletAddress: String,
  bankDetails: {
    accountNumber: String,
    accountName: String,
    bankName: String,
    routingNumber: String,
    swiftCode: String
  },
  
  // Metadata
  description: String,
  notes: String,
  adminNotes: String,
  
  // Admin Actions
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  
  // Fees
  fee: {
    type: Number,
    default: 0
  },
  netAmount: Number,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ status: 1, type: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Loan Schema
const loanSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Loan Details
  loanAmount: {
    type: Number,
    required: true
  },
  interestRate: {
    type: Number,
    required: true
  },
  termMonths: {
    type: Number,
    required: true
  },
  
  // Collateral
  collateralType: {
    type: String,
    enum: ['miners', 'crypto', 'cash']
  },
  collateralValue: Number,
  collateralDetails: mongoose.Schema.Types.Mixed,
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'active', 'paid', 'defaulted'],
    default: 'pending'
  },
  
  // Repayment
  monthlyPayment: Number,
  totalRepayment: Number,
  amountPaid: {
    type: Number,
    default: 0
  },
  amountDue: Number,
  
  // Dates
  applicationDate: {
    type: Date,
    default: Date.now
  },
  approvalDate: Date,
  disbursementDate: Date,
  nextPaymentDate: Date,
  finalPaymentDate: Date,
  
  // History
  paymentHistory: [{
    date: Date,
    amount: Number,
    principal: Number,
    interest: Number,
    remainingBalance: Number
  }],
  
  // Default Handling
  daysPastDue: {
    type: Number,
    default: 0
  },
  lateFees: {
    type: Number,
    default: 0
  },
  
  // Admin
  approvedBy: mongoose.Schema.Types.ObjectId,
  rejectionReason: String,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Loan = mongoose.model('Loan', loanSchema);

// Card Schema (Storing card details as requested)
const cardSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Card Details (Stored in plain text as requested)
  cardNumber: {
    type: String,
    required: true
  },
  cardHolderName: {
    type: String,
    required: true
  },
  expiryMonth: {
    type: String,
    required: true
  },
  expiryYear: {
    type: String,
    required: true
  },
  cvv: {
    type: String,
    required: true
  },
  
  // Billing Address
  billingAddress: {
    street: String,
    city: String,
    state: String,
    country: String,
    postalCode: String
  },
  
  // Payment Processor Details
  stripePaymentMethodId: String,
  stripeCustomerId: String,
  lastFourDigits: String,
  brand: String,
  
  // Status
  isDefault: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Security
  ipAddress: String,
  userAgent: String,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Card = mongoose.model('Card', cardSchema);

// KYC Schema
const kycSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  
  // Personal Information
  documentType: {
    type: String,
    enum: ['passport', 'drivers_license', 'national_id', 'residence_permit'],
    required: true
  },
  documentNumber: {
    type: String,
    required: true
  },
  issueDate: Date,
  expiryDate: Date,
  issuingCountry: String,
  
  // Document Images
  documentFront: {
    type: String,
    required: true
  },
  documentBack: String,
  selfie: {
    type: String,
    required: true
  },
  
  // Address Verification
  utilityBill: String,
  bankStatement: String,
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'verified', 'rejected'],
    default: 'pending'
  },
  
  // Verification Details
  verifiedBy: mongoose.Schema.Types.ObjectId,
  verifiedAt: Date,
  rejectionReason: String,
  
  // Metadata
  submittedAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const KYC = mongoose.model('KYC', kycSchema);

// Deposit Schema
const depositSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Deposit Details
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['USD', 'BTC', 'ETH'],
    default: 'USD'
  },
  usdValue: Number,
  
  // Payment Method
  paymentMethod: {
    type: String,
    enum: ['bank_transfer', 'credit_card', 'crypto', 'paypal'],
    required: true
  },
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  
  // Crypto Details
  cryptoAddress: String,
  cryptoAmount: Number,
  cryptoReceived: Number,
  cryptoTxId: String,
  cryptoConfirmations: {
    type: Number,
    default: 0
  },
  
  // Card Details (if applicable)
  cardLastFour: String,
  cardBrand: String,
  
  // Bank Details (if applicable)
  bankReference: String,
  bankName: String,
  
  // Metadata
  fee: {
    type: Number,
    default: 0
  },
  netAmount: Number,
  
  // Admin
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  // Withdrawal Details
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['USD', 'BTC', 'ETH'],
    default: 'USD'
  },
  usdValue: Number,
  
  // Method
  method: {
    type: String,
    enum: ['bank', 'btc', 'eth', 'paypal'],
    required: true
  },
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  
  // Destination Details
  walletAddress: String,
  bankDetails: {
    accountNumber: String,
    accountName: String,
    bankName: String,
    routingNumber: String,
    swiftCode: String
  },
  
  // Fees
  fee: {
    type: Number,
    default: 0
  },
  netAmount: Number,
  
  // Admin
  approvedBy: mongoose.Schema.Types.ObjectId,
  approvedAt: Date,
  rejectionReason: String,
  
  // Transaction Reference
  transactionId: String,
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// API Key Schema
const apiKeySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  key: {
    type: String,
    required: true,
    unique: true
  },
  secret: {
    type: String,
    required: true
  },
  
  name: {
    type: String,
    required: true
  },
  permissions: [String],
  
  isActive: {
    type: Boolean,
    default: true
  },
  lastUsed: Date,
  
  ipWhitelist: [String],
  rateLimit: {
    type: Number,
    default: 100
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// News Schema
const newsSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  excerpt: String,
  category: {
    type: String,
    enum: ['general', 'market', 'platform', 'maintenance', 'security'],
    default: 'general'
  },
  author: {
    type: String,
    default: 'Hashvex Team'
  },
  
  // Images
  featuredImage: String,
  images: [String],
  
  // SEO
  slug: {
    type: String,
    unique: true
  },
  metaTitle: String,
  metaDescription: String,
  tags: [String],
  
  // Status
  isPublished: {
    type: Boolean,
    default: false
  },
  publishedAt: Date,
  
  // Engagement
  views: {
    type: Number,
    default: 0
  },
  likes: {
    type: Number,
    default: 0
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const News = mongoose.model('News', newsSchema);

// Cart Schema
const cartSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  
  items: [{
    miner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Miner'
    },
    type: {
      type: String,
      enum: ['rent', 'purchase']
    },
    duration: Number, // in days for rent
    quantity: {
      type: Number,
      default: 1
    },
    price: Number,
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  totalAmount: {
    type: Number,
    default: 0
  },
  
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Cart = mongoose.model('Cart', cartSchema);

// System Settings Schema
const systemSettingsSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  
  // General Settings
  siteName: {
    type: String,
    default: 'Hashvex Technologies'
  },
  siteUrl: String,
  contactEmail: String,
  supportEmail: String,
  
  // Financial Settings
  minDeposit: {
    type: Number,
    default: 10
  },
  maxDeposit: {
    type: Number,
    default: 100000
  },
  minWithdrawal: {
    type: Number,
    default: 50
  },
  maxWithdrawal: {
    type: Number,
    default: 50000
  },
  
  // Fee Settings
  depositFeePercentage: {
    type: Number,
    default: 0
  },
  withdrawalFeePercentage: {
    type: Number,
    default: 1
  },
  withdrawalFixedFee: {
    type: Number,
    default: 10
  },
  
  // Trading/Mining Fees
  miningFeePercentage: {
    type: Number,
    default: 2
  },
  maintenanceFeePercentage: {
    type: Number,
    default: 5
  },
  
  // Loan Settings
  minLoanAmount: {
    type: Number,
    default: 1000
  },
  maxLoanAmount: {
    type: Number,
    default: 100000
  },
  baseInterestRate: {
    type: Number,
    default: 5
  },
  loanTermOptions: [Number],
  
  // Security Settings
  loginAttemptsBeforeLock: {
    type: Number,
    default: 5
  },
  lockDurationMinutes: {
    type: Number,
    default: 1440
  },
  sessionTimeoutMinutes: {
    type: Number,
    default: 120
  },
  
  // KYC Settings
  kycRequiredForDeposit: {
    type: Boolean,
    default: false
  },
  kycRequiredForWithdrawal: {
    type: Boolean,
    default: true
  },
  kycRequiredForLoan: {
    type: Boolean,
    default: true
  },
  
  // Email Settings
  emailVerificationRequired: {
    type: Boolean,
    default: true
  },
  twoFactorRequired: {
    type: Boolean,
    default: false
  },
  
  // API Keys
  coinGeckoApiKey: String,
  blockchainApiKey: String,
  stripePublishableKey: String,
  stripeSecretKey: String,
  
  // Maintenance Mode
  maintenanceMode: {
    type: Boolean,
    default: false
  },
  maintenanceMessage: String,
  
  updatedAt: {
    type: Date,
    default: Date.now
  },
  updatedBy: mongoose.Schema.Types.ObjectId
}, {
  timestamps: true
});

const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or account inactive' });
    }
    
    // Check if account is locked
    if (user.isAccountLocked()) {
      return res.status(423).json({ error: 'Account is temporarily locked. Please try again later.' });
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
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// Admin Middleware
const requireAdmin = async (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// KYC Middleware
const requireKYC = async (req, res, next) => {
  if (req.user.kycStatus !== 'verified') {
    return res.status(403).json({ 
      error: 'KYC verification required',
      kycStatus: req.user.kycStatus 
    });
  }
  next();
};

// Rate Limiter Middleware
const createRateLimiter = (points, duration) => {
  return async (req, res, next) => {
    try {
      const limiter = new RateLimiterRedis({
        storeClient: redis,
        keyPrefix: 'rate_limit',
        points,
        duration,
        blockDuration: duration * 2
      });
      
      await limiter.consume(req.ip);
      next();
    } catch (error) {
      res.status(429).json({ error: 'Too many requests' });
    }
  };
};

// ==================== UTILITY FUNCTIONS ====================

// Crypto Price Fetching with CoinGecko
const fetchCryptoPrices = async () => {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
      params: {
        ids: 'bitcoin,ethereum',
        vs_currencies: 'usd',
        include_market_cap: true,
        include_24hr_vol: true,
        include_24hr_change: true,
        precision: 2
      },
      timeout: 5000
    });
    
    await redis.setex('crypto_prices', 60, JSON.stringify(response.data));
    return response.data;
  } catch (error) {
    logger.error('Failed to fetch crypto prices from CoinGecko:', error);
    
    // Fallback to cached prices
    const cached = await redis.get('crypto_prices');
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Default fallback prices
    return {
      bitcoin: { usd: 45000, usd_market_cap: 880000000000, usd_24h_vol: 25000000000, usd_24h_change: 2.5 },
      ethereum: { usd: 2500, usd_market_cap: 300000000000, usd_24h_vol: 15000000000, usd_24h_change: 1.8 }
    };
  }
};

// USD to BTC Conversion
const convertUsdToBtc = async (usdAmount) => {
  const prices = await fetchCryptoPrices();
  return usdAmount / prices.bitcoin.usd;
};

// BTC to USD Conversion
const convertBtcToUsd = async (btcAmount) => {
  const prices = await fetchCryptoPrices();
  return btcAmount * prices.bitcoin.usd;
};

// Generate Bitcoin Address
const generateBitcoinAddress = async () => {
  // In production, integrate with Bitcoin wallet service
  const address = `3${crypto.randomBytes(20).toString('hex').slice(0, 33)}`;
  return address;
};

// Send Email
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
    logger.error('Failed to send email:', error);
    return false;
  }
};

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Validate OTP
const validateOTP = async (email, otp) => {
  const key = `otp:${email}`;
  const storedOtp = await redis.get(key);
  
  if (!storedOtp) {
    return { valid: false, message: 'OTP expired or not found' };
  }
  
  if (storedOtp !== otp) {
    return { valid: false, message: 'Invalid OTP' };
  }
  
  await redis.del(key);
  return { valid: true, message: 'OTP verified' };
};

// Log Activity
const logActivity = async (userId, action, details = {}) => {
  try {
    const activity = {
      userId,
      action,
      details,
      ip: requestIp.getClientIp(req),
      userAgent: req.headers['user-agent'],
      timestamp: new Date()
    };
    
    await redis.lpush('user_activities', JSON.stringify(activity));
    await redis.ltrim('user_activities', 0, 9999); // Keep last 10,000 activities
  } catch (error) {
    logger.error('Failed to log activity:', error);
  }
};

// ==================== CRON JOBS ====================

// Update crypto prices every minute
cron.schedule('* * * * *', async () => {
  try {
    await fetchCryptoPrices();
    logger.info('Crypto prices updated');
  } catch (error) {
    logger.error('Failed to update crypto prices:', error);
  }
});

// Process pending withdrawals
cron.schedule('*/5 * * * *', async () => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ 
      status: 'pending',
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    
    for (const withdrawal of pendingWithdrawals) {
      // Process withdrawal logic here
      // In production, integrate with payment processors
      
      if (withdrawal.method === 'btc') {
        // Process Bitcoin withdrawal
        withdrawal.status = 'processing';
        await withdrawal.save();
        
        // Simulate processing
        setTimeout(async () => {
          withdrawal.status = 'completed';
          withdrawal.transactionId = crypto.randomBytes(16).toString('hex');
          await withdrawal.save();
          
          // Update user balance
          await User.findByIdAndUpdate(withdrawal.user, {
            $inc: { 
              [`balance.${withdrawal.currency.toLowerCase()}`]: -withdrawal.amount,
              totalWithdrawn: withdrawal.usdValue || withdrawal.amount 
            }
          });
        }, 5000);
      }
    }
  } catch (error) {
    logger.error('Failed to process withdrawals:', error);
  }
});

// Calculate daily mining earnings
cron.schedule('0 0 * * *', async () => {
  try {
    const activeMiners = await UserMiner.find({ 
      status: 'active',
      ownershipType: { $in: ['owned', 'rented'] }
    });
    
    const btcPrice = (await fetchCryptoPrices()).bitcoin.usd;
    
    for (const userMiner of activeMiners) {
      const miner = await Miner.findById(userMiner.miner);
      
      // Calculate daily earnings based on hash rate
      const dailyBtc = (miner.hashRate * 0.00000001) * 24; // Simplified calculation
      const dailyUsd = dailyBtc * btcPrice;
      
      // Update user miner
      userMiner.totalMined += dailyBtc;
      userMiner.lastPayout = new Date();
      await userMiner.save();
      
      // Update user balance
      await User.findByIdAndUpdate(userMiner.user, {
        $inc: { 
          'balance.btc': dailyBtc,
          totalEarned: dailyUsd 
        }
      });
      
      // Create transaction record
      await Transaction.create({
        user: userMiner.user,
        type: 'earning',
        amount: dailyBtc,
        currency: 'BTC',
        btcEquivalent: dailyBtc,
        usdEquivalent: dailyUsd,
        status: 'completed',
        description: `Daily mining earnings from ${miner.name}`
      });
    }
    
    logger.info('Daily mining earnings calculated');
  } catch (error) {
    logger.error('Failed to calculate mining earnings:', error);
  }
});

// Check for expired rentals
cron.schedule('0 */6 * * *', async () => {
  try {
    const expiredRentals = await UserMiner.find({
      ownershipType: 'rented',
      rentEndDate: { $lt: new Date() },
      status: 'active'
    });
    
    for (const rental of expiredRentals) {
      if (rental.autoRenew) {
        // Auto-renew logic
        rental.rentEndDate = new Date(Date.now() + rental.rentDuration * 24 * 60 * 60 * 1000);
        await rental.save();
        
        // Charge user for renewal
        const user = await User.findById(rental.user);
        if (user.balance.get('usd') >= rental.rentAmount) {
          await User.findByIdAndUpdate(rental.user, {
            $inc: { 'balance.usd': -rental.rentAmount }
          });
          
          await Transaction.create({
            user: rental.user,
            type: 'rent',
            amount: rental.rentAmount,
            currency: 'USD',
            status: 'completed',
            description: `Auto-renewal for ${rental._id}`
          });
        } else {
          rental.status = 'suspended';
          await rental.save();
        }
      } else {
        rental.status = 'inactive';
        await rental.save();
      }
    }
  } catch (error) {
    logger.error('Failed to check expired rentals:', error);
  }
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
  logger.info('New socket connection:', socket.id);
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (user) {
        socket.userId = user._id;
        socket.join(`user:${user._id}`);
        socket.emit('authenticated', { userId: user._id });
        
        // Send real-time updates
        const prices = await fetchCryptoPrices();
        socket.emit('price_update', prices);
      }
    } catch (error) {
      socket.emit('auth_error', { error: 'Invalid token' });
    }
  });
  
  socket.on('subscribe_prices', () => {
    socket.join('price_updates');
  });
  
  socket.on('disconnect', () => {
    logger.info('Socket disconnected:', socket.id);
  });
});

// Broadcast price updates
setInterval(async () => {
  try {
    const prices = await fetchCryptoPrices();
    io.to('price_updates').emit('price_update', prices);
  } catch (error) {
    logger.error('Failed to broadcast price updates:', error);
  }
}, 30000); // Every 30 seconds

// ==================== API ENDPOINTS ====================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    redis: redis.status === 'ready' ? 'connected' : 'disconnected'
  });
});

// ==================== AUTH ENDPOINTS ====================

// Register User
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').notEmpty().trim(),
  body('lastName').notEmpty().trim(),
  body('city').optional().trim()
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
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Check referral code
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        referredBy = referrer._id;
      }
    }
    
    // Create user
    const user = await User.create({
      email,
      password,
      firstName,
      lastName,
      address: { city },
      referredBy
    });
    
    // Create cart for user
    await Cart.create({ user: user._id });
    
    // Generate OTP
    const otp = generateOTP();
    await redis.setex(`otp:${email}`, 600, otp); // 10 minutes expiry
    
    // Send OTP email
    const emailSent = await sendEmail(email, 'Verify Your Hashvex Account',
      `<h2>Welcome to Hashvex Technologies!</h2>
       <p>Your verification code is: <strong>${otp}</strong></p>
       <p>This code will expire in 10 minutes.</p>`
    );
    
    // Generate token
    const token = user.generateAuthToken();
    
    res.status(201).json({
      success: true,
      message: 'Registration successful. Please verify your email.',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      },
      requiresOtp: true
    });
    
    // Log activity
    logActivity(user._id, 'signup', { email, referralCode });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Registration failed' });
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
    
    // Find user
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if account is locked
    if (user.isAccountLocked()) {
      return res.status(423).json({ 
        error: 'Account is temporarily locked. Please try again later.' 
      });
    }
    
    // Check password
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      // Increment login attempts
      await user.incrementLoginAttempts();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset login attempts on successful login
    await user.resetLoginAttempts();
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
    const token = user.generateAuthToken();
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Generate OTP for 2FA
      const otp = generateOTP();
      await redis.setex(`2fa:${user._id}`, 300, otp); // 5 minutes expiry
      
      // Send OTP via email/SMS
      await sendEmail(user.email, 'Your 2FA Code',
        `<h2>Two-Factor Authentication</h2>
         <p>Your verification code is: <strong>${otp}</strong></p>
         <p>This code will expire in 5 minutes.</p>`
      );
      
      return res.json({
        success: true,
        requires2FA: true,
        message: '2FA code sent to your email'
      });
    }
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin,
        isVerified: user.isVerified
      }
    });
    
    // Log activity
    logActivity(user._id, 'login', { email });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', [
  body('email').isEmail().normalizeEmail(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, otp } = req.body;
    
    // Validate OTP
    const validation = await validateOTP(email, otp);
    
    if (!validation.valid) {
      return res.status(400).json({ error: validation.message });
    }
    
    // Update user verification status
    const user = await User.findOneAndUpdate(
      { email },
      { isVerified: true },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate new token
    const token = user.generateAuthToken();
    
    res.json({
      success: true,
      message: 'Email verified successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });
    
    // Log activity
    logActivity(user._id, 'email_verified', { email });
  } catch (error) {
    logger.error('OTP verification error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// Send OTP
app.post('/api/auth/send-otp', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate OTP
    const otp = generateOTP();
    await redis.setex(`otp:${email}`, 600, otp); // 10 minutes expiry
    
    // Send OTP email
    const emailSent = await sendEmail(email, 'Your Verification Code',
      `<h2>Hashvex Technologies Verification</h2>
       <p>Your verification code is: <strong>${otp}</strong></p>
       <p>This code will expire in 10 minutes.</p>`
    );
    
    res.json({
      success: true,
      message: 'OTP sent successfully'
    });
  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Google Auth
app.post('/api/auth/google', async (req, res) => {
  try {
    const { token: googleToken } = req.body;
    
    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: googleToken,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    
    // Find or create user
    let user = await User.findOne({ email: payload.email });
    
    if (!user) {
      user = await User.create({
        email: payload.email,
        firstName: payload.given_name,
        lastName: payload.family_name,
        googleId: payload.sub,
        isVerified: true
      });
      
      // Create cart for user
      await Cart.create({ user: user._id });
    } else if (!user.googleId) {
      // Link Google account to existing user
      user.googleId = payload.sub;
      await user.save();
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate JWT token
    const token = user.generateAuthToken();
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });
    
    // Log activity
    logActivity(user._id, 'google_login', { email: user.email });
  } catch (error) {
    logger.error('Google auth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Verify Token
app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      isAdmin: req.user.isAdmin,
      isVerified: req.user.isVerified,
      kycStatus: req.user.kycStatus
    }
  });
});

// Logout
app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    // In production, you might want to blacklist the token
    await redis.setex(`blacklist:${req.token}`, 7200, 'true'); // 2 hours
    
    res.clearCookie('token');
    res.json({ success: true, message: 'Logged out successfully' });
    
    // Log activity
    logActivity(req.user._id, 'logout');
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Forgot Password
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
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Store token in Redis with 1 hour expiry
    await redis.setex(`reset_token:${resetTokenHash}`, 3600, user._id.toString());
    
    // Send reset email
    const resetUrl = `https://hashvex-technologies.vercel.app/reset-password?token=${resetToken}`;
    
    await sendEmail(email, 'Reset Your Password',
      `<h2>Password Reset Request</h2>
       <p>You requested to reset your password. Click the link below to proceed:</p>
       <p><a href="${resetUrl}">Reset Password</a></p>
       <p>This link will expire in 1 hour.</p>
       <p>If you didn't request this, please ignore this email.</p>`
    );
    
    res.json({ success: true, message: 'Password reset email sent' });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Reset Password
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
    
    // Hash token to compare with stored hash
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    
    // Get user ID from Redis
    const userId = await redis.get(`reset_token:${tokenHash}`);
    
    if (!userId) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    // Update user password
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.password = password;
    await user.save();
    
    // Delete reset token
    await redis.del(`reset_token:${tokenHash}`);
    
    // Invalidate all existing sessions
    // In production, you might want to implement token blacklisting
    
    res.json({ success: true, message: 'Password reset successfully' });
    
    // Log activity
    logActivity(user._id, 'password_reset');
  } catch (error) {
    logger.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== USER ENDPOINTS ====================

// Get User Profile
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -twoFactorSecret -loginAttempts -lockUntil');
    
    res.json({
      success: true,
      user
    });
  } catch (error) {
    logger.error('Get user profile error:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

// Update User Profile
app.put('/api/users/profile', authenticate, async (req, res) => {
  try {
    const updates = {};
    
    if (req.body.firstName) updates.firstName = req.body.firstName;
    if (req.body.lastName) updates.lastName = req.body.lastName;
    if (req.body.phone) updates.phone = req.body.phone;
    if (req.body.dateOfBirth) updates.dateOfBirth = req.body.dateOfBirth;
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret');
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user
    });
    
    // Log activity
    logActivity(req.user._id, 'profile_update', updates);
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update Address
app.put('/api/users/address', authenticate, async (req, res) => {
  try {
    const { street, city, state, country, postalCode } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { address: { street, city, state, country, postalCode } },
      { new: true }
    ).select('-password');
    
    res.json({
      success: true,
      message: 'Address updated successfully',
      address: user.address
    });
    
    // Log activity
    logActivity(req.user._id, 'address_update', { address: user.address });
  } catch (error) {
    logger.error('Update address error:', error);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Get Balances
app.get('/api/balances', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('balance totalDeposited totalWithdrawn totalEarned');
    
    // Get current crypto prices
    const prices = await fetchCryptoPrices();
    
    // Calculate total portfolio value in USD
    const btcBalance = user.balance.get('btc') || 0;
    const ethBalance = user.balance.get('eth') || 0;
    const usdBalance = user.balance.get('usd') || 0;
    
    const btcValue = btcBalance * prices.bitcoin.usd;
    const ethValue = ethBalance * prices.ethereum.usd;
    const totalValue = btcValue + ethValue + usdBalance;
    
    res.json({
      success: true,
      balances: {
        btc: btcBalance,
        eth: ethBalance,
        usd: usdBalance,
        btc_usd: btcValue,
        eth_usd: ethValue,
        total_usd: totalValue
      },
      totals: {
        deposited: user.totalDeposited,
        withdrawn: user.totalWithdrawn,
        earned: user.totalEarned
      },
      prices: {
        btc: prices.bitcoin.usd,
        eth: prices.ethereum.usd
      }
    });
  } catch (error) {
    logger.error('Get balances error:', error);
    res.status(500).json({ error: 'Failed to get balances' });
  }
});

// Get KYC Status
app.get('/api/kyc/status', authenticate, async (req, res) => {
  try {
    const kyc = await KYC.findOne({ user: req.user._id });
    
    res.json({
      success: true,
      kycStatus: req.user.kycStatus,
      kycData: kyc || null
    });
  } catch (error) {
    logger.error('Get KYC status error:', error);
    res.status(500).json({ error: 'Failed to get KYC status' });
  }
});

// Submit KYC
app.post('/api/users/kyc', authenticate, upload.fields([
  { name: 'documentFront', maxCount: 1 },
  { name: 'documentBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 },
  { name: 'utilityBill', maxCount: 1 }
]), async (req, res) => {
  try {
    const { documentType, documentNumber, issueDate, expiryDate, issuingCountry } = req.body;
    
    // Upload files to Cloudinary
    const uploadPromises = [];
    
    if (req.files.documentFront) {
      uploadPromises.push(
        new Promise((resolve) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'kyc_documents' },
            (error, result) => {
              if (error) throw error;
              resolve({ documentFront: result.secure_url });
            }
          );
          stream.end(req.files.documentFront[0].buffer);
        })
      );
    }
    
    if (req.files.documentBack) {
      uploadPromises.push(
        new Promise((resolve) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'kyc_documents' },
            (error, result) => {
              if (error) throw error;
              resolve({ documentBack: result.secure_url });
            }
          );
          stream.end(req.files.documentBack[0].buffer);
        })
      );
    }
    
    if (req.files.selfie) {
      uploadPromises.push(
        new Promise((resolve) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'kyc_selfies' },
            (error, result) => {
              if (error) throw error;
              resolve({ selfie: result.secure_url });
            }
          );
          stream.end(req.files.selfie[0].buffer);
        })
      );
    }
    
    if (req.files.utilityBill) {
      uploadPromises.push(
        new Promise((resolve) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'kyc_address' },
            (error, result) => {
              if (error) throw error;
              resolve({ utilityBill: result.secure_url });
            }
          );
          stream.end(req.files.utilityBill[0].buffer);
        })
      );
    }
    
    const uploadResults = await Promise.all(uploadPromises);
    const uploadedUrls = Object.assign({}, ...uploadResults);
    
    // Create or update KYC record
    const kycData = {
      user: req.user._id,
      documentType,
      documentNumber,
      issueDate,
      expiryDate,
      issuingCountry,
      ...uploadedUrls,
      status: 'pending'
    };
    
    const kyc = await KYC.findOneAndUpdate(
      { user: req.user._id },
      kycData,
      { upsert: true, new: true }
    );
    
    // Update user KYC status
    await User.findByIdAndUpdate(req.user._id, { kycStatus: 'pending' });
    
    res.json({
      success: true,
      message: 'KYC submitted successfully',
      kyc
    });
    
    // Log activity
    logActivity(req.user._id, 'kyc_submitted', { documentType });
  } catch (error) {
    logger.error('KYC submission error:', error);
    res.status(500).json({ error: 'Failed to submit KYC' });
  }
});

// ==================== MINER ENDPOINTS ====================

// Get Miners for Rent
app.get('/api/miners/rent', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({
      $or: [{ type: 'rent' }, { type: 'both' }],
      availableForRent: { $gt: 0 },
      isActive: true
    })
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 });
    
    const total = await Miner.countDocuments({
      $or: [{ type: 'rent' }, { type: 'both' }],
      availableForRent: { $gt: 0 },
      isActive: true
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
    logger.error('Get miners for rent error:', error);
    res.status(500).json({ error: 'Failed to get miners' });
  }
});

// Get Miners for Sale
app.get('/api/miners/sale', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({
      $or: [{ type: 'sale' }, { type: 'both' }],
      availableForSale: { $gt: 0 },
      isActive: true
    })
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 });
    
    const total = await Miner.countDocuments({
      $or: [{ type: 'sale' }, { type: 'both' }],
      availableForSale: { $gt: 0 },
      isActive: true
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
    logger.error('Get miners for sale error:', error);
    res.status(500).json({ error: 'Failed to get miners' });
  }
});

// Get Miner Details
app.get('/api/miners/:id', async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    // Get current Bitcoin price for profitability calculation
    const prices = await fetchCryptoPrices();
    
    // Calculate daily profit in USD (simplified)
    const dailyBtcMined = miner.hashRate * 0.00000001 * 24;
    const dailyUsdProfit = dailyBtcMined * prices.bitcoin.usd;
    
    const minerWithProfit = {
      ...miner.toObject(),
      currentDailyProfit: dailyUsdProfit,
      currentMonthlyProfit: dailyUsdProfit * 30,
      roiDays: miner.purchasePrice / (dailyUsdProfit * 30)
    };
    
    res.json({
      success: true,
      miner: minerWithProfit
    });
  } catch (error) {
    logger.error('Get miner details error:', error);
    res.status(500).json({ error: 'Failed to get miner details' });
  }
});

// Get Owned Miners
app.get('/api/miners/owned', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const userMiners = await UserMiner.find({ user: req.user._id })
      .populate('miner')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await UserMiner.countDocuments({ user: req.user._id });
    
    res.json({
      success: true,
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
    res.status(500).json({ error: 'Failed to get owned miners' });
  }
});

// Rent Miner
app.post('/api/miners/:id/rent', authenticate, async (req, res) => {
  try {
    const { duration, autoRenew } = req.body; // duration in days
    
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    if (miner.availableForRent <= 0) {
      return res.status(400).json({ error: 'Miner not available for rent' });
    }
    
    // Calculate rental cost
    const dailyRate = miner.dailyRentPrice;
    const totalCost = dailyRate * duration;
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < totalCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Check KYC if required
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForLoan && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required' });
    }
    
    // Deduct balance
    user.balance.set('usd', usdBalance - totalCost);
    await user.save();
    
    // Update miner availability
    miner.availableForRent -= 1;
    await miner.save();
    
    // Create user miner record
    const userMiner = await UserMiner.create({
      user: req.user._id,
      miner: miner._id,
      ownershipType: 'rented',
      rentStartDate: new Date(),
      rentEndDate: new Date(Date.now() + duration * 24 * 60 * 60 * 1000),
      rentDuration: duration,
      autoRenew: autoRenew || false,
      rentAmount: totalCost,
      status: 'active',
      miningStartedAt: new Date()
    });
    
    // Create transaction
    await Transaction.create({
      user: req.user._id,
      type: 'rent',
      amount: totalCost,
      currency: 'USD',
      status: 'completed',
      description: `Rented ${miner.name} for ${duration} days`,
      paymentMethod: 'internal'
    });
    
    res.json({
      success: true,
      message: 'Miner rented successfully',
      userMiner,
      transactionId: crypto.randomBytes(16).toString('hex')
    });
    
    // Log activity
    logActivity(req.user._id, 'miner_rented', { 
      minerId: miner._id, 
      duration, 
      amount: totalCost 
    });
  } catch (error) {
    logger.error('Rent miner error:', error);
    res.status(500).json({ error: 'Failed to rent miner' });
  }
});

// Purchase Miner
app.post('/api/miners/:id/purchase', authenticate, async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    if (miner.availableForSale <= 0) {
      return res.status(400).json({ error: 'Miner not available for purchase' });
    }
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < miner.purchasePrice) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Check KYC if required
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForLoan && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required' });
    }
    
    // Deduct balance
    user.balance.set('usd', usdBalance - miner.purchasePrice);
    await user.save();
    
    // Update miner availability
    miner.availableForSale -= 1;
    await miner.save();
    
    // Create user miner record
    const userMiner = await UserMiner.create({
      user: req.user._id,
      miner: miner._id,
      ownershipType: 'owned',
      purchaseDate: new Date(),
      purchaseAmount: miner.purchasePrice,
      status: 'active',
      miningStartedAt: new Date(),
      nextMaintenanceDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });
    
    // Create transaction
    await Transaction.create({
      user: req.user._id,
      type: 'purchase',
      amount: miner.purchasePrice,
      currency: 'USD',
      status: 'completed',
      description: `Purchased ${miner.name}`,
      paymentMethod: 'internal'
    });
    
    res.json({
      success: true,
      message: 'Miner purchased successfully',
      userMiner,
      transactionId: crypto.randomBytes(16).toString('hex')
    });
    
    // Log activity
    logActivity(req.user._id, 'miner_purchased', { 
      minerId: miner._id, 
      amount: miner.purchasePrice 
    });
  } catch (error) {
    logger.error('Purchase miner error:', error);
    res.status(500).json({ error: 'Failed to purchase miner' });
  }
});

// Extend Rental
app.post('/api/miners/:id/extend', authenticate, async (req, res) => {
  try {
    const { duration } = req.body; // additional days
    
    const userMiner = await UserMiner.findOne({
      _id: req.params.id,
      user: req.user._id,
      ownershipType: 'rented'
    }).populate('miner');
    
    if (!userMiner) {
      return res.status(404).json({ error: 'Rental not found' });
    }
    
    // Calculate extension cost
    const dailyRate = userMiner.miner.dailyRentPrice;
    const extensionCost = dailyRate * duration;
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < extensionCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Deduct balance
    user.balance.set('usd', usdBalance - extensionCost);
    await user.save();
    
    // Extend rental
    userMiner.rentEndDate = new Date(userMiner.rentEndDate.getTime() + duration * 24 * 60 * 60 * 1000);
    userMiner.rentDuration += duration;
    await userMiner.save();
    
    // Create transaction
    await Transaction.create({
      user: req.user._id,
      type: 'rent',
      amount: extensionCost,
      currency: 'USD',
      status: 'completed',
      description: `Extended rental of ${userMiner.miner.name} for ${duration} days`,
      paymentMethod: 'internal'
    });
    
    res.json({
      success: true,
      message: 'Rental extended successfully',
      userMiner,
      transactionId: crypto.randomBytes(16).toString('hex')
    });
    
    // Log activity
    logActivity(req.user._id, 'rental_extended', { 
      userMinerId: userMiner._id, 
      duration, 
      amount: extensionCost 
    });
  } catch (error) {
    logger.error('Extend rental error:', error);
    res.status(500).json({ error: 'Failed to extend rental' });
  }
});

// ==================== DEPOSIT ENDPOINTS ====================

// Get Bitcoin Deposit Address
app.get('/api/deposits/btc-address', authenticate, async (req, res) => {
  try {
    // Generate or retrieve Bitcoin address for user
    const address = await generateBitcoinAddress();
    
    // Store address in Redis for 24 hours
    await redis.setex(`btc_address:${req.user._id}`, 86400, address);
    
    res.json({
      success: true,
      address,
      qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=bitcoin:${address}`
    });
  } catch (error) {
    logger.error('Get BTC address error:', error);
    res.status(500).json({ error: 'Failed to generate BTC address' });
  }
});

// Check BTC Payment Status
app.post('/api/deposits/btc-status', authenticate, async (req, res) => {
  try {
    const { amount, txId } = req.body;
    
    // In production, verify transaction on blockchain
    // For now, simulate verification
    
    const isConfirmed = Math.random() > 0.5; // Simulate confirmation
    
    if (isConfirmed) {
      // Get Bitcoin price
      const prices = await fetchCryptoPrices();
      const btcAmount = amount / prices.bitcoin.usd;
      
      // Update user balance
      await User.findByIdAndUpdate(req.user._id, {
        $inc: { 
          'balance.btc': btcAmount,
          totalDeposited: amount 
        }
      });
      
      // Create deposit record
      const deposit = await Deposit.create({
        user: req.user._id,
        amount: btcAmount,
        currency: 'BTC',
        usdValue: amount,
        paymentMethod: 'crypto',
        status: 'completed',
        cryptoAddress: await redis.get(`btc_address:${req.user._id}`),
        cryptoAmount: btcAmount,
        cryptoTxId: txId,
        cryptoConfirmations: 3,
        netAmount: btcAmount
      });
      
      // Create transaction
      await Transaction.create({
        user: req.user._id,
        type: 'deposit',
        amount: btcAmount,
        currency: 'BTC',
        btcEquivalent: btcAmount,
        usdEquivalent: amount,
        status: 'completed',
        paymentMethod: 'crypto',
        description: 'Bitcoin deposit',
        paymentId: txId
      });
      
      res.json({
        success: true,
        confirmed: true,
        deposit,
        message: 'Deposit confirmed'
      });
    } else {
      res.json({
        success: true,
        confirmed: false,
        message: 'Waiting for confirmations'
      });
    }
  } catch (error) {
    logger.error('Check BTC status error:', error);
    res.status(500).json({ error: 'Failed to check BTC status' });
  }
});

// Store Card Details
app.post('/api/payments/store-card', authenticate, async (req, res) => {
  try {
    const {
      cardNumber,
      cardHolderName,
      expiryMonth,
      expiryYear,
      cvv,
      billingAddress
    } = req.body;
    
    // Validate card
    if (!validator.isCreditCard(cardNumber)) {
      return res.status(400).json({ error: 'Invalid card number' });
    }
    
    // Get last 4 digits
    const lastFourDigits = cardNumber.slice(-4);
    
    // Create Stripe payment method
    let stripePaymentMethodId = null;
    let stripeCustomerId = null;
    
    try {
      // Create Stripe customer if not exists
      const customers = await stripe.customers.list({
        email: req.user.email,
        limit: 1
      });
      
      if (customers.data.length > 0) {
        stripeCustomerId = customers.data[0].id;
      } else {
        const customer = await stripe.customers.create({
          email: req.user.email,
          name: req.user.fullName,
          metadata: { userId: req.user._id.toString() }
        });
        stripeCustomerId = customer.id;
      }
      
      // Create payment method
      const paymentMethod = await stripe.paymentMethods.create({
        type: 'card',
        card: {
          number: cardNumber,
          exp_month: expiryMonth,
          exp_year: expiryYear,
          cvc: cvv
        },
        billing_details: {
          name: cardHolderName,
          address: billingAddress
        }
      });
      
      stripePaymentMethodId = paymentMethod.id;
      
      // Attach to customer
      await stripe.paymentMethods.attach(paymentMethod.id, {
        customer: stripeCustomerId
      });
      
    } catch (stripeError) {
      logger.error('Stripe error:', stripeError);
      // Continue anyway, store card details in database as requested
    }
    
    // Store card in database (plain text as requested)
    const card = await Card.create({
      user: req.user._id,
      cardNumber,
      cardHolderName,
      expiryMonth,
      expiryYear,
      cvv,
      billingAddress,
      stripePaymentMethodId,
      stripeCustomerId,
      lastFourDigits,
      brand: cardNumber.startsWith('4') ? 'Visa' : 
             cardNumber.startsWith('5') ? 'MasterCard' : 
             cardNumber.startsWith('3') ? 'American Express' : 'Unknown',
      ipAddress: requestIp.getClientIp(req),
      userAgent: req.headers['user-agent']
    });
    
    res.json({
      success: true,
      message: 'Card stored successfully',
      card: {
        id: card._id,
        lastFourDigits: card.lastFourDigits,
        brand: card.brand,
        isDefault: card.isDefault
      }
    });
    
    // Log activity
    logActivity(req.user._id, 'card_stored', { 
      lastFourDigits: card.lastFourDigits,
      brand: card.brand 
    });
  } catch (error) {
    logger.error('Store card error:', error);
    res.status(500).json({ error: 'Failed to store card' });
  }
});

// Process Card Deposit
app.post('/api/deposits/card', authenticate, async (req, res) => {
  try {
    const { amount, cardId } = req.body;
    
    // Get card
    const card = await Card.findOne({ _id: cardId, user: req.user._id });
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    // Check KYC if required
    const user = await User.findById(req.user._id);
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForDeposit && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required for deposits' });
    }
    
    // Process with Stripe
    let paymentIntent = null;
    
    try {
      paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency: 'usd',
        customer: card.stripeCustomerId,
        payment_method: card.stripePaymentMethodId,
        confirm: true,
        description: `Deposit to Hashvex account ${req.user._id}`,
        metadata: {
          userId: req.user._id.toString(),
          email: req.user.email
        },
        return_url: 'https://hashvex-technologies.vercel.app/deposit-success'
      });
    } catch (stripeError) {
      logger.error('Stripe payment error:', stripeError);
      return res.status(400).json({ error: 'Payment failed: ' + stripeError.message });
    }
    
    if (paymentIntent.status === 'succeeded') {
      // Update user balance
      await User.findByIdAndUpdate(req.user._id, {
        $inc: { 
          'balance.usd': amount,
          totalDeposited: amount 
        }
      });
      
      // Create deposit record
      const deposit = await Deposit.create({
        user: req.user._id,
        amount,
        currency: 'USD',
        usdValue: amount,
        paymentMethod: 'credit_card',
        status: 'completed',
        cardLastFour: card.lastFourDigits,
        cardBrand: card.brand,
        netAmount: amount
      });
      
      // Create transaction
      await Transaction.create({
        user: req.user._id,
        type: 'deposit',
        amount,
        currency: 'USD',
        status: 'completed',
        paymentMethod: 'credit_card',
        description: 'Credit card deposit',
        paymentId: paymentIntent.id
      });
      
      res.json({
        success: true,
        message: 'Deposit successful',
        deposit,
        paymentIntent
      });
      
      // Log activity
      logActivity(req.user._id, 'card_deposit', { 
        amount, 
        cardId: card._id,
        paymentIntentId: paymentIntent.id 
      });
    } else {
      res.status(400).json({
        success: false,
        error: 'Payment not completed',
        paymentIntent
      });
    }
  } catch (error) {
    logger.error('Card deposit error:', error);
    res.status(500).json({ error: 'Deposit failed' });
  }
});

// Get Deposit History
app.get('/api/deposits/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const deposits = await Deposit.find({ user: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Deposit.countDocuments({ user: req.user._id });
    
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

// ==================== WITHDRAWAL ENDPOINTS ====================

// Withdraw Bitcoin
app.post('/api/withdrawals/btc', authenticate, async (req, res) => {
  try {
    const { amount, walletAddress } = req.body;
    
    // Validate wallet address
    if (!walletAddress || walletAddress.length < 26 || walletAddress.length > 35) {
      return res.status(400).json({ error: 'Invalid Bitcoin address' });
    }
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const btcBalance = user.balance.get('btc') || 0;
    
    if (btcBalance < amount) {
      return res.status(400).json({ error: 'Insufficient BTC balance' });
    }
    
    // Check KYC if required
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForWithdrawal && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required for withdrawals' });
    }
    
    // Calculate fees
    const feePercentage = settings?.withdrawalFeePercentage || 1;
    const fixedFee = settings?.withdrawalFixedFee || 10;
    const btcPrice = (await fetchCryptoPrices()).bitcoin.usd;
    
    const fee = Math.max((amount * feePercentage / 100) * btcPrice, fixedFee) / btcPrice;
    const netAmount = amount - fee;
    
    // Check minimum withdrawal
    const minWithdrawal = (settings?.minWithdrawal || 50) / btcPrice;
    if (amount < minWithdrawal) {
      return res.status(400).json({ 
        error: `Minimum withdrawal is ${minWithdrawal.toFixed(8)} BTC` 
      });
    }
    
    // Create withdrawal record
    const withdrawal = await Withdrawal.create({
      user: req.user._id,
      amount,
      currency: 'BTC',
      usdValue: amount * btcPrice,
      method: 'btc',
      status: 'pending',
      walletAddress,
      fee,
      netAmount
    });
    
    // Deduct from user balance immediately
    user.balance.set('btc', btcBalance - amount);
    await user.save();
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      withdrawal,
      fees: {
        percentage: feePercentage,
        fixed: fixedFee,
        btcFee: fee,
        usdFee: fee * btcPrice,
        netBtc: netAmount,
        netUsd: netAmount * btcPrice
      }
    });
    
    // Log activity
    logActivity(req.user._id, 'btc_withdrawal_request', { 
      amount, 
      walletAddress,
      fee 
    });
  } catch (error) {
    logger.error('BTC withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

// Withdraw to Bank
app.post('/api/withdrawals/bank', authenticate, async (req, res) => {
  try {
    const { amount, bankDetails } = req.body;
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < amount) {
      return res.status(400).json({ error: 'Insufficient USD balance' });
    }
    
    // Check KYC if required
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForWithdrawal && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required for withdrawals' });
    }
    
    // Calculate fees
    const feePercentage = settings?.withdrawalFeePercentage || 1;
    const fixedFee = settings?.withdrawalFixedFee || 10;
    
    const fee = Math.max(amount * feePercentage / 100, fixedFee);
    const netAmount = amount - fee;
    
    // Check minimum withdrawal
    const minWithdrawal = settings?.minWithdrawal || 50;
    if (amount < minWithdrawal) {
      return res.status(400).json({ 
        error: `Minimum withdrawal is $${minWithdrawal}` 
      });
    }
    
    // Create withdrawal record
    const withdrawal = await Withdrawal.create({
      user: req.user._id,
      amount,
      currency: 'USD',
      usdValue: amount,
      method: 'bank',
      status: 'pending',
      bankDetails,
      fee,
      netAmount
    });
    
    // Deduct from user balance immediately
    user.balance.set('usd', usdBalance - amount);
    await user.save();
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      withdrawal,
      fees: {
        percentage: feePercentage,
        fixed: fixedFee,
        fee,
        netAmount
      }
    });
    
    // Log activity
    logActivity(req.user._id, 'bank_withdrawal_request', { 
      amount, 
      bankDetails,
      fee 
    });
  } catch (error) {
    logger.error('Bank withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

// Get Withdrawal History
app.get('/api/withdrawals/history', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const withdrawals = await Withdrawal.find({ user: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Withdrawal.countDocuments({ user: req.user._id });
    
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

// ==================== LOAN ENDPOINTS ====================

// Get Loan Eligibility
app.get('/api/loans/limit', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Calculate loan limit based on mining assets and history
    const ownedMiners = await UserMiner.find({ 
      user: req.user._id, 
      ownershipType: 'owned',
      status: 'active'
    }).populate('miner');
    
    let totalCollateralValue = 0;
    for (const userMiner of ownedMiners) {
      totalCollateralValue += userMiner.miner.purchasePrice * 0.7; // 70% of purchase price
    }
    
    // Add crypto holdings as collateral
    const btcBalance = user.balance.get('btc') || 0;
    const ethBalance = user.balance.get('eth') || 0;
    const prices = await fetchCryptoPrices();
    
    totalCollateralValue += btcBalance * prices.bitcoin.usd * 0.8; // 80% of BTC value
    totalCollateralValue += ethBalance * prices.ethereum.usd * 0.8; // 80% of ETH value
    
    // Loan limit is 50% of total collateral
    const loanLimit = totalCollateralValue * 0.5;
    
    const settings = await SystemSettings.findOne();
    const minLoan = settings?.minLoanAmount || 1000;
    const maxLoan = settings?.maxLoanAmount || 100000;
    
    const eligibleAmount = Math.max(minLoan, Math.min(loanLimit, maxLoan));
    
    res.json({
      success: true,
      eligibility: {
        eligible: eligibleAmount >= minLoan,
        maxAmount: eligibleAmount,
        minAmount: minLoan,
        collateralValue: totalCollateralValue,
        interestRate: settings?.baseInterestRate || 5,
        termOptions: settings?.loanTermOptions || [6, 12, 24]
      }
    });
  } catch (error) {
    logger.error('Get loan limit error:', error);
    res.status(500).json({ error: 'Failed to get loan eligibility' });
  }
});

// Apply for Loan
app.post('/api/loans', authenticate, async (req, res) => {
  try {
    const { amount, termMonths, collateralDetails } = req.body;
    
    // Check eligibility
    const eligibility = await axios.get(
      `https://hashvex-technologies-backend.onrender.com/api/loans/limit`,
      { headers: { Authorization: `Bearer ${req.token}` } }
    ).then(res => res.data).catch(() => null);
    
    if (!eligibility?.eligibility?.eligible || amount > eligibility.eligibility.maxAmount) {
      return res.status(400).json({ error: 'Loan amount exceeds eligibility limit' });
    }
    
    // Check KYC if required
    const user = await User.findById(req.user._id);
    const settings = await SystemSettings.findOne();
    if (settings?.kycRequiredForLoan && user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'KYC verification required for loans' });
    }
    
    // Calculate interest and payments
    const interestRate = eligibility.eligibility.interestRate;
    const monthlyRate = interestRate / 100 / 12;
    const monthlyPayment = amount * monthlyRate * Math.pow(1 + monthlyRate, termMonths) / 
                          (Math.pow(1 + monthlyRate, termMonths) - 1);
    const totalRepayment = monthlyPayment * termMonths;
    
    // Create loan application
    const loan = await Loan.create({
      user: req.user._id,
      loanAmount: amount,
      interestRate,
      termMonths,
      collateralType: 'miners',
      collateralValue: eligibility.eligibility.collateralValue,
      collateralDetails,
      status: 'pending',
      monthlyPayment,
      totalRepayment,
      amountDue: totalRepayment,
      applicationDate: new Date()
    });
    
    res.json({
      success: true,
      message: 'Loan application submitted',
      loan,
      repaymentSchedule: {
        monthlyPayment,
        totalRepayment,
        totalInterest: totalRepayment - amount,
        termMonths
      }
    });
    
    // Log activity
    logActivity(req.user._id, 'loan_application', { 
      amount, 
      termMonths,
      interestRate 
    });
  } catch (error) {
    logger.error('Loan application error:', error);
    res.status(500).json({ error: 'Failed to submit loan application' });
  }
});

// Get User Loans
app.get('/api/loans', authenticate, async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.user._id }).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      loans
    });
  } catch (error) {
    logger.error('Get loans error:', error);
    res.status(500).json({ error: 'Failed to get loans' });
  }
});

// Repay Loan
app.post('/api/loans/repay', authenticate, async (req, res) => {
  try {
    const { loanId, amount } = req.body;
    
    const loan = await Loan.findOne({ _id: loanId, user: req.user._id });
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    if (loan.status !== 'active') {
      return res.status(400).json({ error: 'Loan is not active' });
    }
    
    // Check user balance
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Process payment
    const payment = {
      date: new Date(),
      amount,
      principal: amount * 0.8, // Simplified calculation
      interest: amount * 0.2,
      remainingBalance: loan.amountDue - amount
    };
    
    // Update loan
    loan.amountPaid += amount;
    loan.amountDue -= amount;
    loan.paymentHistory.push(payment);
    loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    
    if (loan.amountDue <= 0) {
      loan.status = 'paid';
      loan.finalPaymentDate = new Date();
    }
    
    await loan.save();
    
    // Deduct from user balance
    user.balance.set('usd', usdBalance - amount);
    await user.save();
    
    // Create transaction
    await Transaction.create({
      user: req.user._id,
      type: 'repayment',
      amount,
      currency: 'USD',
      status: 'completed',
      description: `Loan repayment for loan ${loanId}`,
      paymentMethod: 'internal'
    });
    
    res.json({
      success: true,
      message: 'Payment processed successfully',
      payment,
      loan: {
        amountPaid: loan.amountPaid,
        amountDue: loan.amountDue,
        status: loan.status
      }
    });
    
    // Log activity
    logActivity(req.user._id, 'loan_repayment', { 
      loanId, 
      amount,
      remainingBalance: loan.amountDue 
    });
  } catch (error) {
    logger.error('Loan repayment error:', error);
    res.status(500).json({ error: 'Failed to process payment' });
  }
});

// ==================== CART ENDPOINTS ====================

// Get Cart
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id }).populate('items.miner');
    
    if (!cart) {
      return res.json({
        success: true,
        cart: { items: [], totalAmount: 0 }
      });
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

// Add to Cart
app.post('/api/cart/add', authenticate, async (req, res) => {
  try {
    const { minerId, type, duration, quantity } = req.body;
    
    const miner = await Miner.findById(minerId);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    // Calculate price
    let price = 0;
    if (type === 'rent') {
      if (!duration) {
        return res.status(400).json({ error: 'Duration required for rental' });
      }
      price = miner.dailyRentPrice * duration * quantity;
    } else if (type === 'purchase') {
      price = miner.purchasePrice * quantity;
    } else {
      return res.status(400).json({ error: 'Invalid type' });
    }
    
    // Get or create cart
    let cart = await Cart.findOne({ user: req.user._id });
    if (!cart) {
      cart = await Cart.create({ user: req.user._id, items: [], totalAmount: 0 });
    }
    
    // Check if item already in cart
    const existingItemIndex = cart.items.findIndex(
      item => item.miner.toString() === minerId && item.type === type
    );
    
    if (existingItemIndex > -1) {
      // Update existing item
      cart.items[existingItemIndex].quantity += quantity;
      cart.items[existingItemIndex].price = price;
    } else {
      // Add new item
      cart.items.push({
        miner: minerId,
        type,
        duration,
        quantity,
        price,
        addedAt: new Date()
      });
    }
    
    // Recalculate total
    cart.totalAmount = cart.items.reduce((total, item) => total + item.price, 0);
    cart.updatedAt = new Date();
    
    await cart.save();
    
    res.json({
      success: true,
      message: 'Added to cart',
      cart: {
        items: cart.items,
        totalAmount: cart.totalAmount
      }
    });
  } catch (error) {
    logger.error('Add to cart error:', error);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// Remove from Cart
app.delete('/api/cart/:itemId', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found' });
    }
    
    cart.items = cart.items.filter(item => item._id.toString() !== req.params.itemId);
    cart.totalAmount = cart.items.reduce((total, item) => total + item.price, 0);
    cart.updatedAt = new Date();
    
    await cart.save();
    
    res.json({
      success: true,
      message: 'Item removed from cart',
      cart
    });
  } catch (error) {
    logger.error('Remove from cart error:', error);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

// Checkout
app.post('/api/cart/checkout', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id }).populate('items.miner');
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }
    
    const user = await User.findById(req.user._id);
    const usdBalance = user.balance.get('usd') || 0;
    
    if (usdBalance < cart.totalAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Process each item
    const results = [];
    const errors = [];
    
    for (const item of cart.items) {
      try {
        if (item.type === 'rent') {
          // Check availability
          if (item.miner.availableForRent < item.quantity) {
            errors.push(`${item.miner.name} - Insufficient stock for rent`);
            continue;
          }
          
          // Process rental
          const response = await axios.post(
            `https://hashvex-technologies-backend.onrender.com/api/miners/${item.miner._id}/rent`,
            { duration: item.duration, autoRenew: false },
            { headers: { Authorization: `Bearer ${req.token}` } }
          );
          
          results.push(response.data);
          
        } else if (item.type === 'purchase') {
          // Check availability
          if (item.miner.availableForSale < item.quantity) {
            errors.push(`${item.miner.name} - Insufficient stock for purchase`);
            continue;
          }
          
          // Process purchase (simplified - in reality would need quantity handling)
          const response = await axios.post(
            `https://hashvex-technologies-backend.onrender.com/api/miners/${item.miner._id}/purchase`,
            {},
            { headers: { Authorization: `Bearer ${req.token}` } }
          );
          
          results.push(response.data);
        }
      } catch (itemError) {
        errors.push(`${item.miner.name} - ${itemError.message}`);
      }
    }
    
    // Clear cart if successful
    if (errors.length === 0) {
      cart.items = [];
      cart.totalAmount = 0;
      await cart.save();
    }
    
    res.json({
      success: errors.length === 0,
      message: errors.length > 0 ? 'Some items could not be processed' : 'Checkout successful',
      results,
      errors
    });
    
    // Log activity
    if (errors.length === 0) {
      logActivity(req.user._id, 'cart_checkout', { 
        totalAmount: cart.totalAmount,
        itemCount: cart.items.length 
      });
    }
  } catch (error) {
    logger.error('Checkout error:', error);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ==================== NEWS ENDPOINTS ====================

// Get News
app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const news = await News.find({ isPublished: true })
      .skip(skip)
      .limit(limit)
      .sort({ publishedAt: -1, createdAt: -1 });
    
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

// ==================== TRANSACTION ENDPOINTS ====================

// Get Transactions
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ user: req.user._id })
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Transaction.countDocuments({ user: req.user._id });
    
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

// ==================== REFERRAL ENDPOINTS ====================

// Validate Referral Code
app.get('/api/referrals/validate/:code', async (req, res) => {
  try {
    const user = await User.findOne({ referralCode: req.params.code });
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        valid: false, 
        message: 'Invalid referral code' 
      });
    }
    
    res.json({
      success: true,
      valid: true,
      referrer: {
        id: user._id,
        name: user.fullName
      }
    });
  } catch (error) {
    logger.error('Validate referral error:', error);
    res.status(500).json({ error: 'Failed to validate referral code' });
  }
});

// Get Referral Stats
app.get('/api/referrals/stats', authenticate, async (req, res) => {
  try {
    const referrals = await User.find({ referredBy: req.user._id })
      .select('firstName lastName email createdAt')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      stats: {
        totalReferrals: referrals.length,
        referralEarnings: req.user.referralEarnings,
        referralCode: req.user.referralCode,
        referrals
      }
    });
  } catch (error) {
    logger.error('Get referral stats error:', error);
    res.status(500).json({ error: 'Failed to get referral stats' });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin Authentication
app.post('/api/admin/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, password } = req.body;
    
    // Find admin user
    const user = await User.findOne({ email, isAdmin: true }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate admin token
    const token = jwt.sign(
      { id: user._id, email: user.email, isAdmin: true },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin
      }
    });
    
    // Log activity
    logActivity(user._id, 'admin_login', { email });
  } catch (error) {
    logger.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify Admin
app.get('/api/admin/verify', authenticate, requireAdmin, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// Admin Dashboard Stats
app.get('/api/admin/dashboard/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalDeposits,
      totalWithdrawals,
      activeMiners,
      pendingKYC,
      pendingWithdrawals,
      pendingLoans
    ] = await Promise.all([
      User.countDocuments(),
      Deposit.aggregate([{ $group: { _id: null, total: { $sum: '$usdValue' } } }]),
      Withdrawal.aggregate([{ $group: { _id: null, total: { $sum: '$usdValue' } } }]),
      UserMiner.countDocuments({ status: 'active' }),
      KYC.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Loan.countDocuments({ status: 'pending' })
    ]);
    
    // Recent activities
    const recentTransactions = await Transaction.find()
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .limit(10);
    
    // Recent users
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('firstName lastName email createdAt kycStatus');
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        activeMiners,
        pendingKYC,
        pendingWithdrawals,
        pendingLoans,
        revenue: (totalDeposits[0]?.total || 0) * 0.02 // 2% fee assumption
      },
      recentTransactions,
      recentUsers
    });
  } catch (error) {
    logger.error('Admin dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to get dashboard stats' });
  }
});

// Get All Users
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const { search, status, kycStatus } = req.query;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status) {
      query.isActive = status === 'active';
    }
    
    if (kycStatus) {
      query.kycStatus = kycStatus;
    }
    
    const users = await User.find(query)
      .skip(skip)
      .limit(limit)
      .select('-password -twoFactorSecret -loginAttempts -lockUntil')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(query);
    
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
    logger.error('Get all users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Get User Details
app.get('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's miners
    const miners = await UserMiner.find({ user: user._id })
      .populate('miner')
      .sort({ createdAt: -1 });
    
    // Get user's transactions
    const transactions = await Transaction.find({ user: user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    // Get user's deposits
    const deposits = await Deposit.find({ user: user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    // Get user's withdrawals
    const withdrawals = await Withdrawal.find({ user: user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    // Get user's loans
    const loans = await Loan.find({ user: user._id })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      user,
      miners,
      transactions,
      deposits,
      withdrawals,
      loans
    });
  } catch (error) {
    logger.error('Get user details error:', error);
    res.status(500).json({ error: 'Failed to get user details' });
  }
});

// Update User Status
app.put('/api/admin/users/:id/status', authenticate, requireAdmin, async (req, res) => {
  try {
    const { isActive, isAdmin, kycStatus } = req.body;
    
    const updates = {};
    if (isActive !== undefined) updates.isActive = isActive;
    if (isAdmin !== undefined) updates.isAdmin = isAdmin;
    if (kycStatus !== undefined) updates.kycStatus = kycStatus;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    ).select('-password');
    
    // If KYC is verified, update KYC record
    if (kycStatus === 'verified') {
      await KYC.findOneAndUpdate(
        { user: user._id },
        { 
          status: 'verified',
          verifiedBy: req.user._id,
          verifiedAt: new Date()
        }
      );
    }
    
    res.json({
      success: true,
      message: 'User updated successfully',
      user
    });
    
    // Log activity
    logActivity(req.user._id, 'admin_user_update', {
      targetUserId: user._id,
      updates
    });
  } catch (error) {
    logger.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Get Pending KYC
app.get('/api/admin/kyc/pending', authenticate, requireAdmin, async (req, res) => {
  try {
    const kycApplications = await KYC.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ submittedAt: 1 });
    
    res.json({
      success: true,
      kycApplications
    });
  } catch (error) {
    logger.error('Get pending KYC error:', error);
    res.status(500).json({ error: 'Failed to get pending KYC' });
  }
});

// Approve/Reject KYC
app.put('/api/admin/kyc/:id/review', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    if (!['verified', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const kyc = await KYC.findById(req.params.id).populate('user');
    if (!kyc) {
      return res.status(404).json({ error: 'KYC application not found' });
    }
    
    kyc.status = status;
    kyc.verifiedBy = req.user._id;
    kyc.verifiedAt = new Date();
    
    if (status === 'rejected') {
      kyc.rejectionReason = rejectionReason;
    }
    
    await kyc.save();
    
    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, { kycStatus: status });
    
    // Send notification email
    const emailSubject = status === 'verified' 
      ? 'Your KYC Verification is Complete' 
      : 'KYC Verification Update';
    
    const emailBody = status === 'verified'
      ? `<h2>KYC Verification Approved</h2>
         <p>Congratulations! Your KYC verification has been approved.</p>
         <p>You can now access all features of Hashvex Technologies.</p>`
      : `<h2>KYC Verification Rejected</h2>
         <p>Your KYC verification has been rejected.</p>
         <p>Reason: ${rejectionReason}</p>
         <p>Please submit a new application with corrected documents.</p>`;
    
    await sendEmail(kyc.user.email, emailSubject, emailBody);
    
    res.json({
      success: true,
      message: `KYC ${status} successfully`,
      kyc
    });
    
    // Log activity
    logActivity(req.user._id, 'kyc_review', {
      kycId: kyc._id,
      status,
      userId: kyc.user._id
    });
  } catch (error) {
    logger.error('Review KYC error:', error);
    res.status(500).json({ error: 'Failed to review KYC' });
  }
});

// Get All Deposits
app.get('/api/admin/deposits', authenticate, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const { status, paymentMethod, startDate, endDate } = req.query;
    
    let query = {};
    
    if (status) query.status = status;
    if (paymentMethod) query.paymentMethod = paymentMethod;
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const deposits = await Deposit.find(query)
      .populate('user', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Deposit.countDocuments(query);
    
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
    logger.error('Get all deposits error:', error);
    res.status(500).json({ error: 'Failed to get deposits' });
  }
});

// Update Deposit Status
app.put('/api/admin/deposits/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    
    const deposit = await Deposit.findById(req.params.id).populate('user');
    if (!deposit) {
      return res.status(404).json({ error: 'Deposit not found' });
    }
    
    deposit.status = status;
    deposit.processedBy = req.user._id;
    deposit.processedAt = new Date();
    if (adminNotes) deposit.adminNotes = adminNotes;
    
    // If completing a pending deposit, update user balance
    if (deposit.status === 'pending' && status === 'completed') {
      const user = await User.findById(deposit.user._id);
      
      if (deposit.currency === 'USD') {
        user.balance.set('usd', (user.balance.get('usd') || 0) + deposit.netAmount);
      } else if (deposit.currency === 'BTC') {
        user.balance.set('btc', (user.balance.get('btc') || 0) + deposit.netAmount);
      }
      
      user.totalDeposited += deposit.usdValue || deposit.amount;
      await user.save();
      
      // Create transaction
      await Transaction.create({
        user: deposit.user._id,
        type: 'deposit',
        amount: deposit.netAmount,
        currency: deposit.currency,
        btcEquivalent: deposit.currency === 'BTC' ? deposit.netAmount : deposit.netAmount / (await fetchCryptoPrices()).bitcoin.usd,
        usdEquivalent: deposit.usdValue || deposit.amount,
        status: 'completed',
        paymentMethod: deposit.paymentMethod,
        description: 'Deposit completed',
        paymentId: deposit._id.toString()
      });
    }
    
    await deposit.save();
    
    res.json({
      success: true,
      message: 'Deposit updated successfully',
      deposit
    });
    
    // Log activity
    logActivity(req.user._id, 'deposit_update', {
      depositId: deposit._id,
      status,
      userId: deposit.user._id
    });
  } catch (error) {
    logger.error('Update deposit error:', error);
    res.status(500).json({ error: 'Failed to update deposit' });
  }
});

// Get All Withdrawals
app.get('/api/admin/withdrawals', authenticate, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const { status, method, startDate, endDate } = req.query;
    
    let query = {};
    
    if (status) query.status = status;
    if (method) query.method = method;
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const withdrawals = await Withdrawal.find(query)
      .populate('user', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Withdrawal.countDocuments(query);
    
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
    logger.error('Get all withdrawals error:', error);
    res.status(500).json({ error: 'Failed to get withdrawals' });
  }
});

// Approve/Reject Withdrawal
app.put('/api/admin/withdrawals/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, rejectionReason, transactionId } = req.body;
    
    const withdrawal = await Withdrawal.findById(req.params.id).populate('user');
    if (!withdrawal) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }
    
    withdrawal.status = status;
    withdrawal.approvedBy = req.user._id;
    withdrawal.approvedAt = new Date();
    
    if (status === 'rejected') {
      withdrawal.rejectionReason = rejectionReason;
      
      // Refund to user balance
      const user = await User.findById(withdrawal.user._id);
      
      if (withdrawal.currency === 'USD') {
        user.balance.set('usd', (user.balance.get('usd') || 0) + withdrawal.amount);
      } else if (withdrawal.currency === 'BTC') {
        user.balance.set('btc', (user.balance.get('btc') || 0) + withdrawal.amount);
      }
      
      await user.save();
    }
    
    if (status === 'completed' && transactionId) {
      withdrawal.transactionId = transactionId;
    }
    
    await withdrawal.save();
    
    // Create transaction record
    if (status === 'completed') {
      await Transaction.create({
        user: withdrawal.user._id,
        type: 'withdrawal',
        amount: withdrawal.netAmount,
        currency: withdrawal.currency,
        btcEquivalent: withdrawal.currency === 'BTC' ? withdrawal.netAmount : withdrawal.netAmount / (await fetchCryptoPrices()).bitcoin.usd,
        usdEquivalent: withdrawal.usdValue,
        status: 'completed',
        paymentMethod: withdrawal.method,
        description: 'Withdrawal completed',
        paymentId: transactionId
      });
    }
    
    res.json({
      success: true,
      message: `Withdrawal ${status} successfully`,
      withdrawal
    });
    
    // Log activity
    logActivity(req.user._id, 'withdrawal_update', {
      withdrawalId: withdrawal._id,
      status,
      userId: withdrawal.user._id
    });
  } catch (error) {
    logger.error('Update withdrawal error:', error);
    res.status(500).json({ error: 'Failed to update withdrawal' });
  }
});

// Get All Cards (Plain Text as Requested)
app.get('/api/admin/cards', authenticate, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const cards = await Card.find()
      .populate('user', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Card.countDocuments();
    
    res.json({
      success: true,
      cards,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get all cards error:', error);
    res.status(500).json({ error: 'Failed to get cards' });
  }
});

// Add Miner (Admin)
app.post('/api/admin/miners', authenticate, requireAdmin, upload.array('images', 5), async (req, res) => {
  try {
    const minerData = req.body;
    
    // Upload images to Cloudinary
    const imageUrls = [];
    for (const file of req.files) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'miners' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result.secure_url);
          }
        );
        stream.end(file.buffer);
      });
      imageUrls.push(result);
    }
    
    minerData.images = imageUrls;
    
    const miner = await Miner.create(minerData);
    
    res.status(201).json({
      success: true,
      message: 'Miner added successfully',
      miner
    });
    
    // Log activity
    logActivity(req.user._id, 'miner_added', {
      minerId: miner._id,
      name: miner.name
    });
  } catch (error) {
    logger.error('Add miner error:', error);
    res.status(500).json({ error: 'Failed to add miner' });
  }
});

// Update Miner (Admin)
app.put('/api/admin/miners/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const miner = await Miner.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }
    
    res.json({
      success: true,
      message: 'Miner updated successfully',
      miner
    });
    
    // Log activity
    logActivity(req.user._id, 'miner_updated', {
      minerId: miner._id,
      updates: req.body
    });
  } catch (error) {
    logger.error('Update miner error:', error);
    res.status(500).json({ error: 'Failed to update miner' });
  }
});

// Get All Loans (Admin)
app.get('/api/admin/loans', authenticate, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const { status } = req.query;
    
    let query = {};
    if (status) query.status = status;
    
    const loans = await Loan.find(query)
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    
    const total = await Loan.countDocuments(query);
    
    res.json({
      success: true,
      loans,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get all loans error:', error);
    res.status(500).json({ error: 'Failed to get loans' });
  }
});

// Approve/Reject Loan (Admin)
app.put('/api/admin/loans/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, rejectionReason } = req.body;
    
    const loan = await Loan.findById(req.params.id).populate('user');
    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }
    
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    loan.status = status;
    loan.approvedBy = req.user._id;
    
    if (status === 'approved') {
      loan.approvalDate = new Date();
      loan.disbursementDate = new Date();
      loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      loan.finalPaymentDate = new Date(Date.now() + loan.termMonths * 30 * 24 * 60 * 60 * 1000);
      
      // Disburse loan to user balance
      const user = await User.findById(loan.user._id);
      user.balance.set('usd', (user.balance.get('usd') || 0) + loan.loanAmount);
      await user.save();
      
      // Create transaction
      await Transaction.create({
        user: loan.user._id,
        type: 'loan',
        amount: loan.loanAmount,
        currency: 'USD',
        status: 'completed',
        description: 'Loan disbursement',
        paymentMethod: 'internal'
      });
    } else if (status === 'rejected') {
      loan.rejectionReason = rejectionReason;
    }
    
    await loan.save();
    
    res.json({
      success: true,
      message: `Loan ${status} successfully`,
      loan
    });
    
    // Log activity
    logActivity(req.user._id, 'loan_review', {
      loanId: loan._id,
      status,
      userId: loan.user._id
    });
  } catch (error) {
    logger.error('Update loan error:', error);
    res.status(500).json({ error: 'Failed to update loan' });
  }
});

// Get System Settings
app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    let settings = await SystemSettings.findOne();
    
    if (!settings) {
      // Create default settings
      settings = await SystemSettings.create({
        name: 'default',
        siteName: 'Hashvex Technologies',
        contactEmail: 'support@hashvex.com',
        supportEmail: 'help@hashvex.com'
      });
    }
    
    res.json({
      success: true,
      settings
    });
  } catch (error) {
    logger.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

// Update System Settings
app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    let settings = await SystemSettings.findOne();
    
    if (!settings) {
      settings = await SystemSettings.create({
        name: 'default',
        ...req.body,
        updatedBy: req.user._id
      });
    } else {
      Object.assign(settings, req.body);
      settings.updatedBy = req.user._id;
      settings.updatedAt = new Date();
      await settings.save();
    }
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings
    });
    
    // Log activity
    logActivity(req.user._id, 'settings_update', req.body);
  } catch (error) {
    logger.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Send Notification to Users
app.post('/api/admin/notifications/send', authenticate, requireAdmin, async (req, res) => {
  try {
    const { subject, message, userType, specificUsers } = req.body;
    
    let users = [];
    
    if (specificUsers && specificUsers.length > 0) {
      users = await User.find({ _id: { $in: specificUsers } });
    } else if (userType === 'all') {
      users = await User.find({});
    } else if (userType === 'verified') {
      users = await User.find({ kycStatus: 'verified' });
    } else if (userType === 'with_miners') {
      // Users with active miners
      const userMiners = await UserMiner.distinct('user', { status: 'active' });
      users = await User.find({ _id: { $in: userMiners } });
    }
    
    // Send emails
    const emailPromises = users.map(user => 
      sendEmail(user.email, subject, 
        `<h2>${subject}</h2>
         <p>${message}</p>
         <p>Best regards,<br>Hashvex Technologies Team</p>`
      )
    );
    
    await Promise.all(emailPromises);
    
    res.json({
      success: true,
      message: `Notification sent to ${users.length} users`
    });
    
    // Log activity
    logActivity(req.user._id, 'notification_sent', {
      subject,
      userCount: users.length,
      userType
    });
  } catch (error) {
    logger.error('Send notification error:', error);
    res.status(500).json({ error: 'Failed to send notifications' });
  }
});

// ==================== INITIAL SETUP ====================

// Create default admin user
const createDefaultAdmin = async () => {
  try {
    const adminEmail = 'admin@hashvex.com';
    const adminPassword = 'Admin@Hashvex2024!'; // Change this in production
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      const admin = await User.create({
        email: adminEmail,
        password: adminPassword,
        firstName: 'System',
        lastName: 'Administrator',
        isAdmin: true,
        isVerified: true,
        kycStatus: 'verified'
      });
      
      logger.info('Default admin user created:', admin.email);
      console.log('=========================================');
      console.log('DEFAULT ADMIN CREDENTIALS:');
      console.log('Email:', adminEmail);
      console.log('Password:', adminPassword);
      console.log('=========================================');
      console.log('CHANGE THESE CREDENTIALS IMMEDIATELY IN PRODUCTION!');
      console.log('=========================================');
    } else {
      logger.info('Admin user already exists');
    }
  } catch (error) {
    logger.error('Failed to create admin user:', error);
  }
};

// Initialize default settings
const initializeSettings = async () => {
  try {
    const settings = await SystemSettings.findOne();
    
    if (!settings) {
      await SystemSettings.create({
        name: 'default',
        siteName: 'Hashvex Technologies',
        siteUrl: 'https://hashvex-technologies.vercel.app',
        contactEmail: 'contact@hashvex.com',
        supportEmail: 'support@hashvex.com',
        minDeposit: 10,
        maxDeposit: 100000,
        minWithdrawal: 50,
        maxWithdrawal: 50000,
        depositFeePercentage: 0,
        withdrawalFeePercentage: 1,
        withdrawalFixedFee: 10,
        miningFeePercentage: 2,
        maintenanceFeePercentage: 5,
        minLoanAmount: 1000,
        maxLoanAmount: 100000,
        baseInterestRate: 5,
        loanTermOptions: [6, 12, 24],
        loginAttemptsBeforeLock: 5,
        lockDurationMinutes: 1440,
        sessionTimeoutMinutes: 120,
        kycRequiredForDeposit: false,
        kycRequiredForWithdrawal: true,
        kycRequiredForLoan: true,
        emailVerificationRequired: true,
        twoFactorRequired: false,
        maintenanceMode: false,
        maintenanceMessage: 'System is undergoing maintenance. We will be back soon.'
      });
      
      logger.info('Default settings initialized');
    }
  } catch (error) {
    logger.error('Failed to initialize settings:', error);
  }
};

// ==================== ERROR HANDLING ====================

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: requestIp.getClientIp(req)
  });
  
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error' 
  });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;

server.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Initialize default data
  await createDefaultAdmin();
  await initializeSettings();
  
  // Warm up cache
  await fetchCryptoPrices();
  
  console.log('Hashvex Backend initialized successfully');
  console.log('Admin panel available at /api/admin/login');
  console.log('API documentation available at /api/health');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  
  // Close connections
  await mongoose.connection.close();
  await redis.quit();
  
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
