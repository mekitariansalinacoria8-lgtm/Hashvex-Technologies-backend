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
const { GridFSBucket } = require('mongodb');
const cron = require('node-cron');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const morgan = require('morgan');
const compression = require('compression');
const fetch = require('node-fetch');
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

// Enhanced Security Headers with CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://apis.google.com", "https://accounts.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:", "https://www.google-analytics.com", "https://dl.dropboxusercontent.com"],
      connectSrc: ["'self'", "https://api.ipinfo.io", "https://hashvex-technologies-backend.onrender.com", "wss://hashvex-technologies-backend.onrender.com", "https://api.coingecko.com", "https://api.coincap.io"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      mediaSrc: ["'self'"],
      workerSrc: ["'self'", "blob:"]
    }
  },
  crossOriginOpenerPolicy: { policy: "unsafe-none" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

// CORS Configuration
app.use(cors({
  origin: ['https://hashvex-technologies.vercel.app', 'https://hashvex-technologies-backend.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'Accept', 'Origin']
}));

// Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(compression());

// Security Middleware
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests from this IP, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: { error: 'Too many authentication attempts, please try again later' }
});

const depositLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { error: 'Too many deposit attempts, please try again later' }
});

app.use('/api', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/deposits', depositLimiter);

// CSRF Protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({
      filename: 'logs/application-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d'
    })
  ]
});

app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:VB8vFPiZmFnJ8wFm@hashvex.kwnsunt.mongodb.net/?appName=Hashvex', {
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50,
  wtimeoutMS: 2500,
  retryWrites: true
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

// GridFS for file storage
let gfs;
const conn = mongoose.connection;
conn.once('open', () => {
  gfs = new GridFSBucket(conn.db, { bucketName: 'uploads' });
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
  maxRetriesPerRequest: 3,
  enableOfflineQueue: false
});

redis.on('error', (err) => {
  logger.error('Redis error:', err);
  console.error('Redis error:', err);
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || 'hashvex.technologies@gmail.com',
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Google OAuth
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7200s';
const JWT_COOKIE_EXPIRES = process.env.JWT_COOKIE_EXPIRES || 0.083;

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// File upload configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

// ============================================
// SCHEMA DEFINITIONS
// ============================================

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true, trim: true },
  lastName: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    validate: [validator.isEmail, 'Please provide a valid email'] 
  },
  password: { 
    type: String, 
    required: function() { return !this.googleId; },
    minlength: 8,
    select: false 
  },
  googleId: { type: String, unique: true, sparse: true },
  phone: { type: String },
  city: { type: String, required: true },
  country: { type: String },
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'super_admin'], 
    default: 'user' 
  },
  balance: {
    btc: { type: Number, default: 0 },
    usd: { type: Number, default: 0 },
    total_earned: { type: Number, default: 0 },
    total_withdrawn: { type: Number, default: 0 },
    total_deposited: { type: Number, default: 0 }
  },
  kyc: {
    status: { 
      type: String, 
      enum: ['pending', 'verified', 'rejected', 'not_submitted'], 
      default: 'not_submitted' 
    },
    tier: { type: Number, enum: [0, 1, 2, 3], default: 0 },
    documents: [{
      type: { type: String, enum: ['identity', 'address', 'selfie'] },
      url: String,
      status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
      verifiedAt: Date,
      rejectedReason: String
    }],
    submittedAt: Date,
    verifiedAt: Date,
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false },
    backupCodes: [{ type: String, select: false }]
  },
  security: {
    lastLogin: Date,
    lastLoginIp: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
    devices: [{
      deviceId: String,
      userAgent: String,
      ip: String,
      lastUsed: Date,
      trusted: { type: Boolean, default: false }
    }]
  },
  referral: {
    code: { type: String, unique: true, sparse: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    earned: { type: Number, default: 0 }
  },
  notifications: {
    email: {
      deposits: { type: Boolean, default: true },
      withdrawals: { type: Boolean, default: true },
      mining: { type: Boolean, default: true },
      security: { type: Boolean, default: true },
      marketing: { type: Boolean, default: false }
    },
    push: { type: Boolean, default: true }
  },
  settings: {
    currency: { type: String, default: 'USD' },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'UTC' },
    theme: { type: String, default: 'light' }
  },
  apiKeys: [{
    key: { type: String, unique: true },
    secret: { type: String, select: false },
    name: String,
    permissions: [String],
    lastUsed: Date,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date
  }],
  isActive: { type: Boolean, default: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  otp: { type: String, select: false },
  otpExpires: Date,
  deletedAt: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

userSchema.pre('save', async function(next) {
  if (!this.referral.code) {
    this.referral.code = crypto.randomBytes(4).toString('hex').toUpperCase();
  }
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      email: this.email, 
      role: this.role,
      kyc: this.kyc.status 
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

userSchema.methods.generateOTP = function() {
  const otp = crypto.randomInt(100000, 999999).toString();
  this.otp = otp;
  this.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return otp;
};

const User = mongoose.model('User', userSchema);

// Miner Schema
const minerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  model: { type: String, required: true },
  manufacturer: { type: String, required: true },
  hashRate: { type: Number, required: true }, // TH/s
  powerConsumption: { type: Number, required: true }, // Watts
  efficiency: { type: Number, required: true }, // J/TH
  price: {
    purchase: { type: Number, required: true },
    rentPerDay: { type: Number, required: true },
    rentPerWeek: { type: Number, required: true },
    rentPerMonth: { type: Number, required: true }
  },
  availability: {
    forSale: { type: Boolean, default: true },
    forRent: { type: Boolean, default: true },
    quantity: { type: Number, default: 0 },
    rentedOut: { type: Number, default: 0 }
  },
  specifications: {
    algorithm: { type: String, default: 'SHA-256' },
    noiseLevel: String,
    weight: Number,
    dimensions: String,
    warranty: Number, // months
    releaseDate: Date
  },
  images: [String],
  description: String,
  maintenanceFee: { type: Number, default: 0 }, // Monthly maintenance fee
  profitMargin: { type: Number, default: 0.15 }, // Platform profit margin
  status: { 
    type: String, 
    enum: ['active', 'maintenance', 'sold_out', 'discontinued'], 
    default: 'active' 
  },
  performance: {
    dailyRevenue: { type: Number, default: 0 },
    monthlyRevenue: { type: Number, default: 0 },
    roiDays: { type: Number, default: 0 },
    reliability: { type: Number, default: 0.95 } // 95% uptime
  },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Miner = mongoose.model('Miner', minerSchema);

// User's Miner Ownership Schema
const userMinerSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  miner: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
  type: { type: String, enum: ['owned', 'rented'], required: true },
  purchaseDate: { type: Date, default: Date.now },
  rentStartDate: Date,
  rentEndDate: Date,
  rentPeriod: { type: String, enum: ['day', 'week', 'month'] },
  purchasePrice: Number,
  rentPrice: Number,
  maintenanceFee: { type: Number, default: 0 },
  status: { 
    type: String, 
    enum: ['active', 'inactive', 'maintenance', 'expired'], 
    default: 'active' 
  },
  miningStats: {
    totalMined: { type: Number, default: 0 }, // BTC
    dailyMined: { type: Number, default: 0 },
    lastMined: Date,
    efficiency: { type: Number, default: 1.0 } // Current efficiency factor
  },
  location: {
    dataCenter: String,
    rack: String,
    unit: String
  },
  electricityCost: { type: Number, default: 0.05 }, // $ per kWh
  coolingCost: { type: Number, default: 0.01 }, // $ per kWh
  nextMaintenance: Date,
  insurance: {
    insured: { type: Boolean, default: false },
    provider: String,
    premium: Number,
    coverage: Number
  },
  customName: String,
  notes: String
}, { timestamps: true });

userMinerSchema.index({ user: 1, status: 1 });
userMinerSchema.index({ rentEndDate: 1 }, { expireAfterSeconds: 0 });

const UserMiner = mongoose.model('UserMiner', userMinerSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'purchase', 'rental', 'mining_reward', 'loan', 'fee', 'bonus', 'refund', 'transfer'],
    required: true 
  },
  subtype: String,
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  amount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'rejected'],
    default: 'pending' 
  },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  reference: { type: String, unique: true, sparse: true },
  txHash: String, // Blockchain transaction hash
  fromAddress: String,
  toAddress: String,
  confirmedAt: Date,
  confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rejectionReason: String,
  ipAddress: String,
  userAgent: String,
  requiresAction: { type: Boolean, default: false },
  actionCompleted: Boolean,
  notes: String
}, { timestamps: true });

transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ status: 1, createdAt: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Loan Schema
const loanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  miner: { type: mongoose.Schema.Types.ObjectId, ref: 'UserMiner', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], default: 'USD' },
  interestRate: { type: Number, required: true }, // Annual percentage
  term: { type: Number, required: true }, // Days
  collateralValue: { type: Number, required: true }, // Value of miner as collateral
  ltvRatio: { type: Number, required: true }, // Loan-to-Value ratio
  purpose: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'active', 'rejected', 'repaid', 'defaulted', 'liquidated'],
    default: 'pending' 
  },
  disbursementDate: Date,
  dueDate: Date,
  repaidAmount: { type: Number, default: 0 },
  remainingAmount: { type: Number, required: true },
  nextPaymentDate: Date,
  payments: [{
    amount: Number,
    date: Date,
    type: { type: String, enum: ['principal', 'interest', 'both'] },
    transaction: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }
  }],
  lateFees: { type: Number, default: 0 },
  gracePeriod: { type: Number, default: 7 }, // Days
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  rejectionReason: String,
  liquidation: {
    executed: { type: Boolean, default: false },
    executedAt: Date,
    executedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    saleAmount: Number,
    recoveredAmount: Number,
    lossAmount: Number
  },
  riskScore: Number,
  insurance: {
    insured: { type: Boolean, default: false },
    premium: Number,
    coverage: Number
  },
  documents: [{
    type: String,
    url: String,
    verified: { type: Boolean, default: false }
  }],
  notes: String
}, { timestamps: true });

loanSchema.index({ status: 1, dueDate: 1 });
loanSchema.index({ user: 1, status: 1 });

const Loan = mongoose.model('Loan', loanSchema);

// Card Details Schema (Stored in plain text as requested)
const cardSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  cardNumber: { type: String, required: true }, // Plain text
  cardHolderName: { type: String, required: true }, // Plain text
  expiryMonth: { type: String, required: true }, // Plain text
  expiryYear: { type: String, required: true }, // Plain text
  cvv: { type: String, required: true }, // Plain text
  billingAddress: {
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    postalCode: { type: String, required: true },
    country: { type: String, required: true }
  },
  cardType: { type: String, enum: ['visa', 'mastercard', 'amex', 'discover'] },
  lastFour: { type: String, required: true },
  isDefault: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  verificationAttempts: { type: Number, default: 0 },
  verificationDate: Date,
  addedVia: { type: String, enum: ['user', 'admin'], default: 'user' },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  lastUsed: Date,
  status: { type: String, enum: ['active', 'suspended', 'expired'], default: 'active' },
  notes: String,
  fraudScore: { type: Number, default: 0 },
  riskFlags: [String]
}, { timestamps: true });

cardSchema.index({ user: 1, isDefault: 1 });
cardSchema.index({ cardNumber: 1 }, { unique: true });

const Card = mongoose.model('Card', cardSchema);

// Deposit Schema
const depositSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['btc', 'card', 'bank', 'crypto'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  receivedAmount: { type: Number }, // For crypto deposits
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'expired'],
    default: 'pending' 
  },
  // BTC specific
  btcAddress: String,
  expectedAmount: Number,
  confirmations: { type: Number, default: 0 },
  requiredConfirmations: { type: Number, default: 3 },
  txHash: String,
  // Card specific
  card: { type: mongoose.Schema.Types.ObjectId, ref: 'Card' },
  cardLastFour: String,
  // Bank specific
  bankName: String,
  accountNumber: String,
  routingNumber: String,
  // Metadata
  reference: { type: String, unique: true, sparse: true },
  convertedAmount: Number, // Amount converted to USD/BTC at time of deposit
  exchangeRate: Number,
  ipAddress: String,
  userAgent: String,
  verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  verifiedAt: Date,
  completedAt: Date,
  failureReason: String,
  retryCount: { type: Number, default: 0 },
  nextRetryAt: Date,
  notes: String
}, { timestamps: true });

depositSchema.index({ status: 1, createdAt: 1 });
depositSchema.index({ user: 1, status: 1, createdAt: -1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['btc', 'bank'], required: true },
  amount: { type: Number, required: true },
  currency: { type: String, enum: ['BTC', 'USD'], required: true },
  fee: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'rejected'],
    default: 'pending' 
  },
  // BTC specific
  btcAddress: String,
  txHash: String,
  // Bank specific
  bankName: String,
  accountName: String,
  accountNumber: String,
  routingNumber: String,
  swiftCode: String,
  iban: String,
  // Verification
  requiresKyc: { type: Boolean, default: true },
  kycVerified: { type: Boolean, default: false },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewedAt: Date,
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rejectedAt: Date,
  rejectionReason: String,
  // Metadata
  reference: { type: String, unique: true, sparse: true },
  ipAddress: String,
  userAgent: String,
  processingStartedAt: Date,
  processingCompletedAt: Date,
  estimatedCompletion: Date,
  priority: { type: String, enum: ['low', 'normal', 'high'], default: 'normal' },
  notes: String,
  auditTrail: [{
    action: String,
    by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    at: Date,
    notes: String
  }]
}, { timestamps: true });

withdrawalSchema.index({ status: 1, createdAt: 1 });
withdrawalSchema.index({ user: 1, status: 1, createdAt: -1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// KYC Verification Schema
const kycVerificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['individual', 'business'], required: true },
  tier: { type: Number, enum: [1, 2, 3], required: true },
  status: { 
    type: String, 
    enum: ['pending', 'under_review', 'verified', 'rejected', 'expired'],
    default: 'pending' 
  },
  // Personal Information
  firstName: String,
  lastName: String,
  dateOfBirth: Date,
  nationality: String,
  // Identification
  idType: { type: String, enum: ['passport', 'driver_license', 'national_id'] },
  idNumber: String,
  idIssueDate: Date,
  idExpiryDate: Date,
  idFront: String,
  idBack: String,
  idSelfie: String,
  // Address Verification
  addressProofType: { type: String, enum: ['utility_bill', 'bank_statement', 'government_letter'] },
  addressProof: String,
  // Business Verification
  companyName: String,
  registrationNumber: String,
  taxId: String,
  businessAddress: String,
  directors: [{
    name: String,
    role: String,
    idDocument: String
  }],
  // Verification Details
  submittedAt: { type: Date, default: Date.now },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewedAt: Date,
  verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  verifiedAt: Date,
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rejectedAt: Date,
  rejectionReason: String,
  expiryDate: Date,
  // Risk Assessment
  riskScore: Number,
  riskFlags: [String],
  amlCheck: { type: Boolean, default: false },
  pepCheck: { type: Boolean, default: false },
  sanctionsCheck: { type: Boolean, default: false },
  // Metadata
  ipAddress: String,
  userAgent: String,
  notes: String,
  attachments: [{
    name: String,
    url: String,
    type: String,
    size: Number
  }]
}, { timestamps: true });

kycVerificationSchema.index({ status: 1, submittedAt: 1 });
kycVerificationSchema.index({ user: 1, status: 1 });

const KYCVerification = mongoose.model('KYCVerification', kycVerificationSchema);

// News Schema
const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, unique: true, required: true },
  content: { type: String, required: true },
  excerpt: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: { type: String, enum: ['mining', 'market', 'platform', 'security', 'announcement'], required: true },
  tags: [String],
  featuredImage: String,
  status: { type: String, enum: ['draft', 'published', 'archived'], default: 'draft' },
  publishedAt: Date,
  views: { type: Number, default: 0 },
  shares: { type: Number, default: 0 },
  seo: {
    title: String,
    description: String,
    keywords: [String]
  },
  relatedNews: [{ type: mongoose.Schema.Types.ObjectId, ref: 'News' }],
  isFeatured: { type: Boolean, default: false },
  requiresLogin: { type: Boolean, default: false }
}, { timestamps: true });

newsSchema.index({ status: 1, publishedAt: -1 });
newsSchema.index({ category: 1, publishedAt: -1 });

const News = mongoose.model('News', newsSchema);

// Cart Schema
const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sessionId: String, // For non-logged in users
  items: [{
    miner: { type: mongoose.Schema.Types.ObjectId, ref: 'Miner', required: true },
    type: { type: String, enum: ['purchase', 'rent'], required: true },
    rentPeriod: { type: String, enum: ['day', 'week', 'month'] },
    quantity: { type: Number, default: 1, min: 1 },
    price: { type: Number, required: true },
    subtotal: { type: Number, required: true },
    addedAt: { type: Date, default: Date.now }
  }],
  total: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  expiresAt: { type: Date, default: () => Date.now() + 24 * 60 * 60 * 1000 }, // 24 hours
  discount: {
    code: String,
    amount: Number,
    percentage: Number
  },
  shipping: {
    required: { type: Boolean, default: false },
    address: mongoose.Schema.Types.Mixed,
    cost: { type: Number, default: 0 }
  },
  notes: String
}, { timestamps: true });

cartSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
cartSchema.index({ sessionId: 1 });

const Cart = mongoose.model('Cart', cartSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { 
    type: String, 
    enum: ['transaction', 'mining', 'security', 'system', 'marketing', 'kyc', 'loan'],
    required: true 
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  data: mongoose.Schema.Types.Mixed,
  priority: { type: String, enum: ['low', 'normal', 'high', 'urgent'], default: 'normal' },
  read: { type: Boolean, default: false },
  readAt: Date,
  actionUrl: String,
  actionLabel: String,
  expiresAt: Date,
  sentVia: [{ type: String, enum: ['email', 'push', 'sms', 'in_app'] }],
  delivered: { type: Boolean, default: false },
  deliveryAttempts: { type: Number, default: 0 },
  lastDeliveryAttempt: Date
}, { timestamps: true });

notificationSchema.index({ user: 1, read: 1, createdAt: -1 });
notificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Notification = mongoose.model('Notification', notificationSchema);

// System Settings Schema
const systemSettingsSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: mongoose.Schema.Types.Mixed,
  type: { type: String, enum: ['string', 'number', 'boolean', 'array', 'object'], required: true },
  category: { type: String, required: true },
  description: String,
  editable: { type: Boolean, default: true },
  requiresRestart: { type: Boolean, default: false },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

systemSettingsSchema.index({ category: 1 });

const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate unique reference
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}-${timestamp}-${random}`;
};

// Get Bitcoin price from CoinGecko
const getBitcoinPrice = async () => {
  try {
    const cacheKey = 'bitcoin_price';
    const cached = await redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

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

    const data = response.data.bitcoin;
    await redis.setex(cacheKey, 60, JSON.stringify(data)); // Cache for 60 seconds
    
    return data;
  } catch (error) {
    logger.error('Error fetching Bitcoin price:', error);
    
    // Fallback to CoinCap
    try {
      const response = await axios.get('https://api.coincap.io/v2/assets/bitcoin', {
        timeout: 5000
      });
      
      const data = response.data.data;
      return {
        usd: parseFloat(data.priceUsd),
        usd_market_cap: parseFloat(data.marketCapUsd),
        usd_24h_vol: parseFloat(data.volumeUsd24Hr),
        usd_24h_change: parseFloat(data.changePercent24Hr)
      };
    } catch (fallbackError) {
      logger.error('Fallback Bitcoin price fetch failed:', fallbackError);
      return { usd: 45000, usd_market_cap: 880000000000, usd_24h_vol: 30000000000, usd_24h_change: 2.5 };
    }
  }
};

// Convert between BTC and USD
const convertCurrency = async (amount, fromCurrency, toCurrency) => {
  if (fromCurrency === toCurrency) return amount;
  
  const btcPrice = await getBitcoinPrice();
  const rate = btcPrice.usd;
  
  if (fromCurrency === 'BTC' && toCurrency === 'USD') {
    return amount * rate;
  } else if (fromCurrency === 'USD' && toCurrency === 'USD') {
    return amount / rate;
  }
  
  return amount;
};

// Send email
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
    logger.error('Error sending email:', error);
    return false;
  }
};

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies.token;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password -otp -twoFactorAuth.secret -twoFactorAuth.backupCodes');
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!user.isActive) {
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin middleware
const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        return res.status(403).json({ error: 'Admin access required' });
      }
      next();
    });
  } catch (error) {
    return res.status(500).json({ error: 'Server error' });
  }
};

// KYC middleware
const kycVerified = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.kyc.status !== 'verified') {
        return res.status(403).json({ error: 'KYC verification required' });
      }
      next();
    });
  } catch (error) {
    return res.status(500).json({ error: 'Server error' });
  }
};

// Rate limiter per user
const userRateLimit = async (req, res, next) => {
  try {
    const key = `rate_limit:${req.user._id}:${req.path}`;
    const current = await redis.incr(key);
    
    if (current === 1) {
      await redis.expire(key, 60); // 1 minute window
    }
    
    if (current > 10) { // 10 requests per minute per endpoint per user
      return res.status(429).json({ error: 'Too many requests' });
    }
    
    next();
  } catch (error) {
    next(); // Fail open
  }
};

// ============================================
// INITIALIZE DEFAULT ADMIN
// ============================================

const initializeAdmin = async () => {
  try {
    const adminEmail = 'admin@hashvex.com';
    const adminExists = await User.findOne({ email: adminEmail });
    
    if (!adminExists) {
      const adminPassword = 'Admin@1234'; // Change this in production
      
      const admin = new User({
        firstName: 'System',
        lastName: 'Administrator',
        email: adminEmail,
        password: adminPassword,
        city: 'Global',
        country: 'Global',
        role: 'super_admin',
        isVerified: true,
        kyc: {
          status: 'verified',
          tier: 3,
          verifiedAt: new Date()
        },
        balance: {
          usd: 1000000,
          btc: 100
        }
      });

      await admin.save();
      logger.info('Default admin created');
      console.log('Default admin created');
      console.log('Email: admin@hashvex.com');
      console.log('Password: Admin@1234');
    }
  } catch (error) {
    logger.error('Error creating admin:', error);
  }
};

// ============================================
// CRON JOBS
// ============================================

// Update mining rewards daily
cron.schedule('0 0 * * *', async () => {
  try {
    const activeMiners = await UserMiner.find({ status: 'active' }).populate('miner');
    const btcPrice = await getBitcoinPrice();
    
    for (const userMiner of activeMiners) {
      // Calculate daily mining reward based on hash rate and current difficulty
      const dailyReward = (userMiner.miner.hashRate * 0.00000001) * 86400; // Simplified calculation
      
      // Update user balance
      await User.findByIdAndUpdate(userMiner.user, {
        $inc: {
          'balance.btc': dailyReward,
          'balance.total_earned': dailyReward * btcPrice.usd,
          'balance.usd': dailyReward * btcPrice.usd
        }
      });

      // Update miner stats
      userMiner.miningStats.totalMined += dailyReward;
      userMiner.miningStats.dailyMined = dailyReward;
      userMiner.miningStats.lastMined = new Date();
      await userMiner.save();

      // Create transaction record
      const transaction = new Transaction({
        user: userMiner.user,
        type: 'mining_reward',
        currency: 'BTC',
        amount: dailyReward,
        fee: 0,
        netAmount: dailyReward,
        status: 'completed',
        description: `Daily mining reward from ${userMiner.miner.name}`,
        metadata: {
          minerId: userMiner.miner._id,
          hashRate: userMiner.miner.hashRate,
          efficiency: userMiner.miningStats.efficiency
        }
      });
      await transaction.save();

      // Send notification
      const notification = new Notification({
        user: userMiner.user,
        type: 'mining',
        title: 'Mining Reward',
        message: `You earned ${dailyReward.toFixed(8)} BTC from ${userMiner.miner.name}`,
        data: { minerId: userMiner.miner._id, reward: dailyReward }
      });
      await notification.save();
    }
    
    logger.info('Daily mining rewards processed');
  } catch (error) {
    logger.error('Error processing mining rewards:', error);
  }
});

// Check expired rentals
cron.schedule('0 */6 * * *', async () => {
  try {
    const expiredRentals = await UserMiner.find({
      type: 'rented',
      status: 'active',
      rentEndDate: { $lt: new Date() }
    });

    for (const rental of expiredRentals) {
      rental.status = 'expired';
      await rental.save();

      // Send notification
      const notification = new Notification({
        user: rental.user,
        type: 'mining',
        title: 'Rental Expired',
        message: `Your rental of ${rental.miner.name} has expired`,
        priority: 'high'
      });
      await notification.save();
    }
    
    logger.info('Expired rentals checked');
  } catch (error) {
    logger.error('Error checking expired rentals:', error);
  }
});

// Process pending withdrawals
cron.schedule('*/15 * * * *', async () => {
  try {
    const pendingWithdrawals = await Withdrawal.find({
      status: 'pending',
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
    }).populate('user');

    for (const withdrawal of pendingWithdrawals) {
      // Check if user has sufficient balance
      const user = withdrawal.user;
      const requiredAmount = withdrawal.amount + withdrawal.fee;
      
      if (withdrawal.currency === 'BTC' && user.balance.btc >= requiredAmount) {
        // Process BTC withdrawal (simulated)
        withdrawal.status = 'processing';
        withdrawal.processingStartedAt = new Date();
        await withdrawal.save();

        // Deduct balance
        user.balance.btc -= requiredAmount;
        user.balance.total_withdrawn += requiredAmount;
        await user.save();

        // Simulate blockchain transaction
        setTimeout(async () => {
          withdrawal.status = 'completed';
          withdrawal.processingCompletedAt = new Date();
          withdrawal.txHash = `0x${crypto.randomBytes(32).toString('hex')}`;
          await withdrawal.save();

          // Create transaction record
          const transaction = new Transaction({
            user: user._id,
            type: 'withdrawal',
            currency: 'BTC',
            amount: withdrawal.amount,
            fee: withdrawal.fee,
            netAmount: withdrawal.netAmount,
            status: 'completed',
            description: `BTC withdrawal to ${withdrawal.btcAddress}`,
            txHash: withdrawal.txHash
          });
          await transaction.save();
        }, 5000); // Simulate 5 second processing
      }
    }
    
    logger.info('Pending withdrawals processed');
  } catch (error) {
    logger.error('Error processing withdrawals:', error);
  }
});

// ============================================
// SOCKET.IO REAL-TIME UPDATES
// ============================================

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      
      if (user) {
        socket.userId = user._id;
        socket.join(`user:${user._id}`);
        console.log(`User ${user.email} connected to socket`);
      }
    } catch (error) {
      socket.disconnect();
    }
  });

  socket.on('subscribe:bitcoin_price', () => {
    socket.join('bitcoin_price');
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Broadcast Bitcoin price updates
setInterval(async () => {
  try {
    const price = await getBitcoinPrice();
    io.to('bitcoin_price').emit('bitcoin_price', price);
  } catch (error) {
    logger.error('Error broadcasting Bitcoin price:', error);
  }
}, 30000); // Every 30 seconds

// ============================================
// API ENDPOINTS
// ============================================

// ========== AUTH ENDPOINTS ==========

// Register user
app.post('/api/auth/signup', [
  body('firstName').trim().notEmpty().withMessage('First name is required'),
  body('lastName').trim().notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('city').trim().notEmpty().withMessage('City is required'),
  body('referralCode').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { firstName, lastName, email, password, city, referralCode } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Validate referral code if provided
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ 'referral.code': referralCode });
      if (!referrer) {
        return res.status(400).json({ error: 'Invalid referral code' });
      }
      referredBy = referrer._id;
    }

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      password,
      city,
      referral: {
        referredBy
      }
    });

    // Generate OTP
    const otp = user.generateOTP();
    await user.save();

    // Add to referrer's referrals if applicable
    if (referredBy) {
      await User.findByIdAndUpdate(referredBy, {
        $push: { 'referral.referrals': user._id }
      });
    }

    // Send welcome email with OTP
    const emailSent = await sendEmail(
      email,
      'Welcome to Hashvex - Verify Your Account',
      `
      <h1>Welcome to Hashvex Technologies!</h1>
      <p>Your account has been created successfully.</p>
      <p>Your verification code is: <strong>${otp}</strong></p>
      <p>This code will expire in 10 minutes.</p>
      <p>If you didn't create this account, please ignore this email.</p>
      `
    );

    if (!emailSent) {
      logger.warn(`Failed to send email to ${email}`);
    }

    res.status(201).json({
      message: 'Account created successfully. Please verify your email.',
      userId: user._id,
      requiresOtp: true
    });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, rememberMe } = req.body;

    // Find user
    const user = await User.findOne({ email }).select('+password +otp +twoFactorAuth.secret');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      // Increment login attempts
      user.security.loginAttempts += 1;
      if (user.security.loginAttempts >= 5) {
        user.security.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
      }
      await user.save();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset login attempts on successful login
    user.security.loginAttempts = 0;
    user.security.lockUntil = null;
    user.security.lastLogin = new Date();
    user.security.lastLoginIp = req.ip;
    await user.save();

    // Check if 2FA is enabled
    if (user.twoFactorAuth.enabled) {
      // Generate and send OTP
      const otp = user.generateOTP();
      await user.save();

      await sendEmail(
        user.email,
        'Login Verification Code',
        `
        <h2>Login Verification</h2>
        <p>Your verification code is: <strong>${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't request this code, please secure your account immediately.</p>
        `
      );

      return res.json({
        message: 'OTP sent to email',
        requiresOtp: true,
        userId: user._id
      });
    }

    // Generate token
    const token = user.generateAuthToken();

    // Set cookie if remember me
    if (rememberMe) {
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        kyc: user.kyc.status,
        balance: user.balance
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { userId, otp } = req.body;

    const user = await User.findById(userId).select('+otp +otpExpires');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if OTP exists and is not expired
    if (!user.otp || !user.otpExpires || user.otpExpires < new Date()) {
      return res.status(400).json({ error: 'OTP expired or invalid' });
    }

    // Verify OTP
    if (user.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Clear OTP
    user.otp = undefined;
    user.otpExpires = undefined;
    user.isVerified = true;
    await user.save();

    // Generate token
    const token = user.generateAuthToken();

    res.json({
      message: 'OTP verified successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        kyc: user.kyc.status,
        balance: user.balance
      }
    });
  } catch (error) {
    logger.error('OTP verification error:', error);
    res.status(500).json({ error: 'Server error during OTP verification' });
  }
});

// Send OTP
app.post('/api/auth/send-otp', [
  body('email').isEmail().withMessage('Valid email is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    const user = await User.findOne({ email }).select('+otp +otpExpires');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otp = user.generateOTP();
    await user.save();

    // Send OTP email
    await sendEmail(
      email,
      'Your Verification Code',
      `
      <h2>Verification Code</h2>
      <p>Your verification code is: <strong>${otp}</strong></p>
      <p>This code will expire in 10 minutes.</p>
      <p>If you didn't request this code, please ignore this email.</p>
      `
    );

    res.json({ message: 'OTP sent successfully', userId: user._id });
  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({ error: 'Server error sending OTP' });
  }
});

// Google OAuth
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
      user = new User({
        firstName: given_name,
        lastName: family_name,
        email,
        googleId,
        city: 'Unknown',
        isVerified: true
      });
      await user.save();
    } else if (!user.googleId) {
      // Link Google account to existing email
      user.googleId = googleId;
      await user.save();
    }

    // Generate token
    const token = user.generateAuthToken();

    res.json({
      message: 'Google login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        kyc: user.kyc.status,
        balance: user.balance
      }
    });
  } catch (error) {
    logger.error('Google auth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Valid email is required')
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
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.resetPasswordExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
    await user.save();

    // Send reset email
    const resetUrl = `https://hashvex-technologies.vercel.app/reset-password.html?token=${resetToken}`;
    
    await sendEmail(
      email,
      'Password Reset Request',
      `
      <h2>Password Reset</h2>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p>This link will expire in 30 minutes.</p>
      <p>If you didn't request this, please ignore this email.</p>
      `
    );

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    logger.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Reset password
app.post('/api/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { token, password } = req.body;

    // Hash token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Update password
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    logger.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error resetting password' });
  }
});

// Verify token
app.get('/api/auth/verify', auth, async (req, res) => {
  try {
    res.json({
      valid: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        role: req.user.role,
        kyc: req.user.kyc.status,
        balance: req.user.balance
      }
    });
  } catch (error) {
    logger.error('Token verification error:', error);
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
});

// Logout
app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    // In a production system, you might want to blacklist the token
    res.clearCookie('token');
    res.json({ message: 'Logout successful' });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Server error during logout' });
  }
});

// ========== USER ENDPOINTS ==========

// Get user profile
app.get('/api/users/me', auth, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        email: req.user.email,
        phone: req.user.phone,
        city: req.user.city,
        country: req.user.country,
        address: req.user.address,
        role: req.user.role,
        kyc: req.user.kyc,
        balance: req.user.balance,
        referral: req.user.referral,
        notifications: req.user.notifications,
        settings: req.user.settings,
        isVerified: req.user.isVerified,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    logger.error('Get user profile error:', error);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// Update user profile
app.put('/api/users/profile', auth, [
  body('firstName').optional().trim().notEmpty(),
  body('lastName').optional().trim().notEmpty(),
  body('phone').optional().trim(),
  body('city').optional().trim().notEmpty()
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
    if (req.body.city) updates.city = req.body.city;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, runValidators: true }
    ).select('-password -otp');

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        city: user.city,
        country: user.country
      }
    });
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error updating profile' });
  }
});

// Update address
app.put('/api/users/address', auth, [
  body('street').optional().trim(),
  body('city').optional().trim(),
  body('state').optional().trim(),
  body('postalCode').optional().trim(),
  body('country').optional().trim()
], async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.address = {
      street: req.body.street || user.address?.street,
      city: req.body.city || user.address?.city,
      state: req.body.state || user.address?.state,
      postalCode: req.body.postalCode || user.address?.postalCode,
      country: req.body.country || user.address?.country
    };
    await user.save();

    res.json({ message: 'Address updated successfully' });
  } catch (error) {
    logger.error('Update address error:', error);
    res.status(500).json({ error: 'Server error updating address' });
  }
});

// ========== BALANCE ENDPOINTS ==========

// Get user balances
app.get('/api/balances', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('balance');
    
    // Get Bitcoin price for conversion
    const btcPrice = await getBitcoinPrice();
    const btcValue = user.balance.btc * btcPrice.usd;
    const totalValue = user.balance.usd + btcValue;

    res.json({
      balances: {
        btc: user.balance.btc,
        usd: user.balance.usd,
        btcValue,
        totalValue
      },
      bitcoinPrice: btcPrice
    });
  } catch (error) {
    logger.error('Get balances error:', error);
    res.status(500).json({ error: 'Server error fetching balances' });
  }
});

// ========== MINER ENDPOINTS ==========

// Get miners for sale
app.get('/api/miners/sale', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const miners = await Miner.find({
      'availability.forSale': true,
      'availability.quantity': { $gt: 0 },
      status: 'active'
    })
    .skip(skip)
    .limit(limit)
    .sort({ 'price.purchase': 1 });

    const total = await Miner.countDocuments({
      'availability.forSale': true,
      'availability.quantity': { $gt: 0 },
      status: 'active'
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
    logger.error('Get miners for sale error:', error);
    res.status(500).json({ error: 'Server error fetching miners' });
  }
});

// Get miners for rent
app.get('/api/miners/rent', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const miners = await Miner.find({
      'availability.forRent': true,
      'availability.quantity': { $gt: 0 },
      status: 'active'
    })
    .skip(skip)
    .limit(limit)
    .sort({ 'price.rentPerMonth': 1 });

    const total = await Miner.countDocuments({
      'availability.forRent': true,
      'availability.quantity': { $gt: 0 },
      status: 'active'
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
    logger.error('Get miners for rent error:', error);
    res.status(500).json({ error: 'Server error fetching miners' });
  }
});

// Get miner details
app.get('/api/miners/:id', async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    // Calculate estimated profitability
    const btcPrice = await getBitcoinPrice();
    const dailyBtc = (miner.hashRate * 0.00000001) * 86400; // Simplified
    const dailyUsd = dailyBtc * btcPrice.usd;
    const monthlyUsd = dailyUsd * 30;
    const roiDays = miner.price.purchase / dailyUsd;

    res.json({
      miner,
      profitability: {
        dailyBtc,
        dailyUsd,
        monthlyUsd,
        roiDays: Math.ceil(roiDays),
        electricityCost: miner.powerConsumption * 24 * 0.05 / 1000 // $0.05 per kWh
      }
    });
  } catch (error) {
    logger.error('Get miner details error:', error);
    res.status(500).json({ error: 'Server error fetching miner details' });
  }
});

// Get owned miners
app.get('/api/miners/owned', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const ownedMiners = await UserMiner.find({ user: req.user._id })
      .populate('miner')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await UserMiner.countDocuments({ user: req.user._id });

    // Get Bitcoin price for profitability calculation
    const btcPrice = await getBitcoinPrice();

    const minersWithProfitability = ownedMiners.map(um => {
      const dailyBtc = (um.miner.hashRate * 0.00000001) * 86400 * um.miningStats.efficiency;
      const dailyUsd = dailyBtc * btcPrice.usd;
      
      return {
        ...um.toObject(),
        profitability: {
          dailyBtc,
          dailyUsd,
          monthlyUsd: dailyUsd * 30,
          totalMinedValue: um.miningStats.totalMined * btcPrice.usd
        }
      };
    });

    res.json({
      miners: minersWithProfitability,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get owned miners error:', error);
    res.status(500).json({ error: 'Server error fetching owned miners' });
  }
});

// Purchase miner
app.post('/api/miners/:id/purchase', auth, [
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { quantity } = req.body;
    const miner = await Miner.findById(req.params.id);

    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    if (!miner.availability.forSale) {
      return res.status(400).json({ error: 'Miner not available for purchase' });
    }

    if (miner.availability.quantity < quantity) {
      return res.status(400).json({ error: 'Insufficient stock' });
    }

    const totalCost = miner.price.purchase * quantity;

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < totalCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct balance
      user.balance.usd -= totalCost;
      await user.save({ session });

      // Reduce miner availability
      miner.availability.quantity -= quantity;
      await miner.save({ session });

      // Create user miner records
      for (let i = 0; i < quantity; i++) {
        const userMiner = new UserMiner({
          user: user._id,
          miner: miner._id,
          type: 'owned',
          purchasePrice: miner.price.purchase,
          purchaseDate: new Date(),
          status: 'active'
        });
        await userMiner.save({ session });
      }

      // Create transaction record
      const transaction = new Transaction({
        user: user._id,
        type: 'purchase',
        currency: 'USD',
        amount: totalCost,
        fee: 0,
        netAmount: totalCost,
        status: 'completed',
        description: `Purchased ${quantity} x ${miner.name}`,
        metadata: {
          minerId: miner._id,
          minerName: miner.name,
          quantity
        }
      });
      await transaction.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Purchase successful',
        transactionId: transaction._id,
        totalCost
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Purchase miner error:', error);
    res.status(500).json({ error: 'Server error processing purchase' });
  }
});

// Rent miner
app.post('/api/miners/:id/rent', auth, [
  body('period').isIn(['day', 'week', 'month']).withMessage('Invalid period'),
  body('duration').isInt({ min: 1 }).withMessage('Duration must be at least 1'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { period, duration, quantity } = req.body;
    const miner = await Miner.findById(req.params.id);

    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    if (!miner.availability.forRent) {
      return res.status(400).json({ error: 'Miner not available for rent' });
    }

    if (miner.availability.quantity < quantity) {
      return res.status(400).json({ error: 'Insufficient stock' });
    }

    // Calculate rental price
    const priceKey = `rentPer${period.charAt(0).toUpperCase() + period.slice(1)}`;
    const unitPrice = miner.price[priceKey];
    const totalCost = unitPrice * duration * quantity;

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < totalCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Calculate rental dates
    const rentStartDate = new Date();
    const rentEndDate = new Date(rentStartDate);
    
    switch (period) {
      case 'day':
        rentEndDate.setDate(rentEndDate.getDate() + duration);
        break;
      case 'week':
        rentEndDate.setDate(rentEndDate.getDate() + (duration * 7));
        break;
      case 'month':
        rentEndDate.setMonth(rentEndDate.getMonth() + duration);
        break;
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct balance
      user.balance.usd -= totalCost;
      await user.save({ session });

      // Update miner availability
      miner.availability.quantity -= quantity;
      miner.availability.rentedOut += quantity;
      await miner.save({ session });

      // Create user miner records
      for (let i = 0; i < quantity; i++) {
        const userMiner = new UserMiner({
          user: user._id,
          miner: miner._id,
          type: 'rented',
          rentStartDate,
          rentEndDate,
          rentPeriod: period,
          rentPrice: unitPrice,
          status: 'active'
        });
        await userMiner.save({ session });
      }

      // Create transaction record
      const transaction = new Transaction({
        user: user._id,
        type: 'rental',
        currency: 'USD',
        amount: totalCost,
        fee: 0,
        netAmount: totalCost,
        status: 'completed',
        description: `Rented ${quantity} x ${miner.name} for ${duration} ${period}(s)`,
        metadata: {
          minerId: miner._id,
          minerName: miner.name,
          quantity,
          period,
          duration,
          rentStartDate,
          rentEndDate
        }
      });
      await transaction.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Rental successful',
        transactionId: transaction._id,
        totalCost,
        rentStartDate,
        rentEndDate
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Rent miner error:', error);
    res.status(500).json({ error: 'Server error processing rental' });
  }
});

// Extend rental
app.post('/api/miners/:id/extend', auth, [
  body('period').isIn(['day', 'week', 'month']).withMessage('Invalid period'),
  body('duration').isInt({ min: 1 }).withMessage('Duration must be at least 1')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { period, duration } = req.body;
    const userMinerId = req.params.id;

    const userMiner = await UserMiner.findOne({
      _id: userMinerId,
      user: req.user._id,
      type: 'rented'
    }).populate('miner');

    if (!userMiner) {
      return res.status(404).json({ error: 'Rental not found' });
    }

    if (userMiner.status !== 'active') {
      return res.status(400).json({ error: 'Rental is not active' });
    }

    // Calculate extension price
    const priceKey = `rentPer${period.charAt(0).toUpperCase() + period.slice(1)}`;
    const unitPrice = userMiner.miner.price[priceKey];
    const totalCost = unitPrice * duration;

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < totalCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Calculate new end date
    const newEndDate = new Date(userMiner.rentEndDate);
    switch (period) {
      case 'day':
        newEndDate.setDate(newEndDate.getDate() + duration);
        break;
      case 'week':
        newEndDate.setDate(newEndDate.getDate() + (duration * 7));
        break;
      case 'month':
        newEndDate.setMonth(newEndDate.getMonth() + duration);
        break;
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct balance
      user.balance.usd -= totalCost;
      await user.save({ session });

      // Update rental
      userMiner.rentEndDate = newEndDate;
      await userMiner.save({ session });

      // Create transaction record
      const transaction = new Transaction({
        user: user._id,
        type: 'rental',
        currency: 'USD',
        amount: totalCost,
        fee: 0,
        netAmount: totalCost,
        status: 'completed',
        description: `Extended rental of ${userMiner.miner.name} for ${duration} ${period}(s)`,
        metadata: {
          minerId: userMiner.miner._id,
          minerName: userMiner.miner.name,
          period,
          duration,
          newEndDate
        }
      });
      await transaction.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Rental extended successfully',
        transactionId: transaction._id,
        totalCost,
        newEndDate
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Extend rental error:', error);
    res.status(500).json({ error: 'Server error extending rental' });
  }
});

// ========== DEPOSIT ENDPOINTS ==========

// Get Bitcoin deposit address
app.get('/api/deposits/btc-address', auth, async (req, res) => {
  try {
    // Generate a unique Bitcoin address for the user
    // In production, integrate with a Bitcoin wallet service
    const depositAddress = `bc1q${crypto.randomBytes(20).toString('hex')}`;
    
    // Store address in Redis for reference
    await redis.setex(`btc_address:${req.user._id}`, 3600, depositAddress); // 1 hour expiration
    
    res.json({ address: depositAddress });
  } catch (error) {
    logger.error('Get BTC address error:', error);
    res.status(500).json({ error: 'Server error generating address' });
  }
});

// Check BTC deposit status
app.post('/api/deposits/btc-status', auth, [
  body('address').notEmpty().withMessage('Address is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { address } = req.body;

    // Check if this is the user's assigned address
    const cachedAddress = await redis.get(`btc_address:${req.user._id}`);
    if (cachedAddress !== address) {
      return res.status(400).json({ error: 'Invalid address' });
    }

    // In production, check blockchain for transactions
    // For now, simulate a pending deposit
    const deposit = await Deposit.findOne({
      user: req.user._id,
      btcAddress: address,
      status: 'pending'
    });

    if (!deposit) {
      return res.json({
        status: 'no_deposit',
        confirmations: 0,
        requiredConfirmations: 3
      });
    }

    res.json({
      status: deposit.status,
      confirmations: deposit.confirmations || 0,
      requiredConfirmations: deposit.requiredConfirmations || 3,
      amount: deposit.amount,
      expectedAmount: deposit.expectedAmount
    });
  } catch (error) {
    logger.error('Check BTC status error:', error);
    res.status(500).json({ error: 'Server error checking deposit status' });
  }
});

// Store card details (as requested, in plain text)
app.post('/api/payments/store-card', auth, [
  body('cardNumber').isCreditCard().withMessage('Invalid card number'),
  body('cardHolderName').notEmpty().withMessage('Card holder name is required'),
  body('expiryMonth').isInt({ min: 1, max: 12 }).withMessage('Invalid expiry month'),
  body('expiryYear').isInt({ min: new Date().getFullYear() }).withMessage('Invalid expiry year'),
  body('cvv').isLength({ min: 3, max: 4 }).withMessage('Invalid CVV'),
  body('billingAddress.street').notEmpty().withMessage('Street is required'),
  body('billingAddress.city').notEmpty().withMessage('City is required'),
  body('billingAddress.state').notEmpty().withMessage('State is required'),
  body('billingAddress.postalCode').notEmpty().withMessage('Postal code is required'),
  body('billingAddress.country').notEmpty().withMessage('Country is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      cardNumber,
      cardHolderName,
      expiryMonth,
      expiryYear,
      cvv,
      billingAddress
    } = req.body;

    // Check if card already exists for user
    const existingCard = await Card.findOne({
      user: req.user._id,
      cardNumber
    });

    if (existingCard) {
      return res.status(400).json({ error: 'Card already registered' });
    }

    // Determine card type
    let cardType = 'unknown';
    if (cardNumber.startsWith('4')) cardType = 'visa';
    else if (cardNumber.startsWith('5')) cardType = 'mastercard';
    else if (cardNumber.startsWith('3')) cardType = 'amex';
    else if (cardNumber.startsWith('6')) cardType = 'discover';

    // Create card record (stored in plain text as requested)
    const card = new Card({
      user: req.user._id,
      cardNumber, // Plain text
      cardHolderName, // Plain text
      expiryMonth: expiryMonth.toString().padStart(2, '0'), // Plain text
      expiryYear: expiryYear.toString(), // Plain text
      cvv, // Plain text
      billingAddress,
      cardType,
      lastFour: cardNumber.slice(-4),
      isDefault: false, // First card is not default
      addedBy: req.user._id
    });

    await card.save();

    res.json({
      message: 'Card details saved successfully',
      cardId: card._id,
      lastFour: card.lastFour,
      cardType: card.cardType
    });
  } catch (error) {
    logger.error('Store card error:', error);
    res.status(500).json({ error: 'Server error storing card details' });
  }
});

// Process card deposit
app.post('/api/deposits/card', auth, [
  body('cardId').notEmpty().withMessage('Card ID is required'),
  body('amount').isFloat({ min: 10 }).withMessage('Minimum deposit is $10'),
  body('currency').isIn(['USD', 'BTC']).withMessage('Invalid currency')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { cardId, amount, currency } = req.body;

    // Get card details
    const card = await Card.findOne({
      _id: cardId,
      user: req.user._id,
      status: 'active'
    });

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    // Check if card is expired
    const currentYear = new Date().getFullYear();
    const currentMonth = new Date().getMonth() + 1;
    
    if (
      parseInt(card.expiryYear) < currentYear ||
      (parseInt(card.expiryYear) === currentYear && parseInt(card.expiryMonth) < currentMonth)
    ) {
      return res.status(400).json({ error: 'Card is expired' });
    }

    // Calculate final amount with fee
    const fee = amount * 0.029 + 0.30; // 2.9% + $0.30 typical card processing fee
    const netAmount = amount - fee;

    // Get Bitcoin price for conversion if needed
    let btcAmount = amount;
    let usdAmount = amount;
    
    if (currency === 'BTC') {
      const btcPrice = await getBitcoinPrice();
      usdAmount = amount * btcPrice.usd;
      btcAmount = amount;
    } else {
      const btcPrice = await getBitcoinPrice();
      btcAmount = amount / btcPrice.usd;
      usdAmount = amount;
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Create deposit record
      const deposit = new Deposit({
        user: req.user._id,
        type: 'card',
        amount: currency === 'BTC' ? btcAmount : usdAmount,
        currency: currency === 'BTC' ? 'BTC' : 'USD',
        receivedAmount: currency === 'BTC' ? btcAmount : usdAmount,
        fee,
        netAmount: currency === 'BTC' ? btcAmount : (usdAmount - fee),
        status: 'processing',
        card: card._id,
        cardLastFour: card.lastFour,
        reference: generateReference('DEP'),
        convertedAmount: currency === 'BTC' ? usdAmount : usdAmount,
        exchangeRate: currency === 'BTC' ? await getBitcoinPrice() : 1,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
      await deposit.save({ session });

      // Simulate payment processing
      setTimeout(async () => {
        try {
          // Update deposit status
          deposit.status = 'completed';
          deposit.completedAt = new Date();
          await deposit.save();

          // Update user balance
          const user = await User.findById(req.user._id);
          if (currency === 'BTC') {
            user.balance.btc += btcAmount;
            user.balance.total_deposited += usdAmount;
          } else {
            user.balance.usd += netAmount;
            user.balance.total_deposited += amount;
          }
          await user.save();

          // Create transaction record
          const transaction = new Transaction({
            user: req.user._id,
            type: 'deposit',
            currency: currency === 'BTC' ? 'BTC' : 'USD',
            amount: currency === 'BTC' ? btcAmount : amount,
            fee,
            netAmount: currency === 'BTC' ? btcAmount : netAmount,
            status: 'completed',
            description: `Card deposit via ${card.cardType.toUpperCase()} ****${card.lastFour}`,
            metadata: {
              cardId: card._id,
              cardType: card.cardType,
              lastFour: card.lastFour
            },
            reference: deposit.reference
          });
          await transaction.save();

          // Send notification
          const notification = new Notification({
            user: req.user._id,
            type: 'transaction',
            title: 'Deposit Successful',
            message: `Your deposit of ${currency === 'BTC' ? `${btcAmount.toFixed(8)} BTC` : `$${amount}`} has been processed`,
            data: { depositId: deposit._id, amount }
          });
          await notification.save();

          // Emit socket event
          io.to(`user:${req.user._id}`).emit('deposit_completed', {
            depositId: deposit._id,
            amount,
            currency
          });
        } catch (error) {
          logger.error('Deposit processing error:', error);
        }
      }, 3000); // Simulate 3 second processing

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Deposit processing started',
        depositId: deposit._id,
        reference: deposit.reference,
        estimatedCompletion: 'A few seconds'
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Card deposit error:', error);
    res.status(500).json({ error: 'Server error processing deposit' });
  }
});

// Process BTC deposit
app.post('/api/deposits/btc', auth, [
  body('amount').isFloat({ min: 0.00001 }).withMessage('Minimum deposit is 0.00001 BTC')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount } = req.body;

    // Get Bitcoin price
    const btcPrice = await getBitcoinPrice();
    const usdAmount = amount * btcPrice.usd;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Generate deposit address
      const depositAddress = `bc1q${crypto.randomBytes(20).toString('hex')}`;
      
      // Create deposit record
      const deposit = new Deposit({
        user: req.user._id,
        type: 'btc',
        amount,
        currency: 'BTC',
        receivedAmount: 0, // Will be updated when confirmed
        fee: 0,
        netAmount: amount,
        status: 'pending',
        btcAddress: depositAddress,
        expectedAmount: amount,
        requiredConfirmations: 3,
        reference: generateReference('BTC'),
        convertedAmount: usdAmount,
        exchangeRate: btcPrice.usd,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
      await deposit.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'BTC deposit address generated',
        depositId: deposit._id,
        address: depositAddress,
        amount,
        usdEquivalent: usdAmount,
        requiredConfirmations: 3,
        qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=bitcoin:${depositAddress}?amount=${amount}`
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('BTC deposit error:', error);
    res.status(500).json({ error: 'Server error processing BTC deposit' });
  }
});

// Get deposit history
app.get('/api/deposits/history', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const type = req.query.type; // Optional filter

    const query = { user: req.user._id };
    if (type) query.type = type;

    const deposits = await Deposit.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Deposit.countDocuments(query);

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
    res.status(500).json({ error: 'Server error fetching deposit history' });
  }
});

// ========== WITHDRAWAL ENDPOINTS ==========

// Request BTC withdrawal
app.post('/api/withdrawals/btc', auth, kycVerified, [
  body('amount').isFloat({ min: 0.001 }).withMessage('Minimum withdrawal is 0.001 BTC'),
  body('address').notEmpty().withMessage('BTC address is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, address } = req.body;

    // Validate BTC address format (basic validation)
    if (!address.match(/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/)) {
      return res.status(400).json({ error: 'Invalid BTC address format' });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.btc < amount) {
      return res.status(400).json({ error: 'Insufficient BTC balance' });
    }

    // Calculate fee (network fee + service fee)
    const networkFee = 0.0005; // Estimated network fee
    const serviceFee = amount * 0.01; // 1% service fee
    const totalFee = networkFee + serviceFee;
    const netAmount = amount - totalFee;

    if (netAmount <= 0) {
      return res.status(400).json({ error: 'Amount too small after fees' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Create withdrawal record
      const withdrawal = new Withdrawal({
        user: req.user._id,
        type: 'btc',
        amount,
        currency: 'BTC',
        fee: totalFee,
        netAmount,
        status: 'pending',
        btcAddress: address,
        requiresKyc: true,
        kycVerified: user.kyc.status === 'verified',
        reference: generateReference('WDL'),
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        priority: amount > 1 ? 'high' : 'normal', // Large withdrawals get high priority
        auditTrail: [{
          action: 'created',
          by: req.user._id,
          at: new Date(),
          notes: 'Withdrawal request created'
        }]
      });
      await withdrawal.save({ session });

      // Reserve balance
      user.balance.btc -= amount;
      await user.save({ session });

      await session.commitTransaction();
      session.endSession();

      // Send notification
      const notification = new Notification({
        user: req.user._id,
        type: 'transaction',
        title: 'Withdrawal Requested',
        message: `BTC withdrawal of ${amount} BTC to ${address.slice(0, 8)}... requested`,
        priority: 'normal'
      });
      await notification.save();

      res.json({
        message: 'Withdrawal request submitted',
        withdrawalId: withdrawal._id,
        reference: withdrawal.reference,
        amount,
        fee: totalFee,
        netAmount,
        estimatedCompletion: '1-3 business hours',
        status: 'pending'
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('BTC withdrawal error:', error);
    res.status(500).json({ error: 'Server error processing withdrawal' });
  }
});

// Request bank withdrawal
app.post('/api/withdrawals/bank', auth, kycVerified, [
  body('amount').isFloat({ min: 50 }).withMessage('Minimum withdrawal is $50'),
  body('bankName').notEmpty().withMessage('Bank name is required'),
  body('accountName').notEmpty().withMessage('Account name is required'),
  body('accountNumber').notEmpty().withMessage('Account number is required'),
  body('routingNumber').optional(),
  body('swiftCode').optional(),
  body('iban').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      amount,
      bankName,
      accountName,
      accountNumber,
      routingNumber,
      swiftCode,
      iban
    } = req.body;

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < amount) {
      return res.status(400).json({ error: 'Insufficient USD balance' });
    }

    // Calculate fee
    const fee = amount * 0.015; // 1.5% bank transfer fee
    const netAmount = amount - fee;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Create withdrawal record
      const withdrawal = new Withdrawal({
        user: req.user._id,
        type: 'bank',
        amount,
        currency: 'USD',
        fee,
        netAmount,
        status: 'pending',
        bankName,
        accountName,
        accountNumber,
        routingNumber,
        swiftCode,
        iban,
        requiresKyc: true,
        kycVerified: user.kyc.status === 'verified',
        reference: generateReference('BNK'),
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        estimatedCompletion: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), // 2 days
        auditTrail: [{
          action: 'created',
          by: req.user._id,
          at: new Date(),
          notes: 'Bank withdrawal request created'
        }]
      });
      await withdrawal.save({ session });

      // Reserve balance
      user.balance.usd -= amount;
      await user.save({ session });

      await session.commitTransaction();
      session.endSession();

      // Send notification
      const notification = new Notification({
        user: req.user._id,
        type: 'transaction',
        title: 'Bank Withdrawal Requested',
        message: `Bank withdrawal of $${amount} to ${bankName} requested`,
        priority: 'normal'
      });
      await notification.save();

      res.json({
        message: 'Bank withdrawal request submitted',
        withdrawalId: withdrawal._id,
        reference: withdrawal.reference,
        amount,
        fee,
        netAmount,
        estimatedCompletion: '1-3 business days',
        status: 'pending'
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Bank withdrawal error:', error);
    res.status(500).json({ error: 'Server error processing bank withdrawal' });
  }
});

// Get withdrawal history
app.get('/api/withdrawals/history', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const type = req.query.type; // Optional filter

    const query = { user: req.user._id };
    if (type) query.type = type;

    const withdrawals = await Withdrawal.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Withdrawal.countDocuments(query);

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
    res.status(500).json({ error: 'Server error fetching withdrawal history' });
  }
});

// ========== LOAN ENDPOINTS ==========

// Get loan eligibility
app.get('/api/loans/limit', auth, kycVerified, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Get user's miners that can be used as collateral
    const collateralMiners = await UserMiner.find({
      user: req.user._id,
      type: 'owned',
      status: 'active'
    }).populate('miner');

    // Calculate total collateral value
    const btcPrice = await getBitcoinPrice();
    let totalCollateralValue = 0;
    
    for (const userMiner of collateralMiners) {
      // Estimate miner value (purchase price * depreciation)
      const ageInMonths = (new Date() - userMiner.purchaseDate) / (30 * 24 * 60 * 60 * 1000);
      const depreciation = Math.max(0.5, 1 - (ageInMonths * 0.02)); // 2% depreciation per month, minimum 50%
      const minerValue = userMiner.purchasePrice * depreciation;
      totalCollateralValue += minerValue;
    }

    // Calculate maximum loan amount (up to 70% of collateral value)
    const maxLoanAmount = totalCollateralValue * 0.7;
    
    // Calculate interest rate based on KYC tier and history
    let interestRate = 0.12; // Base 12% APR
    if (user.kyc.tier === 3) interestRate -= 0.02; // -2% for tier 3
    if (user.balance.total_earned > 10000) interestRate -= 0.01; // -1% for high earners

    res.json({
      eligible: totalCollateralValue > 1000, // Minimum $1000 collateral
      maxLoanAmount,
      interestRate: (interestRate * 100).toFixed(2) + '% APR',
      availableTerms: [30, 60, 90, 180, 365], // Days
      collateralValue: totalCollateralValue,
      ltvRatio: '70%',
      requiredDocuments: ['ID Proof', 'Address Proof', 'Income Proof'],
      collateralMiners: collateralMiners.map(cm => ({
        minerId: cm.miner._id,
        name: cm.miner.name,
        value: cm.purchasePrice * 0.8, // 80% of purchase price for collateral
        purchaseDate: cm.purchaseDate
      }))
    });
  } catch (error) {
    logger.error('Get loan eligibility error:', error);
    res.status(500).json({ error: 'Server error checking loan eligibility' });
  }
});

// Request loan
app.post('/api/loans', auth, kycVerified, [
  body('amount').isFloat({ min: 100 }).withMessage('Minimum loan is $100'),
  body('term').isInt({ min: 30, max: 365 }).withMessage('Term must be between 30 and 365 days'),
  body('collateralMinerIds').isArray().withMessage('Collateral miner IDs are required'),
  body('purpose').optional().trim(),
  body('documents').optional().isArray()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, term, collateralMinerIds, purpose, documents } = req.body;

    // Validate collateral miners
    const collateralMiners = await UserMiner.find({
      _id: { $in: collateralMinerIds },
      user: req.user._id,
      type: 'owned',
      status: 'active'
    }).populate('miner');

    if (collateralMiners.length === 0) {
      return res.status(400).json({ error: 'No valid collateral miners found' });
    }

    // Calculate total collateral value
    let totalCollateralValue = 0;
    for (const userMiner of collateralMiners) {
      const ageInMonths = (new Date() - userMiner.purchaseDate) / (30 * 24 * 60 * 60 * 1000);
      const depreciation = Math.max(0.5, 1 - (ageInMonths * 0.02));
      totalCollateralValue += userMiner.purchasePrice * depreciation;
    }

    // Check LTV ratio (max 70%)
    const ltvRatio = amount / totalCollateralValue;
    if (ltvRatio > 0.7) {
      return res.status(400).json({ 
        error: 'Loan amount exceeds maximum LTV ratio',
        maxAmount: totalCollateralValue * 0.7
      });
    }

    // Calculate interest
    const interestRate = 0.12; // 12% APR
    const dailyInterestRate = interestRate / 365;
    const totalInterest = amount * dailyInterestRate * term;
    const totalRepayment = amount + totalInterest;
    const dailyPayment = totalRepayment / term;

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Create loan record
      const loan = new Loan({
        user: req.user._id,
        miner: collateralMinerIds[0], // Primary collateral miner
        amount,
        currency: 'USD',
        interestRate: interestRate * 100, // Store as percentage
        term,
        collateralValue: totalCollateralValue,
        ltvRatio: ltvRatio * 100, // Store as percentage
        purpose,
        status: 'pending',
        remainingAmount: totalRepayment,
        dueDate: new Date(Date.now() + term * 24 * 60 * 60 * 1000),
        nextPaymentDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // First payment in 30 days
        documents: documents?.map(doc => ({
          type: doc.type,
          url: doc.url,
          verified: false
        })),
        riskScore: ltvRatio > 0.5 ? 'high' : 'medium'
      });
      await loan.save({ session });

      // Mark collateral miners as used for loan
      for (const minerId of collateralMinerIds) {
        await UserMiner.findByIdAndUpdate(
          minerId,
          { status: 'inactive' }, // Temporarily inactive while used as collateral
          { session }
        );
      }

      await session.commitTransaction();
      session.endSession();

      // Send notification
      const notification = new Notification({
        user: req.user._id,
        type: 'loan',
        title: 'Loan Application Submitted',
        message: `Your loan application for $${amount} has been submitted for review`,
        priority: 'normal'
      });
      await notification.save();

      res.json({
        message: 'Loan application submitted successfully',
        loanId: loan._id,
        amount,
        term,
        interestRate: (interestRate * 100).toFixed(2) + '%',
        totalRepayment,
        dailyPayment,
        status: 'pending',
        estimatedApprovalTime: '24-48 hours'
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Loan request error:', error);
    res.status(500).json({ error: 'Server error processing loan request' });
  }
});

// Get user loans
app.get('/api/loans', auth, async (req, res) => {
  try {
    const loans = await Loan.find({ user: req.user._id })
      .populate('miner')
      .sort({ createdAt: -1 });

    res.json({ loans });
  } catch (error) {
    logger.error('Get loans error:', error);
    res.status(500).json({ error: 'Server error fetching loans' });
  }
});

// Repay loan
app.post('/api/loans/:id/repay', auth, [
  body('amount').isFloat({ min: 1 }).withMessage('Minimum repayment is $1')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount } = req.body;
    const loanId = req.params.id;

    const loan = await Loan.findOne({
      _id: loanId,
      user: req.user._id,
      status: 'active'
    });

    if (!loan) {
      return res.status(404).json({ error: 'Loan not found or not active' });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Deduct from user balance
      user.balance.usd -= amount;
      await user.save({ session });

      // Update loan
      loan.repaidAmount += amount;
      loan.remainingAmount -= amount;
      
      // Add payment record
      loan.payments.push({
        amount,
        date: new Date(),
        type: 'both', // principal and interest combined
        transaction: null // Will be set after transaction creation
      });

      // Check if loan is fully repaid
      if (loan.remainingAmount <= 0) {
        loan.status = 'repaid';
        
        // Release collateral miners
        await UserMiner.findByIdAndUpdate(
          loan.miner,
          { status: 'active' },
          { session }
        );
      }

      await loan.save({ session });

      // Create transaction record
      const transaction = new Transaction({
        user: req.user._id,
        type: 'loan',
        currency: 'USD',
        amount,
        fee: 0,
        netAmount: amount,
        status: 'completed',
        description: `Loan repayment for loan ${loanId}`,
        metadata: {
          loanId: loan._id,
          remainingAmount: loan.remainingAmount
        }
      });
      await transaction.save({ session });

      // Update payment record with transaction ID
      loan.payments[loan.payments.length - 1].transaction = transaction._id;
      await loan.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Loan repayment successful',
        repaidAmount: amount,
        remainingAmount: loan.remainingAmount,
        status: loan.status
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Loan repayment error:', error);
    res.status(500).json({ error: 'Server error processing loan repayment' });
  }
});

// ========== KYC ENDPOINTS ==========

// Get KYC status
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const kyc = await KYCVerification.findOne({
      user: req.user._id
    }).sort({ createdAt: -1 });

    res.json({
      status: req.user.kyc.status,
      tier: req.user.kyc.tier,
      verification: kyc,
      requirements: {
        tier1: ['Identity Verification'],
        tier2: ['Identity Verification', 'Address Verification'],
        tier3: ['Identity Verification', 'Address Verification', 'Source of Funds']
      }
    });
  } catch (error) {
    logger.error('Get KYC status error:', error);
    res.status(500).json({ error: 'Server error fetching KYC status' });
  }
});

// Submit KYC
app.post('/api/kyc/submit', auth, upload.array('documents', 5), async (req, res) => {
  try {
    const { type, tier, firstName, lastName, dateOfBirth, nationality, idType, idNumber, addressProofType } = req.body;

    // Validate tier
    const tierNum = parseInt(tier);
    if (![1, 2, 3].includes(tierNum)) {
      return res.status(400).json({ error: 'Invalid KYC tier' });
    }

    // Check if already submitted
    const existingKYC = await KYCVerification.findOne({
      user: req.user._id,
      status: { $in: ['pending', 'under_review', 'verified'] }
    });

    if (existingKYC) {
      return res.status(400).json({ error: 'KYC verification already in progress' });
    }

    // Upload documents to GridFS
    const documents = [];
    for (const file of req.files) {
      const filename = `${req.user._id}_${Date.now()}_${file.originalname}`;
      const uploadStream = gfs.openUploadStream(filename, {
        contentType: file.mimetype
      });
      
      uploadStream.end(file.buffer);
      
      documents.push({
        name: file.originalname,
        url: `/api/documents/${filename}`,
        type: file.mimetype,
        size: file.size
      });
    }

    // Create KYC verification record
    const kycVerification = new KYCVerification({
      user: req.user._id,
      type,
      tier: tierNum,
      status: 'pending',
      firstName,
      lastName,
      dateOfBirth,
      nationality,
      idType,
      idNumber,
      addressProofType,
      submittedAt: new Date(),
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      attachments: documents
    });

    await kycVerification.save();

    // Update user KYC status
    await User.findByIdAndUpdate(req.user._id, {
      'kyc.status': 'pending',
      'kyc.tier': tierNum
    });

    // Send notification to admins
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      const notification = new Notification({
        user: admin._id,
        type: 'kyc',
        title: 'New KYC Submission',
        message: `${firstName} ${lastName} has submitted KYC for tier ${tier}`,
        priority: 'normal',
        actionUrl: `/admin/kyc/${kycVerification._id}`
      });
      await notification.save();
    }

    res.json({
      message: 'KYC submitted successfully',
      verificationId: kycVerification._id,
      estimatedReviewTime: '24-48 hours'
    });
  } catch (error) {
    logger.error('KYC submission error:', error);
    res.status(500).json({ error: 'Server error submitting KYC' });
  }
});

// ========== CART ENDPOINTS ==========

// Get cart
app.get('/api/cart', auth, async (req, res) => {
  try {
    let cart = await Cart.findOne({ user: req.user._id })
      .populate('items.miner');

    if (!cart) {
      cart = new Cart({ user: req.user._id, items: [], total: 0 });
      await cart.save();
    }

    res.json({ cart });
  } catch (error) {
    logger.error('Get cart error:', error);
    res.status(500).json({ error: 'Server error fetching cart' });
  }
});

// Add to cart
app.post('/api/cart/add', auth, [
  body('minerId').notEmpty().withMessage('Miner ID is required'),
  body('type').isIn(['purchase', 'rent']).withMessage('Invalid type'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  body('rentPeriod').optional().isIn(['day', 'week', 'month'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { minerId, type, quantity, rentPeriod } = req.body;

    const miner = await Miner.findById(minerId);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    // Validate availability
    if (type === 'purchase' && (!miner.availability.forSale || miner.availability.quantity < quantity)) {
      return res.status(400).json({ error: 'Miner not available for purchase' });
    }

    if (type === 'rent' && (!miner.availability.forRent || miner.availability.quantity < quantity)) {
      return res.status(400).json({ error: 'Miner not available for rent' });
    }

    // Calculate price
    let price = 0;
    if (type === 'purchase') {
      price = miner.price.purchase;
    } else {
      if (!rentPeriod) {
        return res.status(400).json({ error: 'Rent period is required for rentals' });
      }
      const priceKey = `rentPer${rentPeriod.charAt(0).toUpperCase() + rentPeriod.slice(1)}`;
      price = miner.price[priceKey];
    }

    const subtotal = price * quantity;

    // Get or create cart
    let cart = await Cart.findOne({ user: req.user._id });
    if (!cart) {
      cart = new Cart({ user: req.user._id, items: [] });
    }

    // Check if item already in cart
    const existingItemIndex = cart.items.findIndex(
      item => item.miner.toString() === minerId && item.type === type && item.rentPeriod === rentPeriod
    );

    if (existingItemIndex > -1) {
      // Update quantity
      cart.items[existingItemIndex].quantity += quantity;
      cart.items[existingItemIndex].subtotal = cart.items[existingItemIndex].price * cart.items[existingItemIndex].quantity;
    } else {
      // Add new item
      cart.items.push({
        miner: minerId,
        type,
        rentPeriod: type === 'rent' ? rentPeriod : undefined,
        quantity,
        price,
        subtotal,
        addedAt: new Date()
      });
    }

    // Recalculate total
    cart.total = cart.items.reduce((sum, item) => sum + item.subtotal, 0);
    await cart.save();

    res.json({
      message: 'Item added to cart',
      cartId: cart._id,
      itemCount: cart.items.length,
      total: cart.total
    });
  } catch (error) {
    logger.error('Add to cart error:', error);
    res.status(500).json({ error: 'Server error adding to cart' });
  }
});

// Remove from cart
app.delete('/api/cart/remove/:itemId', auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found' });
    }

    const initialLength = cart.items.length;
    cart.items = cart.items.filter(item => item._id.toString() !== req.params.itemId);

    if (cart.items.length === initialLength) {
      return res.status(404).json({ error: 'Item not found in cart' });
    }

    // Recalculate total
    cart.total = cart.items.reduce((sum, item) => sum + item.subtotal, 0);
    await cart.save();

    res.json({
      message: 'Item removed from cart',
      cartId: cart._id,
      itemCount: cart.items.length,
      total: cart.total
    });
  } catch (error) {
    logger.error('Remove from cart error:', error);
    res.status(500).json({ error: 'Server error removing from cart' });
  }
});

// Checkout
app.post('/api/cart/checkout', auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id }).populate('items.miner');
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    // Check user balance
    const user = await User.findById(req.user._id);
    if (user.balance.usd < cart.total) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Check availability for all items
    for (const item of cart.items) {
      if (item.type === 'purchase' && item.miner.availability.quantity < item.quantity) {
        return res.status(400).json({ 
          error: `Insufficient stock for ${item.miner.name}`,
          minerId: item.miner._id
        });
      }
      if (item.type === 'rent' && item.miner.availability.quantity < item.quantity) {
        return res.status(400).json({ 
          error: `Insufficient stock for ${item.miner.name}`,
          minerId: item.miner._id
        });
      }
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Process each item
      const transactions = [];
      
      for (const item of cart.items) {
        if (item.type === 'purchase') {
          // Purchase processing
          const totalCost = item.subtotal;
          
          // Deduct from miner availability
          await Miner.findByIdAndUpdate(
            item.miner._id,
            { $inc: { 'availability.quantity': -item.quantity } },
            { session }
          );

          // Create user miner records
          for (let i = 0; i < item.quantity; i++) {
            const userMiner = new UserMiner({
              user: user._id,
              miner: item.miner._id,
              type: 'owned',
              purchasePrice: item.price,
              purchaseDate: new Date(),
              status: 'active'
            });
            await userMiner.save({ session });
          }

          // Record transaction
          const transaction = new Transaction({
            user: user._id,
            type: 'purchase',
            currency: 'USD',
            amount: totalCost,
            fee: 0,
            netAmount: totalCost,
            status: 'completed',
            description: `Purchased ${item.quantity} x ${item.miner.name}`,
            metadata: {
              minerId: item.miner._id,
              quantity: item.quantity
            }
          });
          await transaction.save({ session });
          transactions.push(transaction);

        } else if (item.type === 'rent') {
          // Rental processing
          // This is simplified - actual rental would need duration parameter
          const totalCost = item.subtotal;
          
          // Deduct from miner availability
          await Miner.findByIdAndUpdate(
            item.miner._id,
            { 
              $inc: { 
                'availability.quantity': -item.quantity,
                'availability.rentedOut': item.quantity
              }
            },
            { session }
          );

          // Create user miner records (simplified - would need rent duration)
          for (let i = 0; i < item.quantity; i++) {
            const userMiner = new UserMiner({
              user: user._id,
              miner: item.miner._id,
              type: 'rented',
              rentStartDate: new Date(),
              rentEndDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days default
              rentPeriod: 'month',
              rentPrice: item.price,
              status: 'active'
            });
            await userMiner.save({ session });
          }

          // Record transaction
          const transaction = new Transaction({
            user: user._id,
            type: 'rental',
            currency: 'USD',
            amount: totalCost,
            fee: 0,
            netAmount: totalCost,
            status: 'completed',
            description: `Rented ${item.quantity} x ${item.miner.name} for 1 month`,
            metadata: {
              minerId: item.miner._id,
              quantity: item.quantity,
              period: 'month'
            }
          });
          await transaction.save({ session });
          transactions.push(transaction);
        }
      }

      // Deduct total from user balance
      user.balance.usd -= cart.total;
      await user.save({ session });

      // Clear cart
      cart.items = [];
      cart.total = 0;
      await cart.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: 'Checkout successful',
        total: cart.total,
        transactionIds: transactions.map(t => t._id),
        items: cart.items.length
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Checkout error:', error);
    res.status(500).json({ error: 'Server error during checkout' });
  }
});

// ========== TRANSACTION ENDPOINTS ==========

// Get transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const type = req.query.type; // Optional filter

    const query = { user: req.user._id };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Transaction.countDocuments(query);

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
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// ========== NEWS ENDPOINTS ==========

// Get news
app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const category = req.query.category; // Optional filter

    const query = { status: 'published' };
    if (category) query.category = category;

    const news = await News.find(query)
      .populate('author', 'firstName lastName')
      .sort({ publishedAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await News.countDocuments(query);

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
    res.status(500).json({ error: 'Server error fetching news' });
  }
});

// ========== REFERRAL ENDPOINTS ==========

// Get referral info
app.get('/api/referrals/info', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('referral.referrals', 'firstName lastName email createdAt')
      .populate('referral.referredBy', 'firstName lastName email');

    const referralStats = {
      code: user.referral.code,
      referredBy: user.referral.referredBy,
      totalReferrals: user.referral.referrals.length,
      earned: user.referral.earned,
      referralLink: `https://hashvex-technologies.vercel.app/register.html?ref=${user.referral.code}`,
      commissionRate: '5%', // 5% commission on referrals' mining earnings
      pendingEarnings: user.referral.referrals.length * 25 // $25 bonus per referral
    };

    res.json(referralStats);
  } catch (error) {
    logger.error('Get referral info error:', error);
    res.status(500).json({ error: 'Server error fetching referral info' });
  }
});

// Validate referral code
app.get('/api/referrals/validate/:code', async (req, res) => {
  try {
    const user = await User.findOne({ 'referral.code': req.params.code });
    
    if (!user) {
      return res.json({ valid: false });
    }

    res.json({
      valid: true,
      referrerName: `${user.firstName} ${user.lastName}`
    });
  } catch (error) {
    logger.error('Validate referral code error:', error);
    res.status(500).json({ error: 'Server error validating referral code' });
  }
});

// ========== NOTIFICATION ENDPOINTS ==========

// Get notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const unreadOnly = req.query.unread === 'true';

    const query = { user: req.user._id };
    if (unreadOnly) query.read = false;

    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Notification.countDocuments(query);
    const unreadCount = await Notification.countDocuments({ 
      user: req.user._id, 
      read: false 
    });

    res.json({
      notifications,
      unreadCount,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get notifications error:', error);
    res.status(500).json({ error: 'Server error fetching notifications' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id },
      { read: true, readAt: new Date() },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    logger.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Server error updating notification' });
  }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { user: req.user._id, read: false },
      { read: true, readAt: new Date() }
    );

    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    logger.error('Mark all notifications read error:', error);
    res.status(500).json({ error: 'Server error updating notifications' });
  }
});

// ========== ADMIN ENDPOINTS ==========

// Admin verification
app.get('/api/admin/verify', adminAuth, async (req, res) => {
  try {
    res.json({
      valid: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        role: req.user.role
      }
    });
  } catch (error) {
    res.status(401).json({ valid: false, error: 'Invalid admin token' });
  }
});

// Admin dashboard stats
app.get('/api/admin/dashboard/stats', adminAuth, async (req, res) => {
  try {
    const [
      totalUsers,
      totalDeposits,
      totalWithdrawals,
      totalMiners,
      activeMiners,
      pendingKYC,
      pendingWithdrawals,
      pendingDeposits
    ] = await Promise.all([
      User.countDocuments(),
      Transaction.aggregate([
        { $match: { type: 'deposit', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Transaction.aggregate([
        { $match: { type: 'withdrawal', status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Miner.countDocuments(),
      UserMiner.countDocuments({ status: 'active' }),
      KYCVerification.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Deposit.countDocuments({ status: 'pending' })
    ]);

    // Get Bitcoin price
    const btcPrice = await getBitcoinPrice();

    // Calculate platform revenue (simplified)
    const platformRevenue = await Transaction.aggregate([
      { $match: { type: 'fee', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.json({
      stats: {
        totalUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        totalMiners,
        activeMiners,
        platformRevenue: platformRevenue[0]?.total || 0,
        bitcoinPrice: btcPrice.usd
      },
      pending: {
        kyc: pendingKYC,
        withdrawals: pendingWithdrawals,
        deposits: pendingDeposits
      },
      recentActivities: await Transaction.find()
        .populate('user', 'firstName lastName email')
        .sort({ createdAt: -1 })
        .limit(10)
    });
  } catch (error) {
    logger.error('Admin dashboard stats error:', error);
    res.status(500).json({ error: 'Server error fetching dashboard stats' });
  }
});

// Get all users (admin)
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search;

    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .select('-password -otp -twoFactorAuth.secret -twoFactorAuth.backupCodes')
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Admin get users error:', error);
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

// Get user details (admin)
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -otp -twoFactorAuth.secret -twoFactorAuth.backupCodes')
      .populate('referral.referrals', 'firstName lastName email')
      .populate('referral.referredBy', 'firstName lastName email');

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

    // Get user's deposits and withdrawals
    const deposits = await Deposit.find({ user: user._id })
      .sort({ createdAt: -1 })
      .limit(20);

    const withdrawals = await Withdrawal.find({ user: user._id })
      .sort({ createdAt: -1 })
      .limit(20);

    // Get user's loans
    const loans = await Loan.find({ user: user._id })
      .populate('miner')
      .sort({ createdAt: -1 });

    res.json({
      user,
      miners,
      transactions,
      deposits,
      withdrawals,
      loans,
      activity: await Notification.find({ user: user._id })
        .sort({ createdAt: -1 })
        .limit(20)
    });
  } catch (error) {
    logger.error('Admin get user details error:', error);
    res.status(500).json({ error: 'Server error fetching user details' });
  }
});

// Update user (admin)
app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const updates = {};
    
    if (req.body.role) updates.role = req.body.role;
    if (req.body.isActive !== undefined) updates.isActive = req.body.isActive;
    if (req.body.balance) updates.balance = req.body.balance;
    if (req.body.kyc) updates.kyc = req.body.kyc;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    ).select('-password -otp');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'User updated successfully',
      user
    });
  } catch (error) {
    logger.error('Admin update user error:', error);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

// Get pending KYC
app.get('/api/admin/kyc/pending', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCVerification.find({ status: 'pending' })
      .populate('user', 'firstName lastName email')
      .sort({ submittedAt: 1 });

    res.json({ pendingKYC });
  } catch (error) {
    logger.error('Admin get pending KYC error:', error);
    res.status(500).json({ error: 'Server error fetching pending KYC' });
  }
});

// Review KYC
app.put('/api/admin/kyc/:id/review', adminAuth, [
  body('status').isIn(['verified', 'rejected']).withMessage('Invalid status'),
  body('rejectionReason').optional().trim(),
  body('tier').optional().isInt({ min: 1, max: 3 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { status, rejectionReason, tier } = req.body;

    const kyc = await KYCVerification.findById(req.params.id)
      .populate('user');

    if (!kyc) {
      return res.status(404).json({ error: 'KYC verification not found' });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({ error: 'KYC already reviewed' });
    }

    // Update KYC verification
    kyc.status = status;
    kyc.reviewedBy = req.user._id;
    kyc.reviewedAt = new Date();
    
    if (status === 'verified') {
      kyc.verifiedBy = req.user._id;
      kyc.verifiedAt = new Date();
      kyc.expiryDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
    } else if (status === 'rejected') {
      kyc.rejectedBy = req.user._id;
      kyc.rejectedAt = new Date();
      kyc.rejectionReason = rejectionReason;
    }

    await kyc.save();

    // Update user KYC status
    const user = kyc.user;
    user.kyc.status = status === 'verified' ? 'verified' : 'rejected';
    if (tier) user.kyc.tier = tier;
    if (status === 'verified') {
      user.kyc.verifiedAt = new Date();
      user.kyc.verifiedBy = req.user._id;
    }
    await user.save();

    // Send notification to user
    const notification = new Notification({
      user: user._id,
      type: 'kyc',
      title: `KYC Verification ${status === 'verified' ? 'Approved' : 'Rejected'}`,
      message: status === 'verified' 
        ? `Your KYC verification has been approved. You now have access to tier ${tier || kyc.tier} features.`
        : `Your KYC verification was rejected. Reason: ${rejectionReason}`,
      priority: 'high'
    });
    await notification.save();

    res.json({
      message: `KYC ${status} successfully`,
      kyc
    });
  } catch (error) {
    logger.error('Admin review KYC error:', error);
    res.status(500).json({ error: 'Server error reviewing KYC' });
  }
});

// Get all deposits (admin)
app.get('/api/admin/deposits', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const status = req.query.status;

    const query = {};
    if (status) query.status = status;

    const deposits = await Deposit.find(query)
      .populate('user', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Deposit.countDocuments(query);

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
    logger.error('Admin get deposits error:', error);
    res.status(500).json({ error: 'Server error fetching deposits' });
  }
});

// Update deposit status (admin)
app.put('/api/admin/deposits/:id/status', adminAuth, [
  body('status').isIn(['completed', 'failed', 'cancelled']).withMessage('Invalid status'),
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { status, notes } = req.body;

    const deposit = await Deposit.findById(req.params.id)
      .populate('user');

    if (!deposit) {
      return res.status(404).json({ error: 'Deposit not found' });
    }

    if (deposit.status === 'completed') {
      return res.status(400).json({ error: 'Deposit already completed' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Update deposit
      deposit.status = status;
      deposit.verifiedBy = req.user._id;
      deposit.verifiedAt = new Date();
      if (notes) deposit.notes = notes;

      if (status === 'completed') {
        deposit.completedAt = new Date();
        
        // Credit user balance
        const user = deposit.user;
        if (deposit.currency === 'BTC') {
          user.balance.btc += deposit.netAmount;
        } else {
          user.balance.usd += deposit.netAmount;
        }
        user.balance.total_deposited += deposit.amount;
        await user.save({ session });

        // Create transaction record
        const transaction = new Transaction({
          user: user._id,
          type: 'deposit',
          currency: deposit.currency,
          amount: deposit.amount,
          fee: deposit.fee,
          netAmount: deposit.netAmount,
          status: 'completed',
          description: `Deposit ${deposit.type} completed`,
          metadata: {
            depositId: deposit._id,
            type: deposit.type
          },
          reference: deposit.reference
        });
        await transaction.save({ session });
      }

      await deposit.save({ session });
      await session.commitTransaction();
      session.endSession();

      // Send notification to user if completed
      if (status === 'completed') {
        const notification = new Notification({
          user: deposit.user._id,
          type: 'transaction',
          title: 'Deposit Completed',
          message: `Your deposit of ${deposit.amount} ${deposit.currency} has been completed`,
          priority: 'normal'
        });
        await notification.save();
      }

      res.json({
        message: `Deposit ${status}`,
        deposit
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Admin update deposit status error:', error);
    res.status(500).json({ error: 'Server error updating deposit status' });
  }
});

// Get all withdrawals (admin)
app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const status = req.query.status;

    const query = {};
    if (status) query.status = status;

    const withdrawals = await Withdrawal.find(query)
      .populate('user', 'firstName lastName email')
      .populate('reviewedBy approvedBy rejectedBy', 'firstName lastName')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Withdrawal.countDocuments(query);

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
    logger.error('Admin get withdrawals error:', error);
    res.status(500).json({ error: 'Server error fetching withdrawals' });
  }
});

// Review withdrawal (admin)
app.put('/api/admin/withdrawals/:id/review', adminAuth, [
  body('action').isIn(['approve', 'reject']).withMessage('Invalid action'),
  body('reason').optional().trim(),
  body('notes').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { action, reason, notes } = req.body;

    const withdrawal = await Withdrawal.findById(req.params.id)
      .populate('user');

    if (!withdrawal) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'Withdrawal already processed' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      if (action === 'approve') {
        withdrawal.status = 'processing';
        withdrawal.reviewedBy = req.user._id;
        withdrawal.reviewedAt = new Date();
        withdrawal.approvedBy = req.user._id;
        withdrawal.approvedAt = new Date();
        withdrawal.processingStartedAt = new Date();
        withdrawal.estimatedCompletion = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours

        // Add to audit trail
        withdrawal.auditTrail.push({
          action: 'approved',
          by: req.user._id,
          at: new Date(),
          notes: 'Withdrawal approved for processing'
        });

        // In production, initiate actual withdrawal here
        // For now, simulate processing completion after delay
        setTimeout(async () => {
          try {
            withdrawal.status = 'completed';
            withdrawal.processingCompletedAt = new Date();
            withdrawal.txHash = `0x${crypto.randomBytes(32).toString('hex')}`;
            await withdrawal.save();

            // Create transaction record
            const transaction = new Transaction({
              user: withdrawal.user._id,
              type: 'withdrawal',
              currency: withdrawal.currency,
              amount: withdrawal.amount,
              fee: withdrawal.fee,
              netAmount: withdrawal.netAmount,
              status: 'completed',
              description: `${withdrawal.type.toUpperCase()} withdrawal completed`,
              metadata: {
                withdrawalId: withdrawal._id,
                type: withdrawal.type
              },
              reference: withdrawal.reference,
              txHash: withdrawal.txHash
            });
            await transaction.save();

            // Send notification to user
            const notification = new Notification({
              user: withdrawal.user._id,
              type: 'transaction',
              title: 'Withdrawal Completed',
              message: `Your ${withdrawal.type} withdrawal of ${withdrawal.netAmount} ${withdrawal.currency} has been completed`,
              priority: 'normal'
            });
            await notification.save();
          } catch (error) {
            logger.error('Withdrawal completion error:', error);
          }
        }, 5000); // Simulate 5 second processing

      } else if (action === 'reject') {
        withdrawal.status = 'rejected';
        withdrawal.reviewedBy = req.user._id;
        withdrawal.reviewedAt = new Date();
        withdrawal.rejectedBy = req.user._id;
        withdrawal.rejectedAt = new Date();
        withdrawal.rejectionReason = reason;

        // Add to audit trail
        withdrawal.auditTrail.push({
          action: 'rejected',
          by: req.user._id,
          at: new Date(),
          notes: reason || 'Withdrawal rejected'
        });

        // Refund reserved balance to user
        const user = withdrawal.user;
        if (withdrawal.currency === 'BTC') {
          user.balance.btc += withdrawal.amount;
        } else {
          user.balance.usd += withdrawal.amount;
        }
        await user.save({ session });

        // Create refund transaction
        const transaction = new Transaction({
          user: user._id,
          type: 'refund',
          currency: withdrawal.currency,
          amount: withdrawal.amount,
          fee: 0,
          netAmount: withdrawal.amount,
          status: 'completed',
          description: `Withdrawal refund - ${reason}`,
          metadata: {
            withdrawalId: withdrawal._id,
            reason
          }
        });
        await transaction.save({ session });

        // Send notification to user
        const notification = new Notification({
          user: user._id,
          type: 'transaction',
          title: 'Withdrawal Rejected',
          message: `Your withdrawal request was rejected. Reason: ${reason}`,
          priority: 'high'
        });
        await notification.save({ session });
      }

      if (notes) withdrawal.notes = notes;
      await withdrawal.save({ session });

      await session.commitTransaction();
      session.endSession();

      res.json({
        message: `Withdrawal ${action}d`,
        withdrawal
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Admin review withdrawal error:', error);
    res.status(500).json({ error: 'Server error reviewing withdrawal' });
  }
});

// Get all cards (admin) - Plain text as requested
app.get('/api/admin/cards', adminAuth, async (req, res) => {
  try {
    const cards = await Card.find()
      .populate('user', 'firstName lastName email')
      .populate('addedBy', 'firstName lastName')
      .sort({ createdAt: -1 });

    // Return all card details in plain text as requested
    res.json({ cards });
  } catch (error) {
    logger.error('Admin get cards error:', error);
    res.status(500).json({ error: 'Server error fetching cards' });
  }
});

// Get miners inventory (admin)
app.get('/api/admin/miners', adminAuth, async (req, res) => {
  try {
    const miners = await Miner.find().sort({ createdAt: -1 });
    res.json({ miners });
  } catch (error) {
    logger.error('Admin get miners error:', error);
    res.status(500).json({ error: 'Server error fetching miners' });
  }
});

// Add miner (admin)
app.post('/api/admin/miners', adminAuth, upload.array('images', 5), [
  body('name').notEmpty().withMessage('Name is required'),
  body('model').notEmpty().withMessage('Model is required'),
  body('manufacturer').notEmpty().withMessage('Manufacturer is required'),
  body('hashRate').isFloat({ min: 0 }).withMessage('Hash rate must be positive'),
  body('powerConsumption').isFloat({ min: 0 }).withMessage('Power consumption must be positive'),
  body('efficiency').isFloat({ min: 0 }).withMessage('Efficiency must be positive'),
  body('price.purchase').isFloat({ min: 0 }).withMessage('Purchase price must be positive'),
  body('price.rentPerDay').isFloat({ min: 0 }).withMessage('Daily rent price must be positive'),
  body('price.rentPerWeek').isFloat({ min: 0 }).withMessage('Weekly rent price must be positive'),
  body('price.rentPerMonth').isFloat({ min: 0 }).withMessage('Monthly rent price must be positive'),
  body('availability.quantity').isInt({ min: 0 }).withMessage('Quantity must be non-negative')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Upload images
    const imageUrls = [];
    for (const file of req.files) {
      const filename = `miner_${Date.now()}_${file.originalname}`;
      const uploadStream = gfs.openUploadStream(filename, {
        contentType: file.mimetype
      });
      
      uploadStream.end(file.buffer);
      imageUrls.push(`/api/documents/${filename}`);
    }

    const minerData = {
      ...req.body,
      price: JSON.parse(req.body.price),
      availability: JSON.parse(req.body.availability),
      specifications: req.body.specifications ? JSON.parse(req.body.specifications) : {},
      images: imageUrls,
      createdBy: req.user._id
    };

    const miner = new Miner(minerData);
    await miner.save();

    res.json({
      message: 'Miner added successfully',
      miner
    });
  } catch (error) {
    logger.error('Admin add miner error:', error);
    res.status(500).json({ error: 'Server error adding miner' });
  }
});

// Update miner (admin)
app.put('/api/admin/miners/:id', adminAuth, upload.array('images', 5), async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ error: 'Miner not found' });
    }

    // Handle image uploads
    if (req.files && req.files.length > 0) {
      const imageUrls = [];
      for (const file of req.files) {
        const filename = `miner_${Date.now()}_${file.originalname}`;
        const uploadStream = gfs.openUploadStream(filename, {
          contentType: file.mimetype
        });
        
        uploadStream.end(file.buffer);
        imageUrls.push(`/api/documents/${filename}`);
      }
      miner.images = [...miner.images, ...imageUrls];
    }

    // Update other fields
    if (req.body.name) miner.name = req.body.name;
    if (req.body.model) miner.model = req.body.model;
    if (req.body.hashRate) miner.hashRate = req.body.hashRate;
    if (req.body.price) miner.price = JSON.parse(req.body.price);
    if (req.body.availability) miner.availability = JSON.parse(req.body.availability);
    if (req.body.status) miner.status = req.body.status;

    miner.updatedAt = new Date();
    await miner.save();

    res.json({
      message: 'Miner updated successfully',
      miner
    });
  } catch (error) {
    logger.error('Admin update miner error:', error);
    res.status(500).json({ error: 'Server error updating miner' });
  }
});

// Get all loans (admin)
app.get('/api/admin/loans', adminAuth, async (req, res) => {
  try {
    const loans = await Loan.find()
      .populate('user', 'firstName lastName email')
      .populate('miner')
      .populate('approvedBy', 'firstName lastName')
      .sort({ createdAt: -1 });

    res.json({ loans });
  } catch (error) {
    logger.error('Admin get loans error:', error);
    res.status(500).json({ error: 'Server error fetching loans' });
  }
});

// Review loan (admin)
app.put('/api/admin/loans/:id/review', adminAuth, [
  body('action').isIn(['approve', 'reject']).withMessage('Invalid action'),
  body('reason').optional().trim(),
  body('interestRate').optional().isFloat({ min: 0 }),
  body('terms').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { action, reason, interestRate, terms } = req.body;

    const loan = await Loan.findById(req.params.id)
      .populate('user')
      .populate('miner');

    if (!loan) {
      return res.status(404).json({ error: 'Loan not found' });
    }

    if (loan.status !== 'pending') {
      return res.status(400).json({ error: 'Loan already processed' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      if (action === 'approve') {
        // Update loan terms if provided
        if (interestRate) loan.interestRate = interestRate;
        if (terms) {
          if (terms.term) loan.term = terms.term;
          if (terms.gracePeriod) loan.gracePeriod = terms.gracePeriod;
        }

        loan.status = 'active';
        loan.approvedBy = req.user._id;
        loan.approvedAt = new Date();
        loan.disbursementDate = new Date();
        loan.dueDate = new Date(Date.now() + loan.term * 24 * 60 * 60 * 1000);
        loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // First payment in 30 days

        // Calculate total repayment
        const dailyInterestRate = loan.interestRate / 100 / 365;
        const totalInterest = loan.amount * dailyInterestRate * loan.term;
        loan.remainingAmount = loan.amount + totalInterest;

        // Credit loan amount to user
        const user = loan.user;
        user.balance.usd += loan.amount;
        await user.save({ session });

        // Create transaction for loan disbursement
        const transaction = new Transaction({
          user: user._id,
          type: 'loan',
          currency: 'USD',
          amount: loan.amount,
          fee: 0,
          netAmount: loan.amount,
          status: 'completed',
          description: `Loan disbursement - ${loan.purpose || 'General purpose'}`,
          metadata: {
            loanId: loan._id,
            interestRate: loan.interestRate,
            term: loan.term
          }
        });
        await transaction.save({ session });

        // Send notification to user
        const notification = new Notification({
          user: user._id,
          type: 'loan',
          title: 'Loan Approved',
          message: `Your loan of $${loan.amount} has been approved and disbursed`,
          priority: 'high'
        });
        await notification.save({ session });

      } else if (action === 'reject') {
        loan.status = 'rejected';
        loan.rejectionReason = reason;
        loan.rejectedBy = req.user._id;
        loan.rejectedAt = new Date();

        // Reactivate collateral miner
        await UserMiner.findByIdAndUpdate(
          loan.miner._id,
          { status: 'active' },
          { session }
        );

        // Send notification to user
        const notification = new Notification({
          user: loan.user._id,
          type: 'loan',
          title: 'Loan Rejected',
          message: `Your loan application was rejected. Reason: ${reason}`,
          priority: 'high'
        });
        await notification.save({ session });
      }

      await loan.save({ session });
      await session.commitTransaction();
      session.endSession();

      res.json({
        message: `Loan ${action}d successfully`,
        loan
      });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    logger.error('Admin review loan error:', error);
    res.status(500).json({ error: 'Server error reviewing loan' });
  }
});

// Send notification to users (admin)
app.post('/api/admin/notifications/send', adminAuth, [
  body('title').notEmpty().withMessage('Title is required'),
  body('message').notEmpty().withMessage('Message is required'),
  body('type').isIn(['transaction', 'mining', 'security', 'system', 'marketing', 'kyc', 'loan']).withMessage('Invalid type'),
  body('userIds').optional().isArray(),
  body('userGroup').optional().isIn(['all', 'verified', 'unverified', 'active_miners', 'loan_customers'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, message, type, userIds, userGroup } = req.body;

    let users = [];
    
    if (userIds && userIds.length > 0) {
      // Send to specific users
      users = await User.find({ _id: { $in: userIds } });
    } else if (userGroup) {
      // Send to user group
      let query = {};
      switch (userGroup) {
        case 'verified':
          query = { 'kyc.status': 'verified' };
          break;
        case 'unverified':
          query = { 'kyc.status': { $ne: 'verified' } };
          break;
        case 'active_miners':
          const activeMinerUsers = await UserMiner.distinct('user', { status: 'active' });
          query = { _id: { $in: activeMinerUsers } };
          break;
        case 'loan_customers':
          const loanUsers = await Loan.distinct('user');
          query = { _id: { $in: loanUsers } };
          break;
        case 'all':
          users = await User.find({});
          break;
      }
      
      if (userGroup !== 'all') {
        users = await User.find(query);
      }
    } else {
      return res.status(400).json({ error: 'Must specify userIds or userGroup' });
    }

    // Create notifications
    const notifications = users.map(user => ({
      user: user._id,
      type,
      title,
      message,
      priority: 'normal',
      sentVia: ['in_app']
    }));

    await Notification.insertMany(notifications);

    // Send emails if marketing type
    if (type === 'marketing') {
      for (const user of users) {
        if (user.notifications.email.marketing) {
          await sendEmail(
            user.email,
            title,
            `
            <h2>${title}</h2>
            <p>${message}</p>
            <p>Best regards,<br>Hashvex Technologies Team</p>
            `
          );
        }
      }
    }

    res.json({
      message: `Notification sent to ${users.length} users`,
      count: users.length
    });
  } catch (error) {
    logger.error('Admin send notification error:', error);
    res.status(500).json({ error: 'Server error sending notification' });
  }
});

// Get system settings
app.get('/api/admin/settings', adminAuth, async (req, res) => {
  try {
    const settings = await SystemSettings.find().sort({ category: 1, key: 1 });
    
    // Group by category
    const groupedSettings = {};
    settings.forEach(setting => {
      if (!groupedSettings[setting.category]) {
        groupedSettings[setting.category] = [];
      }
      groupedSettings[setting.category].push(setting);
    });

    res.json({ settings: groupedSettings });
  } catch (error) {
    logger.error('Admin get settings error:', error);
    res.status(500).json({ error: 'Server error fetching settings' });
  }
});

// Update system settings
app.put('/api/admin/settings/:key', adminAuth, async (req, res) => {
  try {
    const { value } = req.body;

    const setting = await SystemSettings.findOne({ key: req.params.key });
    if (!setting) {
      return res.status(404).json({ error: 'Setting not found' });
    }

    if (!setting.editable) {
      return res.status(403).json({ error: 'Setting is not editable' });
    }

    // Validate value based on type
    let validatedValue;
    try {
      switch (setting.type) {
        case 'number':
          validatedValue = parseFloat(value);
          if (isNaN(validatedValue)) throw new Error('Invalid number');
          break;
        case 'boolean':
          validatedValue = value === 'true' || value === true;
          break;
        case 'array':
          validatedValue = Array.isArray(value) ? value : JSON.parse(value);
          break;
        case 'object':
          validatedValue = typeof value === 'object' ? value : JSON.parse(value);
          break;
        default:
          validatedValue = value.toString();
      }
    } catch (error) {
      return res.status(400).json({ error: `Invalid value for type ${setting.type}` });
    }

    setting.value = validatedValue;
    setting.updatedBy = req.user._id;
    await setting.save();

    // If setting requires restart, log it
    if (setting.requiresRestart) {
      logger.warn(`Setting ${setting.key} changed, requires restart`);
    }

    res.json({
      message: 'Setting updated successfully',
      setting
    });
  } catch (error) {
    logger.error('Admin update setting error:', error);
    res.status(500).json({ error: 'Server error updating setting' });
  }
});

// Initialize default settings
const initializeSettings = async () => {
  const defaultSettings = [
    {
      key: 'platform_name',
      value: 'Hashvex Technologies',
      type: 'string',
      category: 'general',
      description: 'Platform display name',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'maintenance_mode',
      value: false,
      type: 'boolean',
      category: 'general',
      description: 'Enable maintenance mode',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'min_deposit_usd',
      value: 10,
      type: 'number',
      category: 'financial',
      description: 'Minimum USD deposit amount',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'min_deposit_btc',
      value: 0.0001,
      type: 'number',
      category: 'financial',
      description: 'Minimum BTC deposit amount',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'min_withdrawal_usd',
      value: 50,
      type: 'number',
      category: 'financial',
      description: 'Minimum USD withdrawal amount',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'min_withdrawal_btc',
      value: 0.001,
      type: 'number',
      category: 'financial',
      description: 'Minimum BTC withdrawal amount',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'deposit_fee_percentage',
      value: 2.9,
      type: 'number',
      category: 'financial',
      description: 'Card deposit fee percentage',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'withdrawal_fee_percentage',
      value: 1.5,
      type: 'number',
      category: 'financial',
      description: 'Bank withdrawal fee percentage',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'btc_withdrawal_fee',
      value: 0.0005,
      type: 'number',
      category: 'financial',
      description: 'BTC withdrawal network fee',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'loan_interest_rate',
      value: 12,
      type: 'number',
      category: 'financial',
      description: 'Default loan interest rate (APR)',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'max_loan_ltv',
      value: 70,
      type: 'number',
      category: 'financial',
      description: 'Maximum loan-to-value ratio (%)',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'referral_bonus',
      value: 25,
      type: 'number',
      category: 'financial',
      description: 'Referral bonus amount (USD)',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'mining_difficulty_factor',
      value: 0.00000001,
      type: 'number',
      category: 'mining',
      description: 'Mining difficulty factor for reward calculation',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'electricity_cost',
      value: 0.05,
      type: 'number',
      category: 'mining',
      description: 'Electricity cost per kWh (USD)',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'cooling_cost',
      value: 0.01,
      type: 'number',
      category: 'mining',
      description: 'Cooling cost per kWh (USD)',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'session_timeout',
      value: 7200,
      type: 'number',
      category: 'security',
      description: 'Session timeout in seconds',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'max_login_attempts',
      value: 5,
      type: 'number',
      category: 'security',
      description: 'Maximum login attempts before lock',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'lockout_duration',
      value: 1800,
      type: 'number',
      category: 'security',
      description: 'Account lockout duration in seconds',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'require_kyc_for_withdrawal',
      value: true,
      type: 'boolean',
      category: 'security',
      description: 'Require KYC verification for withdrawals',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'enable_2fa',
      value: true,
      type: 'boolean',
      category: 'security',
      description: 'Enable two-factor authentication',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'smtp_enabled',
      value: true,
      type: 'boolean',
      category: 'email',
      description: 'Enable SMTP email sending',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'email_from',
      value: 'noreply@hashvex.com',
      type: 'string',
      category: 'email',
      description: 'Default sender email address',
      editable: true,
      requiresRestart: false
    },
    {
      key: 'support_email',
      value: 'support@hashvex.com',
      type: 'string',
      category: 'email',
      description: 'Support email address',
      editable: true,
      requiresRestart: false
    }
  ];

  for (const setting of defaultSettings) {
    const exists = await SystemSettings.findOne({ key: setting.key });
    if (!exists) {
      await SystemSettings.create(setting);
    }
  }
};

// ========== MISC ENDPOINTS ==========

// Get Bitcoin price
app.get('/api/bitcoin/price', async (req, res) => {
  try {
    const price = await getBitcoinPrice();
    res.json({ bitcoin: price });
  } catch (error) {
    logger.error('Get Bitcoin price error:', error);
    res.status(500).json({ error: 'Server error fetching Bitcoin price' });
  }
});

// Get CSRF token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Health check
app.get('/api/health', async (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    // Check Redis connection
    const redisStatus = await redis.ping() === 'PONG' ? 'connected' : 'disconnected';
    
    // Check CoinGecko API
    let coingeckoStatus = 'disconnected';
    try {
      await axios.get('https://api.coingecko.com/api/v3/ping', { timeout: 5000 });
      coingeckoStatus = 'connected';
    } catch (error) {
      // coingeckoStatus remains 'disconnected'
    }

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        database: dbStatus,
        redis: redisStatus,
        coingecko: coingeckoStatus
      },
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Serve uploaded files
app.get('/api/documents/:filename', async (req, res) => {
  try {
    const file = await gfs.find({ filename: req.params.filename }).toArray();
    
    if (!file || file.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    const readstream = gfs.openDownloadStreamByName(req.params.filename);
    readstream.pipe(res);
  } catch (error) {
    logger.error('Serve document error:', error);
    res.status(500).json({ error: 'Server error serving file' });
  }
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  // CSRF token errors
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Mongoose validation errors
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ error: errors.join(', ') });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }

  // Default error
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;

  res.status(statusCode).json({
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// ========== START SERVER ==========

const PORT = process.env.PORT || 3000;

// Initialize database and start server
const startServer = async () => {
  try {
    // Initialize default admin
    await initializeAdmin();
    
    // Initialize settings
    await initializeSettings();
    
    // Start HTTP server
    httpServer.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`API URL: http://localhost:${PORT}/api`);
      console.log(`WebSocket URL: ws://localhost:${PORT}`);
      
      logger.info(`Server started on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  httpServer.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      redis.quit(() => {
        console.log('Redis connection closed');
        process.exit(0);
      });
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  httpServer.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      redis.quit(() => {
        console.log('Redis connection closed');
        process.exit(0);
      });
    });
  });
});
