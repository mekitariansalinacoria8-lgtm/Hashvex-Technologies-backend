require('dotenv').config()
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

// FIXED Helmet Configuration
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

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
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

// Database connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mekitariansalinacoria8_db_user:Gd6RQK8mVRn5BuBi@cluster0.fvvirw2.mongodb.net/hashvex?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: true,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  maxPoolSize: 50
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis-14450.c276.us-east-1-2.ec2.redns.redis-cloud.com',
  port: process.env.REDIS_PORT || 14450,
  password: process.env.REDIS_PASSWORD || 'qjXgsg0YrsLaSumlEW9HkIZbvLjXEwXR',
  retryStrategy: (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 3
});

redis.on('error', (err) => {
  console.error('❌ Redis error:', err);
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
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: function() { return !this.googleId; },
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
    default: 'user'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  referralCode: {
    type: String,
    unique: true
  },
  referredBy: String,
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
    submittedAt: Date,
    verifiedAt: Date,
    verifiedBy: mongoose.Schema.Types.ObjectId
  },
  walletAddress: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  emailVerificationToken: String,
  emailVerificationExpires: Date
});

// Balance Schema
const balanceSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  btc: {
    type: Number,
    default: 0
  },
  usd: {
    type: Number,
    default: 0
  },
  pendingBtc: {
    type: Number,
    default: 0
  },
  pendingUsd: {
    type: Number,
    default: 0
  },
  totalDeposited: {
    type: Number,
    default: 0
  },
  totalWithdrawn: {
    type: Number,
    default: 0
  },
  miningBalance: {
    type: Number,
    default: 0
  },
  loanBalance: {
    type: Number,
    default: 0
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

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
    required: true
  },
  dailyProfit: Number,
  monthlyProfit: Number,
  roiDays: Number,
  type: {
    type: String,
    enum: ['rent', 'sale'],
    required: true
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
    default: true
  },
  image: String,
  description: String,
  specifications: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Owned Miner Schema
const ownedMinerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  minerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Miner',
    required: true
  },
  purchaseType: {
    type: String,
    enum: ['rent', 'purchase'],
    required: true
  },
  purchaseDate: {
    type: Date,
    default: Date.now
  },
  expiryDate: Date,
  status: {
    type: String,
    enum: ['active', 'expired', 'suspended'],
    default: 'active'
  },
  dailyEarnings: Number,
  totalEarned: {
    type: Number,
    default: 0
  },
  miningAddress: String,
  powerCost: Number,
  maintenanceFee: Number,
  nextPayout: Date,
  contractDetails: mongoose.Schema.Types.Mixed
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'mining_payout', 'loan', 'repayment', 'purchase', 'rental'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  description: String,
  metadata: mongoose.Schema.Types.Mixed,
  txHash: String,
  walletAddress: String,
  bankDetails: mongoose.Schema.Types.Mixed,
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Deposit Schema
const depositSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true
  },
  method: {
    type: String,
    enum: ['bitcoin', 'bank_transfer', 'credit_card', 'crypto'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'failed'],
    default: 'pending'
  },
  btcAddress: String,
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
  transactionId: String,
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    required: true
  },
  method: {
    type: String,
    enum: ['bitcoin', 'bank_transfer'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'rejected', 'cancelled'],
    default: 'pending'
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
    default: 0
  },
  netAmount: Number,
  adminNotes: String,
  processedBy: mongoose.Schema.Types.ObjectId,
  processedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Loan Schema
const loanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    enum: ['BTC', 'USD'],
    default: 'USD'
  },
  term: {
    type: Number,
    required: true
  },
  interestRate: {
    type: Number,
    required: true
  },
  monthlyPayment: Number,
  totalRepayment: Number,
  purpose: String,
  collateral: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'OwnedMiner'
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'active', 'completed', 'defaulted'],
    default: 'pending'
  },
  approvedAmount: Number,
  approvedBy: mongoose.Schema.Types.ObjectId,
  approvedAt: Date,
  disbursedAt: Date,
  nextPaymentDate: Date,
  paymentsMade: {
    type: Number,
    default: 0
  },
  remainingBalance: Number,
  lateFees: {
    type: Number,
    default: 0
  },
  adminNotes: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Cart Schema
const cartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    minerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Miner'
    },
    quantity: {
      type: Number,
      default: 1
    },
    price: Number,
    type: String,
    rentalPeriod: Number
  }],
  total: {
    type: Number,
    default: 0
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
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
    required: true
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
    required: true
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
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

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

// ============================ UTILITY FUNCTIONS ============================

// Generate JWT Token
const generateToken = (userId, role = 'user') => {
  return jwt.sign(
    { userId, role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
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
      return res.status(401).json({ success: false, message: 'Invalid token.' });
    }
    
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, message: 'User not found or inactive.' });
    }
    
    req.user = user;
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
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
    
    // Try CoinGecko first
    try {
      const response = await axios.get(`${COINGECKO_API}/simple/price?ids=bitcoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true`);
      const priceData = {
        price: response.data.bitcoin.usd,
        marketCap: response.data.bitcoin.usd_market_cap,
        volume: response.data.bitcoin.usd_24h_vol,
        change24h: response.data.bitcoin.usd_24h_change,
        source: 'coingecko'
      };
      
      await redis.setex(cacheKey, 60, JSON.stringify(priceData));
      return priceData;
    } catch (coingeckoError) {
      // Fallback to CoinCap
      const response = await axios.get(`${COINCAP_API}/assets/bitcoin`);
      const priceData = {
        price: parseFloat(response.data.data.priceUsd),
        marketCap: parseFloat(response.data.data.marketCapUsd),
        volume: parseFloat(response.data.data.volumeUsd24Hr),
        change24h: parseFloat(response.data.data.changePercent24Hr),
        source: 'coincap'
      };
      
      await redis.setex(cacheKey, 60, JSON.stringify(priceData));
      return priceData;
    }
  } catch (error) {
    console.error('Error fetching Bitcoin price:', error);
    // Return a default price if both APIs fail
    return {
      price: 45000,
      marketCap: 880000000000,
      volume: 30000000000,
      change24h: 1.5,
      source: 'default'
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

// Send Email
const sendEmail = async (to, subject, html) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER || 'noreply@hashvex.com',
      to,
      subject,
      html
    };
    
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
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

// Authentication Endpoints
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').notEmpty().trim(),
  body('lastName').notEmpty().trim(),
  body('city').optional().trim(),
  body('referralCode').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { email, password, firstName, lastName, city, referralCode } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
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
    
    // Create balance record
    const balance = new Balance({
      userId: user._id,
      btc: 0,
      usd: 0,
      totalDeposited: 0,
      totalWithdrawn: 0
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
    
    // Send verification email
    const verificationLink = `https://hashvex-technologies.vercel.app/verify-email?token=${user.emailVerificationToken}`;
    const emailHtml = `
      <h2>Welcome to Hashvex Technologies!</h2>
      <p>Your account has been created successfully.</p>
      <p>Your verification OTP: <strong>${otp}</strong></p>
      <p>Or click this link to verify: <a href="${verificationLink}">${verificationLink}</a></p>
      <p>This OTP will expire in 10 minutes.</p>
      <p>Your referral code: <strong>${userReferralCode}</strong></p>
    `;
    
    await sendEmail(user.email, 'Verify Your Hashvex Account', emailHtml);
    
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
    
    // Find user with password
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Account is deactivated' });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      // Increment login attempts
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
      }
      await user.save();
      
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();
    await user.save();
    
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
      
      // Send 2FA OTP email
      const emailHtml = `
        <h2>Two-Factor Authentication Required</h2>
        <p>Your 2FA verification code: <strong>${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
      `;
      
      await sendEmail(user.email, 'Hashvex 2FA Verification', emailHtml);
      
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

app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID || '634814462335-9o4t8q95c4orcsd9sijjl52374g6vm85.apps.googleusercontent.com'
    });
    
    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub: googleId } = payload;
    
    let user = await User.findOne({ $or: [{ email }, { googleId }] });
    
    if (!user) {
      // Create new user
      user = new User({
        email,
        googleId,
        firstName: given_name,
        lastName: family_name || '',
        isVerified: true,
        referralCode: 'HVX' + crypto.randomBytes(4).toString('hex').toUpperCase()
      });
      
      await user.save();
      
      // Create balance record
      const balance = new Balance({
        userId: user._id,
        btc: 0,
        usd: 0,
        totalDeposited: 0,
        totalWithdrawn: 0
      });
      
      await balance.save();
      
      // Create cart
      const cart = new Cart({
        userId: user._id,
        items: [],
        total: 0
      });
      
      await cart.save();
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    // Generate token
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
    res.status(401).json({ success: false, message: 'Google authentication failed' });
  }
});

app.post('/api/auth/send-otp', [
  body('email').isEmail().normalizeEmail(),
  body('type').isIn(['verification', 'reset', 'two_factor'])
], async (req, res) => {
  try {
    const { email, type } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate OTP
    const otp = generateOTP();
    const otpRecord = new OTP({
      email,
      otp,
      type,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });
    
    await otpRecord.save();
    
    // Send OTP email
    let subject, html;
    switch (type) {
      case 'verification':
        subject = 'Verify Your Hashvex Account';
        html = `<h2>Email Verification</h2><p>Your verification code: <strong>${otp}</strong></p>`;
        break;
      case 'reset':
        subject = 'Password Reset Code';
        html = `<h2>Password Reset</h2><p>Your reset code: <strong>${otp}</strong></p>`;
        break;
      case 'two_factor':
        subject = 'Two-Factor Authentication';
        html = `<h2>2FA Verification</h2><p>Your verification code: <strong>${otp}</strong></p>`;
        break;
    }
    
    await sendEmail(email, subject, html);
    
    res.json({ success: true, message: 'OTP sent successfully' });
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
    
    if (otpRecord.attempts >= 3) {
      return res.status(400).json({ success: false, message: 'Too many attempts. OTP expired.' });
    }
    
    otpRecord.attempts += 1;
    
    if (otpRecord.otp !== otp) {
      await otpRecord.save();
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
    
    // Mark OTP as verified
    otpRecord.verified = true;
    await otpRecord.save();
    
    // Handle different OTP types
    const user = await User.findOne({ email });
    
    if (type === 'verification') {
      user.isVerified = true;
      user.emailVerificationToken = null;
      user.emailVerificationExpires = null;
      await user.save();
    }
    
    // Generate token for 2FA verification
    let token = null;
    if (type === 'two_factor' || type === 'verification') {
      token = generateToken(user._id, user.role);
    }
    
    res.json({
      success: true,
      message: 'OTP verified successfully',
      token,
      user: type === 'verification' ? {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isVerified: user.isVerified
      } : null
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'OTP verification failed' });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
    const resetLink = `https://hashvex-technologies.vercel.app/reset-password?token=${resetToken}`;
    const emailHtml = `
      <h2>Password Reset Request</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${resetLink}">${resetLink}</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
    `;
    
    await sendEmail(email, 'Password Reset Request', emailHtml);
    
    res.json({ success: true, message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Failed to process request' });
  }
});

app.post('/api/auth/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const { token, password } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    
    // Send confirmation email
    const emailHtml = `
      <h2>Password Reset Successful</h2>
      <p>Your password has been reset successfully.</p>
      <p>If you didn't make this change, please contact support immediately.</p>
    `;
    
    await sendEmail(user.email, 'Password Reset Successful', emailHtml);
    
    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    res.clearCookie('token');
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Logout failed' });
  }
});

app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      firstName: req.user.firstName,
      lastName: req.user.lastName,
      role: req.user.role,
      isVerified: req.user.isVerified,
      kycStatus: req.user.kycStatus,
      twoFactorEnabled: req.user.twoFactorEnabled
    }
  });
});

// User Endpoints
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json({ success: true, user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user data' });
  }
});

app.put('/api/users/profile', authenticate, async (req, res) => {
  try {
    const { firstName, lastName, phone, dateOfBirth } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (phone) user.phone = phone;
    if (dateOfBirth) user.dateOfBirth = dateOfBirth;
    
    await user.save();
    
    res.json({ success: true, message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

// Balance Endpoints
app.get('/api/balances', authenticate, async (req, res) => {
  try {
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance) {
      // Create balance if not exists
      const newBalance = new Balance({
        userId: req.userId,
        btc: 0,
        usd: 0,
        totalDeposited: 0,
        totalWithdrawn: 0
      });
      await newBalance.save();
      return res.json({ success: true, balance: newBalance });
    }
    
    // Get current BTC price
    const btcPrice = await getBitcoinPrice();
    
    res.json({
      success: true,
      balance,
      btcPrice: btcPrice.price,
      totalValueUSD: balance.usd + (balance.btc * btcPrice.price)
    });
  } catch (error) {
    console.error('Get balance error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch balance' });
  }
});

// Miner Endpoints
app.get('/api/miners/rent', async (req, res) => {
  try {
    const { page = 1, limit = 10, sort = 'price', order = 'asc' } = req.query;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ type: 'rent', available: true })
      .sort({ [sort]: order === 'asc' ? 1 : -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Miner.countDocuments({ type: 'rent', available: true });
    
    res.json({
      success: true,
      miners,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
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
    const { page = 1, limit = 10, sort = 'price', order = 'asc' } = req.query;
    const skip = (page - 1) * limit;
    
    const miners = await Miner.find({ type: 'sale', available: true })
      .sort({ [sort]: order === 'asc' ? 1 : -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Miner.countDocuments({ type: 'sale', available: true });
    
    res.json({
      success: true,
      miners,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get sale miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch miners' });
  }
});

app.get('/api/miners/:id', async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    res.json({ success: true, miner });
  } catch (error) {
    console.error('Get miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch miner' });
  }
});

// Owned Miners Endpoints
app.get('/api/miners/owned', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10, status = 'active' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { userId: req.userId };
    if (status !== 'all') {
      query.status = status;
    }
    
    const ownedMiners = await OwnedMiner.find(query)
      .populate('minerId')
      .sort({ purchaseDate: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await OwnedMiner.countDocuments(query);
    
    // Calculate totals
    let totalDailyEarnings = 0;
    let totalEarned = 0;
    let activeMiners = 0;
    
    ownedMiners.forEach(miner => {
      if (miner.status === 'active') {
        totalDailyEarnings += miner.dailyEarnings || 0;
        activeMiners++;
      }
      totalEarned += miner.totalEarned || 0;
    });
    
    res.json({
      success: true,
      miners: ownedMiners,
      totals: {
        activeMiners,
        totalDailyEarnings,
        totalEarned
      },
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get owned miners error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch owned miners' });
  }
});

// Cart Endpoints
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.userId }).populate('items.minerId');
    if (!cart) {
      const newCart = new Cart({ userId: req.userId, items: [], total: 0 });
      await newCart.save();
      return res.json({ success: true, cart: newCart });
    }
    
    res.json({ success: true, cart });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch cart' });
  }
});

app.post('/api/cart/add', authenticate, async (req, res) => {
  try {
    const { minerId, quantity = 1, type, rentalPeriod } = req.body;
    
    const miner = await Miner.findById(minerId);
    if (!miner || !miner.available) {
      return res.status(404).json({ success: false, message: 'Miner not available' });
    }
    
    let cart = await Cart.findOne({ userId: req.userId });
    if (!cart) {
      cart = new Cart({ userId: req.userId, items: [], total: 0 });
    }
    
    // Check if item already exists
    const existingItemIndex = cart.items.findIndex(item => 
      item.minerId.toString() === minerId && item.type === type
    );
    
    if (existingItemIndex > -1) {
      cart.items[existingItemIndex].quantity += quantity;
    } else {
      cart.items.push({
        minerId,
        quantity,
        price: miner.price,
        type: type || miner.type,
        rentalPeriod: rentalPeriod || miner.rentalPeriod
      });
    }
    
    // Calculate total
    cart.total = cart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    cart.updatedAt = new Date();
    
    await cart.save();
    
    res.json({ success: true, message: 'Item added to cart', cart });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ success: false, message: 'Failed to add to cart' });
  }
});

app.post('/api/cart/checkout', authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.userId }).populate('items.minerId');
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ success: false, message: 'Cart is empty' });
    }
    
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < cart.total) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Process each item
    const purchasedMiners = [];
    
    for (const item of cart.items) {
      const miner = item.minerId;
      
      // Create owned miner record
      const ownedMiner = new OwnedMiner({
        userId: req.userId,
        minerId: miner._id,
        purchaseType: item.type,
        purchaseDate: new Date(),
        expiryDate: item.type === 'rent' ? 
          new Date(Date.now() + (item.rentalPeriod || 30) * 24 * 60 * 60 * 1000) : null,
        dailyEarnings: miner.dailyProfit || miner.price * 0.01,
        miningAddress: crypto.randomBytes(16).toString('hex'),
        contractDetails: {
          price: item.price,
          quantity: item.quantity,
          rentalPeriod: item.rentalPeriod
        }
      });
      
      await ownedMiner.save();
      purchasedMiners.push(ownedMiner);
      
      // Update miner quantity
      miner.quantity -= item.quantity;
      if (miner.quantity <= 0) {
        miner.available = false;
      }
      await miner.save();
    }
    
    // Update balance
    balance.usd -= cart.total;
    await balance.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.userId,
      type: cart.items.some(item => item.type === 'rent') ? 'rental' : 'purchase',
      amount: cart.total,
      currency: 'USD',
      status: 'completed',
      description: `Purchase of ${cart.items.length} miner(s)`,
      metadata: {
        cartItems: cart.items,
        purchasedMiners: purchasedMiners.map(m => m._id)
      }
    });
    
    await transaction.save();
    
    // Clear cart
    cart.items = [];
    cart.total = 0;
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({
      success: true,
      message: 'Checkout successful',
      purchasedMiners,
      transaction
    });
  } catch (error) {
    console.error('Checkout error:', error);
    res.status(500).json({ success: false, message: 'Checkout failed' });
  }
});

// Deposit Endpoints
app.get('/api/deposits/btc-address', authenticate, async (req, res) => {
  try {
    // Generate unique deposit address (in production, use a real Bitcoin wallet API)
    const depositAddress = `bc1q${crypto.randomBytes(20).toString('hex')}`;
    
    // Store address in Redis for 24 hours
    await redis.setex(`deposit:${req.userId}:address`, 86400, depositAddress);
    
    res.json({ success: true, address: depositAddress });
  } catch (error) {
    console.error('Generate BTC address error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate address' });
  }
});

app.post('/api/deposits/btc-status', authenticate, async (req, res) => {
  try {
    const { address } = req.body;
    
    // In production, check blockchain for confirmations
    // For demo, simulate pending status
    const confirmations = Math.floor(Math.random() * 4);
    const status = confirmations >= 3 ? 'confirmed' : 'pending';
    
    if (status === 'confirmed') {
      // Update balance
      const balance = await Balance.findOne({ userId: req.userId });
      balance.btc += 0.1; // Example amount
      await balance.save();
      
      // Create deposit record
      const deposit = new Deposit({
        userId: req.userId,
        amount: 0.1,
        currency: 'BTC',
        method: 'bitcoin',
        status: 'completed',
        btcAddress: address,
        confirmations: 3,
        transactionId: crypto.randomBytes(16).toString('hex')
      });
      
      await deposit.save();
    }
    
    res.json({ success: true, status, confirmations });
  } catch (error) {
    console.error('BTC status error:', error);
    res.status(500).json({ success: false, message: 'Failed to check status' });
  }
});

app.post('/api/payments/store-card', authenticate, async (req, res) => {
  try {
    const { cardNumber, cardHolder, expiryDate, cvv, billingAddress } = req.body;
    
    // Store card details in plain text (as requested)
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
    
    // Process deposit
    const deposit = new Deposit({
      userId: req.userId,
      amount: 100, // Example amount
      currency: 'USD',
      method: 'credit_card',
      status: 'completed',
      cardDetails: { cardNumber, cardHolder, expiryDate, cvv, billingAddress },
      transactionId: `CARD-${Date.now()}`
    });
    
    await deposit.save();
    
    // Update balance
    const balance = await Balance.findOne({ userId: req.userId });
    balance.usd += 100;
    balance.totalDeposited += 100;
    await balance.save();
    
    res.json({ success: true, message: 'Card processed successfully' });
  } catch (error) {
    console.error('Store card error:', error);
    res.status(500).json({ success: false, message: 'Failed to process card' });
  }
});

app.get('/api/deposits/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    
    const deposits = await Deposit.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Deposit.countDocuments({ userId: req.userId });
    
    res.json({
      success: true,
      deposits,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get deposits error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch deposit history' });
  }
});

// Withdrawal Endpoints
app.get('/api/kyc/status', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('kycStatus');
    res.json({ success: true, kycStatus: user.kycStatus });
  } catch (error) {
    console.error('Get KYC status error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch KYC status' });
  }
});

app.post('/api/withdrawals/btc', authenticate, async (req, res) => {
  try {
    const { amount, address } = req.body;
    
    // Check KYC
    const user = await User.findById(req.userId);
    if (user.kycStatus !== 'verified') {
      return res.status(400).json({ success: false, message: 'KYC verification required' });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.btc < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient BTC balance' });
    }
    
    // Create withdrawal
    const withdrawal = new Withdrawal({
      userId: req.userId,
      amount,
      currency: 'BTC',
      method: 'bitcoin',
      status: 'pending',
      btcAddress: address,
      fee: 0.0005, // 0.0005 BTC fee
      netAmount: amount - 0.0005
    });
    
    await withdrawal.save();
    
    // Update balance
    balance.pendingBtc += amount;
    await balance.save();
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      withdrawal
    });
  } catch (error) {
    console.error('BTC withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Withdrawal failed' });
  }
});

app.post('/api/withdrawals/bank', authenticate, async (req, res) => {
  try {
    const { amount, bankDetails } = req.body;
    
    // Check KYC
    const user = await User.findById(req.userId);
    if (user.kycStatus !== 'verified') {
      return res.status(400).json({ success: false, message: 'KYC verification required' });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient USD balance' });
    }
    
    // Convert amount to BTC if needed
    const btcAmount = await usdToBtc(amount);
    
    // Create withdrawal
    const withdrawal = new Withdrawal({
      userId: req.userId,
      amount,
      currency: 'USD',
      method: 'bank_transfer',
      status: 'pending',
      bankDetails,
      fee: amount * 0.02, // 2% fee
      netAmount: amount * 0.98
    });
    
    await withdrawal.save();
    
    // Update balance
    balance.pendingUsd += amount;
    await balance.save();
    
    res.json({
      success: true,
      message: 'Bank withdrawal request submitted',
      withdrawal
    });
  } catch (error) {
    console.error('Bank withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Withdrawal failed' });
  }
});

app.get('/api/withdrawals/history', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    
    const withdrawals = await Withdrawal.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Withdrawal.countDocuments({ userId: req.userId });
    
    res.json({
      success: true,
      withdrawals,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch withdrawal history' });
  }
});

// Loan Endpoints
app.get('/api/loans/limit', authenticate, async (req, res) => {
  try {
    const balance = await Balance.findOne({ userId: req.userId });
    const ownedMiners = await OwnedMiner.find({ userId: req.userId, status: 'active' });
    
    // Calculate loan eligibility based on mining assets
    let totalMiningValue = 0;
    ownedMiners.forEach(miner => {
      totalMiningValue += miner.contractDetails?.price || 0;
    });
    
    const maxLoanAmount = totalMiningValue * 0.5; // 50% of mining assets value
    const currentLoans = await Loan.find({ userId: req.userId, status: { $in: ['active', 'pending'] } });
    
    let totalActiveLoans = 0;
    currentLoans.forEach(loan => {
      if (loan.status === 'active') {
        totalActiveLoans += loan.remainingBalance || loan.amount;
      }
    });
    
    const availableLoan = Math.max(0, maxLoanAmount - totalActiveLoans);
    
    res.json({
      success: true,
      maxLoanAmount,
      availableLoan,
      totalActiveLoans,
      miningAssetsValue: totalMiningValue,
      eligibility: availableLoan > 0
    });
  } catch (error) {
    console.error('Get loan limit error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch loan eligibility' });
  }
});

app.post('/api/loans', authenticate, async (req, res) => {
  try {
    const { amount, term, purpose, collateralMinerId } = req.body;
    
    // Check loan eligibility
    const eligibility = await Loan.findOne({ userId: req.userId, status: 'pending' });
    if (eligibility) {
      return res.status(400).json({ success: false, message: 'You already have a pending loan application' });
    }
    
    // Create loan application
    const interestRate = 12; // 12% annual interest
    const monthlyInterestRate = interestRate / 12 / 100;
    const monthlyPayment = (amount * monthlyInterestRate) / (1 - Math.pow(1 + monthlyInterestRate, -term));
    const totalRepayment = monthlyPayment * term;
    
    const loan = new Loan({
      userId: req.userId,
      amount,
      currency: 'USD',
      term,
      interestRate,
      monthlyPayment,
      totalRepayment,
      purpose,
      collateral: collateralMinerId,
      status: 'pending',
      remainingBalance: totalRepayment
    });
    
    await loan.save();
    
    res.json({
      success: true,
      message: 'Loan application submitted',
      loan
    });
  } catch (error) {
    console.error('Create loan error:', error);
    res.status(500).json({ success: false, message: 'Failed to submit loan application' });
  }
});

app.post('/api/loans/repay', authenticate, async (req, res) => {
  try {
    const { loanId, amount } = req.body;
    
    const loan = await Loan.findOne({ _id: loanId, userId: req.userId });
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }
    
    if (loan.status !== 'active') {
      return res.status(400).json({ success: false, message: 'Loan is not active' });
    }
    
    // Check balance
    const balance = await Balance.findOne({ userId: req.userId });
    if (!balance || balance.usd < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    // Process payment
    balance.usd -= amount;
    await balance.save();
    
    // Update loan
    loan.remainingBalance -= amount;
    loan.paymentsMade += 1;
    
    if (loan.remainingBalance <= 0) {
      loan.status = 'completed';
      loan.remainingBalance = 0;
    }
    
    loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await loan.save();
    
    // Create transaction
    const transaction = new Transaction({
      userId: req.userId,
      type: 'repayment',
      amount,
      currency: 'USD',
      status: 'completed',
      description: `Loan repayment for loan #${loan._id}`,
      metadata: { loanId: loan._id }
    });
    
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Loan repayment successful',
      loan,
      transaction
    });
  } catch (error) {
    console.error('Repay loan error:', error);
    res.status(500).json({ success: false, message: 'Failed to process repayment' });
  }
});

// Transaction Endpoints
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = { userId: req.userId };
    if (type && type !== 'all') {
      query.type = type;
    }
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      success: true,
      transactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
  }
});

// Bitcoin Price Endpoint
app.get('/api/bitcoin/price', async (req, res) => {
  try {
    const priceData = await getBitcoinPrice();
    res.json({ success: true, ...priceData });
  } catch (error) {
    console.error('Get BTC price error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch Bitcoin price' });
  }
});

// KYC Endpoints
app.post('/api/kyc/identity', authenticate, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    const user = await User.findById(req.userId);
    user.kycData = user.kycData || {};
    user.kycData.documentFront = req.file.path;
    user.kycStatus = 'pending';
    await user.save();
    
    res.json({ success: true, message: 'Identity document uploaded' });
  } catch (error) {
    console.error('KYC upload error:', error);
    res.status(500).json({ success: false, message: 'Failed to upload document' });
  }
});

app.post('/api/kyc/submit', authenticate, async (req, res) => {
  try {
    const { documentType, documentNumber } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user.kycData || !user.kycData.documentFront) {
      return res.status(400).json({ success: false, message: 'Please upload documents first' });
    }
    
    user.kycData.documentType = documentType;
    user.kycData.documentNumber = documentNumber;
    user.kycData.submittedAt = new Date();
    user.kycStatus = 'pending';
    
    await user.save();
    
    // Notify admin (in production, send notification)
    
    res.json({ success: true, message: 'KYC submitted for review' });
  } catch (error) {
    console.error('KYC submit error:', error);
    res.status(500).json({ success: false, message: 'Failed to submit KYC' });
  }
});

// ============================ ADMIN ENDPOINTS ============================

app.post('/api/admin/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email, role: 'admin' }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = generateToken(user._id, user.role);
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

app.get('/api/admin/verify', authenticate, requireAdmin, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.get('/api/admin/dashboard/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalMiners,
      activeMiners,
      pendingDeposits,
      pendingWithdrawals,
      pendingLoans,
      totalRevenue,
      btcPrice
    ] = await Promise.all([
      User.countDocuments(),
      Miner.countDocuments(),
      OwnedMiner.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Loan.countDocuments({ status: 'pending' }),
      Transaction.aggregate([
        { $match: { type: { $in: ['purchase', 'rental'] }, status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      getBitcoinPrice()
    ]);
    
    // Recent activity
    const recentTransactions = await Transaction.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'firstName lastName email');
    
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('firstName lastName email createdAt');
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalMiners,
        activeMiners,
        pendingDeposits,
        pendingWithdrawals,
        pendingLoans,
        totalRevenue: totalRevenue[0]?.total || 0,
        btcPrice: btcPrice.price
      },
      recentTransactions,
      recentUsers
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to load dashboard' });
  }
});

// User Management
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'active') query.isActive = true;
    if (status === 'inactive') query.isActive = false;
    if (status === 'verified') query.isVerified = true;
    if (status === 'unverified') query.isVerified = false;
    
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(query);
    
    res.json({
      success: true,
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

app.put('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { isActive, role, kycStatus } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (isActive !== undefined) user.isActive = isActive;
    if (role) user.role = role;
    if (kycStatus) {
      user.kycStatus = kycStatus;
      if (kycStatus === 'verified') {
        user.kycData.verifiedAt = new Date();
        user.kycData.verifiedBy = req.userId;
      }
    }
    
    await user.save();
    
    res.json({ success: true, message: 'User updated successfully', user });
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ success: false, message: 'Failed to update user' });
  }
});

// KYC Management
app.get('/api/admin/kyc/pending', authenticate, requireAdmin, async (req, res) => {
  try {
    const pendingKYC = await User.find({ kycStatus: 'pending' })
      .select('firstName lastName email kycData createdAt')
      .sort({ 'kycData.submittedAt': -1 });
    
    res.json({ success: true, pendingKYC });
  } catch (error) {
    console.error('Admin get pending KYC error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch pending KYC' });
  }
});

app.post('/api/admin/kyc/verify/:userId', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, notes } = req.body;
    
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    user.kycStatus = status;
    user.kycData.verifiedAt = new Date();
    user.kycData.verifiedBy = req.userId;
    user.kycData.adminNotes = notes;
    
    await user.save();
    
    // Send notification email
    if (status === 'verified') {
      await sendEmail(user.email, 'KYC Verification Approved', `
        <h2>KYC Verification Approved</h2>
        <p>Your KYC verification has been approved. You can now access all platform features.</p>
      `);
    } else if (status === 'rejected') {
      await sendEmail(user.email, 'KYC Verification Rejected', `
        <h2>KYC Verification Rejected</h2>
        <p>Your KYC verification has been rejected. Please submit valid documents.</p>
        <p>Reason: ${notes}</p>
      `);
    }
    
    res.json({ success: true, message: `KYC ${status} successfully` });
  } catch (error) {
    console.error('Admin verify KYC error:', error);
    res.status(500).json({ success: false, message: 'Failed to process KYC' });
  }
});

// Deposit Management
app.get('/api/admin/deposits', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) query.status = status;
    
    const deposits = await Deposit.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Deposit.countDocuments(query);
    
    res.json({
      success: true,
      deposits,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get deposits error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch deposits' });
  }
});

app.put('/api/admin/deposits/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    
    const deposit = await Deposit.findById(req.params.id).populate('userId');
    if (!deposit) {
      return res.status(404).json({ success: false, message: 'Deposit not found' });
    }
    
    const oldStatus = deposit.status;
    deposit.status = status;
    deposit.processedBy = req.userId;
    deposit.processedAt = new Date();
    if (adminNotes) deposit.adminNotes = adminNotes;
    
    // If completing deposit, update user balance
    if (oldStatus !== 'completed' && status === 'completed') {
      const balance = await Balance.findOne({ userId: deposit.userId._id });
      if (balance) {
        if (deposit.currency === 'BTC') {
          balance.btc += deposit.amount;
        } else {
          balance.usd += deposit.amount;
        }
        balance.totalDeposited += deposit.amount;
        await balance.save();
      }
      
      // Create transaction
      const transaction = new Transaction({
        userId: deposit.userId._id,
        type: 'deposit',
        amount: deposit.amount,
        currency: deposit.currency,
        status: 'completed',
        description: `Deposit via ${deposit.method}`,
        metadata: { depositId: deposit._id }
      });
      
      await transaction.save();
    }
    
    await deposit.save();
    
    res.json({ success: true, message: 'Deposit updated successfully', deposit });
  } catch (error) {
    console.error('Admin update deposit error:', error);
    res.status(500).json({ success: false, message: 'Failed to update deposit' });
  }
});

// Withdrawal Management
app.get('/api/admin/withdrawals', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) query.status = status;
    
    const withdrawals = await Withdrawal.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Withdrawal.countDocuments(query);
    
    res.json({
      success: true,
      withdrawals,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get withdrawals error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch withdrawals' });
  }
});

app.put('/api/admin/withdrawals/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    
    const withdrawal = await Withdrawal.findById(req.params.id).populate('userId');
    if (!withdrawal) {
      return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    }
    
    const oldStatus = withdrawal.status;
    withdrawal.status = status;
    withdrawal.processedBy = req.userId;
    withdrawal.processedAt = new Date();
    if (adminNotes) withdrawal.adminNotes = adminNotes;
    
    // If completing withdrawal, update user balance
    if (oldStatus !== 'completed' && status === 'completed') {
      const balance = await Balance.findOne({ userId: withdrawal.userId._id });
      if (balance) {
        if (withdrawal.currency === 'BTC') {
          balance.btc -= withdrawal.amount;
          balance.pendingBtc -= withdrawal.amount;
        } else {
          balance.usd -= withdrawal.amount;
          balance.pendingUsd -= withdrawal.amount;
        }
        balance.totalWithdrawn += withdrawal.amount;
        await balance.save();
      }
      
      // Create transaction
      const transaction = new Transaction({
        userId: withdrawal.userId._id,
        type: 'withdrawal',
        amount: withdrawal.netAmount,
        currency: withdrawal.currency,
        status: 'completed',
        description: `Withdrawal via ${withdrawal.method}`,
        metadata: { withdrawalId: withdrawal._id, fee: withdrawal.fee }
      });
      
      await transaction.save();
    } else if (status === 'rejected') {
      // If rejecting, release pending balance
      const balance = await Balance.findOne({ userId: withdrawal.userId._id });
      if (balance) {
        if (withdrawal.currency === 'BTC') {
          balance.pendingBtc -= withdrawal.amount;
        } else {
          balance.pendingUsd -= withdrawal.amount;
        }
        await balance.save();
      }
    }
    
    await withdrawal.save();
    
    res.json({ success: true, message: 'Withdrawal updated successfully', withdrawal });
  } catch (error) {
    console.error('Admin update withdrawal error:', error);
    res.status(500).json({ success: false, message: 'Failed to update withdrawal' });
  }
});

// Loan Management
app.get('/api/admin/loans', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {};
    if (status) query.status = status;
    
    const loans = await Loan.find(query)
      .populate('userId', 'firstName lastName email')
      .populate('collateral')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Loan.countDocuments(query);
    
    res.json({
      success: true,
      loans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get loans error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch loans' });
  }
});

app.put('/api/admin/loans/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const { status, approvedAmount, adminNotes } = req.body;
    
    const loan = await Loan.findById(req.params.id).populate('userId');
    if (!loan) {
      return res.status(404).json({ success: false, message: 'Loan not found' });
    }
    
    if (status === 'approved') {
      loan.status = 'approved';
      loan.approvedAmount = approvedAmount || loan.amount;
      loan.approvedBy = req.userId;
      loan.approvedAt = new Date();
      loan.nextPaymentDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      
      // Disburse loan to user balance
      const balance = await Balance.findOne({ userId: loan.userId._id });
      if (balance) {
        balance.usd += loan.approvedAmount;
        await balance.save();
      }
      
      // Create transaction
      const transaction = new Transaction({
        userId: loan.userId._id,
        type: 'loan',
        amount: loan.approvedAmount,
        currency: 'USD',
        status: 'completed',
        description: `Loan disbursement for ${loan.purpose}`,
        metadata: { loanId: loan._id, term: loan.term, interestRate: loan.interestRate }
      });
      
      await transaction.save();
    } else if (status === 'rejected') {
      loan.status = 'rejected';
      loan.adminNotes = adminNotes;
    }
    
    await loan.save();
    
    res.json({ success: true, message: `Loan ${status} successfully`, loan });
  } catch (error) {
    console.error('Admin update loan error:', error);
    res.status(500).json({ success: false, message: 'Failed to update loan' });
  }
});

// Miner Management
app.post('/api/admin/miners', authenticate, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const minerData = req.body;
    
    if (req.file) {
      minerData.image = req.file.path;
    }
    
    const miner = new Miner(minerData);
    await miner.save();
    
    res.json({ success: true, message: 'Miner added successfully', miner });
  } catch (error) {
    console.error('Admin add miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to add miner' });
  }
});

app.put('/api/admin/miners/:id', authenticate, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    Object.assign(miner, req.body);
    
    if (req.file) {
      miner.image = req.file.path;
    }
    
    await miner.save();
    
    res.json({ success: true, message: 'Miner updated successfully', miner });
  } catch (error) {
    console.error('Admin update miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to update miner' });
  }
});

app.delete('/api/admin/miners/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    const miner = await Miner.findById(req.params.id);
    if (!miner) {
      return res.status(404).json({ success: false, message: 'Miner not found' });
    }
    
    // Check if miner is owned by anyone
    const ownedCount = await OwnedMiner.countDocuments({ minerId: miner._id });
    if (ownedCount > 0) {
      return res.status(400).json({ success: false, message: 'Cannot delete miner that is currently owned' });
    }
    
    await miner.deleteOne();
    
    res.json({ success: true, message: 'Miner deleted successfully' });
  } catch (error) {
    console.error('Admin delete miner error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete miner' });
  }
});

// Card Details (Admin Access)
app.get('/api/admin/cards', authenticate, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const cards = await Card.find()
      .populate('userId', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Card.countDocuments();
    
    res.json({
      success: true,
      cards,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin get cards error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch card details' });
  }
});

// System Settings
app.get('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    // In production, get from database
    const settings = {
      siteName: 'Hashvex Technologies',
      maintenance: false,
      registrationEnabled: true,
      depositEnabled: true,
      withdrawalEnabled: true,
      loanEnabled: true,
      btcWithdrawalFee: 0.0005,
      usdWithdrawalFee: 0.02,
      loanInterestRate: 12,
      kycRequired: true,
      referralBonus: 50,
      supportEmail: 'support@hashvex.com'
    };
    
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Admin get settings error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  try {
    // In production, save to database
    const settings = req.body;
    
    res.json({ success: true, message: 'Settings updated successfully', settings });
  } catch (error) {
    console.error('Admin update settings error:', error);
    res.status(500).json({ success: false, message: 'Failed to update settings' });
  }
});

// ============================ WEBHOOKS & REAL-TIME ============================

// WebSocket for real-time updates
io.on('connection', (socket) => {
  console.log('Client connected');
  
  socket.on('subscribe', (data) => {
    if (data.userId) {
      socket.join(`user:${data.userId}`);
    }
    if (data.channel === 'bitcoin_price') {
      socket.join('bitcoin_price');
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Broadcast Bitcoin price updates every 30 seconds
setInterval(async () => {
  try {
    const priceData = await getBitcoinPrice();
    io.to('bitcoin_price').emit('bitcoin_price_update', priceData);
  } catch (error) {
    console.error('Error broadcasting Bitcoin price:', error);
  }
}, 30000);

// Webhook for blockchain transactions (simulated)
app.post('/webhook/blockchain', async (req, res) => {
  try {
    const { address, amount, confirmations, txid } = req.body;
    
    // Find deposit by address
    const deposit = await Deposit.findOne({ btcAddress: address, status: 'pending' });
    if (deposit) {
      deposit.confirmations = confirmations;
      
      if (confirmations >= 3) {
        deposit.status = 'confirmed';
        
        // Update user balance
        const balance = await Balance.findOne({ userId: deposit.userId });
        if (balance) {
          balance.btc += amount;
          await balance.save();
        }
        
        // Notify user via WebSocket
        io.to(`user:${deposit.userId}`).emit('deposit_confirmed', {
          amount,
          txid,
          balance: balance.btc
        });
      }
      
      await deposit.save();
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ success: false });
  }
});

// ============================ SERVER STARTUP ============================

const PORT = process.env.PORT || 5000;

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: 'File upload error: ' + err.message });
  }
  
  res.status(500).json({ success: false, message: 'Internal server error' });
});

httpServer.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ MongoDB: ${MONGODB_URI.split('@')[1]?.split('/')[0] || 'Connected'}`);
  console.log(`✅ Admin Login: admin@hashvex.com / Admin@123`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing server...');
  httpServer.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
