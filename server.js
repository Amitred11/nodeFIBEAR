require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss-clean');
const multer = require('multer');
const Joi = require('joi');
const { Readable } = require('stream');
const { finished } = require('stream/promises');
const fileType = require('file-type');

// --- Safety Check ---
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET or REFRESH_TOKEN_SECRET is not defined in the .env file.');
    process.exit(1);
}

const API_SECRET_KEY = process.env.API_SECRET_KEY;

const app = express();

// --- Middleware Functions (Move these to separate files in a real project) ---
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const validate = (schema) => (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });
    next();
};

const errorHandler = (err, req, res, next) => {
    console.error(err.stack || err.message);
    const statusCode = res.statusCode || 500;
    const response = {
        success: false,
        message: err.message || 'Server Error'
    };

    // Conditionally add stack trace based on environment
    if (process.env.NODE_ENV !== 'production') {
        response.stack = err.stack;
    }

    res.status(statusCode).json(response);
};

// --- Validation Schemas ---
const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(12).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$/)
        .message("Password must be at least 12 characters and include one lowercase letter, one uppercase letter, one number, and one special character").required(),
    displayName: Joi.string().required(),
});

// --- Security Middleware Configuration ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Removing 'unsafe-inline' - Enforce external scripts
            imgSrc: ["'self'", "data:"],
            styleSrc: ["'self'"], // Ensure all styles are from 'self'
            objectSrc: ["'none'"], // Disable object/embed elements
            upgradeInsecureRequests: [],  // Upgrade insecure requests
        },
    },
    frameguard: {
        action: 'deny' // Prevent clickjacking
    },
    referrerPolicy: { policy: 'same-origin' }, // Only send referrer for same-origin requests
    crossOriginEmbedderPolicy: false
}));
app.use(mongoSanitize());
app.use(hpp());
app.use(xss());

// --- Request Parsing ---
app.use(express.json({
    limit: '10mb',
    verify: (req, res, buf) => { req.rawBody = buf.toString(); }
}));

// --- Request Content-Type Restriction ---
app.use((req, res, next) => {
    if (req.is('application/json')) return next();
    res.status(415).json({ message: 'Only application/json content type is allowed.' });
});

// --- Rate Limiters ---
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again after 15 minutes",
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/auth', authLimiter);

const generalLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 200,
    message: 'Too many requests. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/support', generalLimiter);

// --- Signature Verification ---
const checkSignature = (req, res, next) => {
    const publicRoutes = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/api/health'];
    if (publicRoutes.includes(req.path)) return next();

    const timestamp = req.header('X-Request-Timestamp');
    const signatureFromClient = req.header('X-Request-Signature');

    if (!timestamp || !signatureFromClient) return res.status(400).json({ message: 'Missing security headers.' });

    const now = Math.floor(Date.now() / 1000);
    if (now - parseInt(timestamp) > 30) return res.status(408).json({ message: 'Request has expired. Please check your device time.' });

    if (!API_SECRET_KEY) return res.status(500).json({ message: 'Server configuration error' });

    const method = req.method;
    const path = req.originalUrl;
    const body = req.rawBody || null; //Simplified rawBody check.

    const dataToSign = `${timestamp}.${method}.${path}${body ? `.${body}` : ''}`;
    const expectedSignature = crypto.createHmac('sha256', API_SECRET_KEY).update(dataToSign).digest('base64');

    if (signatureFromClient !== expectedSignature) return res.status(403).json({ message: 'Invalid request signature.' });

    next();
};
app.use('/api', checkSignature);

// --- Authentication ---
const checkAuth = asyncHandler(async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ message: 'Not authorized, no token' });

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password -refreshToken');
        if (!user) return res.status(401).json({ message: "Not authorized, user not found" });
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Not authorized, token failed' });
    }
});

// --- Admin Authorization ---
const checkAdmin = asyncHandler(async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ message: 'Not authorized, no token' });

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password'); // No refresh token exclusion
        if (!user || !user.isAdmin) return res.status(403).json({ message: 'Access denied. Admin role required.' });
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Not authorized, token failed or missing.' });
    }
});

// --- Multer Configuration ---
const fileStorage = multer.memoryStorage();

const fileUpload = multer({
    storage: fileStorage,
    limits: { fileSize: 1024 * 1024 * 5 },  // 5MB limit
    fileFilter: async (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];

        if (!allowedMimeTypes.includes(file.mimetype)) {
            return cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'), false);
        }

        // Additional security: Check file content using `file-type` package
        const buffer = file.stream.read(); // Read a chunk of the file

        if (!buffer) {
            return cb(new Error('Could not read file buffer.'), false);
        }

        const type = await fileType.fromBuffer(buffer);

        if (!type || !allowedMimeTypes.includes(type.mime)) {
            return cb(new Error('File content does not match the declared MIME type.'), false);
        }

        cb(null, true);
    }
});

// --- Models (Consider moving these to separate files) ---
const UserSchema = new mongoose.Schema({
    refreshToken: { type: String, index: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    displayName: { type: String },
    isAdmin: { type: Boolean, default: false },
    isModemInstalled: { type: Boolean, default: false },
    photoUrl: { type: String },
    mobileNumber: { type: String },
    birthday: { type: String },
    gender: { type: String },
    address: { type: String },
    phase: { type: String },
    city: { type: String },
    province: { type: String },
    zipCode: { type: String },
    pushToken: { type: String },
    accountCreatedAt: { type: Date, default: Date.now },
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

UserSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const SubscriptionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: { type: String, enum: ['active', 'pending_verification', 'pending_installation', 'declined', 'cancelled'], required: true },
    plan: { name: String, price: Number, priceLabel: String, features: [String] },
    paymentMethod: { type: String },
    startDate: { type: Date },
    renewalDate: { type: Date },
    declineReason: { type: String },
    history: [{
        type: { type: String, required: true },
        details: String,
        date: { type: Date, default: Date.now },
        amount: Number,
        receiptNumber: String,
        planName: String
    }],
    proofOfPayment: { type: String, default: null }
}, { timestamps: true });

const BillSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    subscriptionId: { type: String, ref: 'Subscription', required: true },
    planName: String,
    amount: Number,
    statementDate: { type: Date, default: Date.now },
    dueDate: Date,
    status: { type: String, enum: ['Due', 'Paid', 'Overdue'], default: 'Due' },
    paymentDate: Date,
}, { timestamps: true });

const FeedbackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: String,
    userPhotoUrl: String,
    rating: { type: Number, required: true },
    text: { type: String, required: true },
}, { timestamps: true });

const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userName: String,
    subject: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['Open', 'InProgress', 'Resolved', 'Closed'], default: 'Open' },
    adminComment: { type: String, default: '' },
    imageUrl: { type: String },
    messages: [{
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        senderName: String,
        text: { type: String, required: true },
        isAdmin: { type: Boolean, default: false },
        timestamp: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const NotificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: { type: String, default: 'default' },
    read: { type: Boolean, default: false },
}, { timestamps: true });

const LiveChatSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userName: String,
    status: { type: String, enum: ['open', 'active', 'closed'], default: 'open' },
    messages: [{
        senderId: { type: String, required: true },
        senderName: String,
        text: { type: String, required: true },
        isAdmin: { type: Boolean, default: false },
        timestamp: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const LiveChatSession = mongoose.model('LiveChatSession', LiveChatSessionSchema);
const User = mongoose.model('User', UserSchema);
const Subscription = mongoose.model('Subscription', SubscriptionSchema);
const Bill = mongoose.model('Bill', BillSchema);
const Feedback = mongoose.model('Feedback', FeedbackSchema);
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);
const Notification = mongoose.model('Notification', NotificationSchema);

// --- Security Best Practices ---
console.warn("SECURITY: Implement automated security scanning in CI/CD.");
console.warn("SECURITY: Schedule regular security audits by experts.");
console.warn("SECURITY: Establish a vulnerability disclosure program.");
console.warn("SECURITY: Define and practice an incident response plan.");

// --- API ROUTES ---
// --- Auth Routes (Public) ---
app.get('/api/health', (req, res) => res.status(200).json({ status: "ok", message: "Node.js server is running." }));

app.post('/api/auth/register', validate(registerSchema), asyncHandler(async (req, res) => {
    const { displayName, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User with this email already exists.' });
    const user = new User({ displayName, email, password });
    await user.save();
    // Consider sending a welcome email here
    res.status(201).json({ message: 'User registered successfully.' });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const { email, password, rememberMe } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await user.matchPassword(password))) return res.status(401).json({ message: 'Invalid email or password.' });

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: rememberMe ? '30d' : '1d' });

    user.refreshToken = refreshToken;
    await user.save();

    res.json({
        accessToken,
        refreshToken,
        user: { _id: user._id, displayName: user.displayName, email: user.email, isAdmin: user.isAdmin, }
    });
}));

app.post('/api/auth/refresh', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "Refresh token is required." });

    const userInDb = await User.findOne({ refreshToken });
    if (!userInDb) return res.status(403).json({ message: "Invalid session. Please log in again." });

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid or expired session. Please log in again." });

        const newAccessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const newRefreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' });

        userInDb.refreshToken = newRefreshToken;
        await userInDb.save();

        res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    });
}));

app.post('/api/auth/logout', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(204); // No content

    await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
    res.sendStatus(204);
}));

// --- User Routes (Protected) ---
app.get('/api/users/me', checkAuth, asyncHandler(async (req, res) => {
    const user = await User.findById(req.user).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
}));

app.put('/api/users/me', checkAuth, asyncHandler(async (req, res) => {
    const user = await User.findById(req.user);
    if (!user) return res.status(404).json({ message: 'User not found' });

    Object.assign(user, req.body); //  More dynamic update with `Object.assign`
    if (req.body.photoData && req.body.photoData.base64) {
        user.photoUrl = `data:${req.body.photoData.mimeType};base64,${req.body.photoData.base64}`;
    }

    const updatedUser = await user.save();
    const { password, ...userResponse } = updatedUser.toObject(); //Destructure to exclude

    res.json(userResponse);
}));

app.put('/api/users/change-password', checkAuth, asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user);
    if (!user) return res.status(404).json({ message: "User not found." });

    if (!(await user.matchPassword(currentPassword))) return res.status(401).json({ message: "Incorrect current password." });

    user.password = newPassword;
    await user.save();
    res.status(200).json({ message: "Password changed successfully." });
}));

app.post('/api/users/push-token', checkAuth, asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user, { pushToken: req.body.token });
    res.status(200).json({ message: 'Token updated successfully' });
}));

// --- Subscription & Billing Routes (Protected) ---
app.get('/api/subscriptions/details', checkAuth, asyncHandler(async (req, res) => {
    const subscription = await Subscription.findOne({ userId: req.user }).sort({ createdAt: -1 });
    const bills = await Bill.find({ userId: req.user }).sort({ createdAt: -1 });

    if (!subscription && bills.length === 0) return res.json({ status: null, subscriptionData: null, activePlan: null, paymentHistory: [], renewalDate: null });

    const billHistory = bills.map(b => ({ id: b._id, type: 'bill', status: b.status, amount: b.amount, planName: b.planName, statementDate: b.statementDate, paymentDate: b.paymentDate, date: b.createdAt }));
    const combinedHistory = [...(subscription?.history || []), ...billHistory].sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json({
        status: subscription?.status, subscriptionData: subscription, activePlan: subscription?.plan,
        paymentHistory: combinedHistory, renewalDate: subscription?.renewalDate,
    });
}));

app.post('/api/subscriptions/subscribe', checkAuth, asyncHandler(async (req, res) => {
    const { plan, paymentMethod, proofOfPayment } = req.body;
    const user = await User.findById(req.user);

    if (!user) return res.status(404).json({ message: "User not found." });

    const needsInstallation = (user.isModemInstalled !== true);

    if (paymentMethod === 'Cash on Delivery') {
        let newSubscription;
        if (needsInstallation) {
            newSubscription = new Subscription({
                userId: req.user, status: 'pending_installation', plan: plan, paymentMethod: paymentMethod,
                history: [{ type: 'subscribed', details: `Subscription initiated. Awaiting field agent for installation and payment.` }],
            });
            await new Notification({
                userId: req.user, title: 'Application Received!',
                message: `We've received your application for ${plan.name}. Please wait for our field agent to contact you for the installation schedule.`,
            }).save();

        } else {
            const startDate = new Date();
            const renewalDate = new Date(startDate);
            renewalDate.setMonth(startDate.getMonth() + 1);
            newSubscription = new Subscription({
                userId: req.user, status: 'active', plan: plan, paymentMethod: paymentMethod, startDate, renewalDate,
                history: [{ type: 'activated', details: `Re-subscribed to ${plan.name} via Cash on Delivery.`, amount: plan.price, planName: plan.name }],
            });
            const savedSubscription = await newSubscription.save();
            await new Bill({
                userId: req.user, subscriptionId: savedSubscription._id, planName: plan.name, amount: plan.price,
                dueDate: new Date(new Date().setDate(new Date().getDate() + 7)), status: 'Due',
            }).save();
            await new Notification({
                userId: req.user, title: 'Subscription Reactivated!',
                message: `Your ${plan.name} is now active. Your first bill of ₱${plan.price.toFixed(2)} is due.`,
            }).save();
        }
         await newSubscription.save();
        return res.status(201).json(newSubscription);

    } else if (paymentMethod === 'GCash') {
        if (!proofOfPayment) return res.status(400).json({ message: "Proof of payment is required for GCash." });
        const newSubscription = new Subscription({
            userId: req.user, status: 'pending_verification', plan: plan, paymentMethod: paymentMethod,
            history: [{ type: 'submitted_payment', details: `User submitted GCash payment for ${plan.name}`, amount: plan.price, planName: plan.name }],
            proofOfPayment: proofOfPayment,
        });
         await newSubscription.save();
        return res.status(201).json(newSubscription);
    } else {
        return res.status(400).json({ message: "Invalid payment method specified." });
    }
}));

app.post('/api/billing/pay', checkAuth, asyncHandler(async (req, res) => {
    const { billId, amount, planName } = req.body;
    await Bill.findByIdAndUpdate(billId, { status: 'Paid', paymentDate: new Date() });
    await Subscription.findOneAndUpdate(
        { userId: req.user, status: 'active' },
        {
            $push: {
                history: {
                    $each: [{
                        type: 'payment_success', details: `Paid bill for ${planName}`, amount: amount, planName: planName,
                        receiptNumber: `RCPT-${Date.now()}`
                    }], $sort: { date: -1 }
                }
            }
        }
    );
    res.status(200).json({ message: "Payment successful" });
}));

app.post('/api/subscriptions/cancel', checkAuth, asyncHandler(async (req, res) => {
    const subscription = await Subscription.findOne({
        userId: req.user,
        status: { $in: ['active', 'pending_verification', 'pending_installation'] }
    });

    if (!subscription) return res.status(404).json({ message: 'No cancellable subscription found.' });

    subscription.history.unshift({
        type: 'cancelled',
        details: `User cancelled the subscription while its status was '${subscription.status}'.`,
        date: new Date(),
    });
    subscription.status = 'cancelled';
    await subscription.save();

    res.status(200).json({ message: 'Subscription cancelled successfully.' });
}));

app.post('/api/subscriptions/clear', checkAuth, asyncHandler(async (req, res) => {
    await Subscription.deleteOne({ userId: req.user, status: 'declined' });
    res.status(204).send();
}));

// --- Feedback Routes ---
app.get('/api/feedback', asyncHandler(async (req, res) => {
    const feedbacks = await Feedback.find().sort({ createdAt: -1 }).limit(parseInt(req.query.limit) || 5);
    res.json(feedbacks);
}));

app.post('/api/feedback', checkAuth, asyncHandler(async (req, res) => {
    const user = await User.findById(req.user);
    if (!user) return res.status(404).json({ message: "User not found" });
    const newFeedback = new Feedback({
        ...req.body, userId: req.user, userName: user.displayName,
        userPhotoUrl: user.photoUrl,
    });
    await newFeedback.save();
    res.status(201).json(newFeedback);
}));

app.put('/api/feedback/:id', checkAuth, asyncHandler(async (req, res) => {
    const { rating, text } = req.body;
    const feedback = await Feedback.findById(req.params.id);

    if (!feedback) return res.status(404).json({ message: 'Feedback not found.' });
    if (feedback.userId.toString() !== req.user) return res.status(403).json({ message: 'User not authorized to edit this feedback.' });

    feedback.rating = rating;
    feedback.text = text;

    const updatedFeedback = await feedback.save();
    res.json(updatedFeedback);
}));

app.delete('/api/feedback/:id', checkAuth, asyncHandler(async (req, res) => {
    const feedback = await Feedback.findById(req.params.id);

    if (!feedback) return res.status(404).json({ message: 'Feedback not found.' });
    if (feedback.userId.toString() !== req.user) return res.status(403).json({ message: 'User not authorized to delete this feedback.' });

    await feedback.deleteOne();
    res.json({ message: 'Feedback removed successfully.' });
}));

// --- Support & Notification Routes ---
app.post('/api/support/tickets', checkAuth, asyncHandler(async (req, res) => {
    const { subject, description, imageData } = req.body;
    const user = await User.findById(req.user);

    const openTickets = await SupportTicket.countDocuments({ userId: req.user, status: 'Open' });
    if (openTickets >= 5) return res.status(429).json({ message: "You have reached the maximum number of open tickets." });

    const newTicket = new SupportTicket({
        userId: req.user, userName: user.displayName,
        subject: subject, description: description, imageUrl: imageData || null
    });

    await newTicket.save();

    await new Notification({
        userId: req.user, title: 'Support Ticket Received',
        message: `We've received your ticket: "${newTicket.subject}".`,
    }).save();

    res.status(201).json(newTicket);
}));

app.get('/api/support/tickets', checkAuth, asyncHandler(async (req, res) => {
    const tickets = await SupportTicket.find({ userId: req.user }).sort({ updatedAt: -1 });
    res.json(tickets);
}));

app.get('/api/support/tickets/:id', checkAuth, asyncHandler(async (req, res) => {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket || ticket.userId.toString() !== req.user) return res.status(404).json({ message: "Ticket not found or you're not authorized to view it." });
    res.json(ticket);
}));

app.post('/api/support/tickets/:id/reply', checkAuth, asyncHandler(async (req, res) => {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket || ticket.userId.toString() !== req.user) return res.status(404).json({ message: "Ticket not found or you're not authorized to reply." });

    const user = await User.findById(req.user);
    const newReply = {
        senderId: req.user, senderName: user.displayName, text: req.body.text, isAdmin: false
    };

    ticket.messages.push(newReply);
    if (ticket.status === 'Resolved' || ticket.status === 'Closed') ticket.status = 'In Progress';

    const updatedTicket = await ticket.save();
    res.status(201).json(updatedTicket);
}));

app.post('/api/support/request-agent', checkAuth, asyncHandler(async (req, res) => {
    const userId = req.user;

    let session = await LiveChatSession.findOne({ userId, status: { $in: ['open', 'active'] } });
    if (session) return res.status(200).json({ message: 'Existing chat session found.', chatId: session._id });

    const user = await User.findById(userId).select('displayName');
    session = new LiveChatSession({
        userId: userId, userName: user.displayName, status: 'open',
        messages: [{ senderId: 'system', senderName: 'System', text: 'A support agent will be with you shortly.' }]
    });
    await session.save();

    res.status(201).json({ message: 'Live chat session requested.', chatId: session._id });

}));

app.post('/api/support/live-chat/:chatId/message', checkAuth, asyncHandler(async (req, res) => {
    const { text } = req.body;
    const { chatId } = req.params;
    const userId = req.user;

    const session = await LiveChatSession.findById(chatId);
    if (!session || session.userId.toString() !== userId) return res.status(403).json({ message: 'You are not authorized to post in this chat session.' });

    const sender = await User.findById(userId).select('displayName');
    session.messages.push({
        senderId: userId, senderName: sender.displayName, text, isAdmin: false,
    });
    await session.save();
    res.status(201).json(session);
}));

app.get('/api/support/live-chat/:chatId', checkAuth, asyncHandler(async (req, res) => {
    const { chatId } = req.params;
    const session = await LiveChatSession.findById(chatId);
    if (!session || (session.userId.toString() !== req.user)) return res.status(404).json({ message: "Chat session not found or access denied." });
    res.status(200).json(session);
}));

app.get('/api/support/live-chat/:chatId/listen', checkAuth, asyncHandler(async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const { chatId } = req.params;

    const sendMessages = (messages) => {
        res.write(`data: ${JSON.stringify(messages)}\n\n`);
    };

    const initialSession = await LiveChatSession.findById(chatId);
    if (!initialSession || initialSession.userId.toString() !== req.user) {
        res.write(`data: ${JSON.stringify({ error: "Access Denied" })}\n\n`);
        return res.end();
    }
    sendMessages(initialSession.messages);

    const changeStream = LiveChatSession.watch([{ $match: { 'fullDocument._id': new mongoose.Types.ObjectId(chatId) } }]);

    changeStream.on('change', (change) => {
        if (change.operationType === 'update' && change.fullDocument && change.fullDocument.messages) {
            sendMessages(change.fullDocument.messages);
        }
    });

    req.on('close', () => {
        changeStream.close();
        res.end();
    });
}));

app.delete('/api/support/live-chat/:chatId', checkAuth, asyncHandler(async (req, res) => {
    const { chatId } = req.params;
    const session = await LiveChatSession.findById(chatId);
    if (!session || session.userId.toString() !== req.user) return res.status(404).json({ message: 'Chat session not found or access denied.' });

    await session.deleteOne();
    res.status(200).json({ message: 'Chat session deleted successfully.' });
}));

app.delete('/api/support/live-chat/:chatId/message/:messageId', checkAuth, asyncHandler(async (req, res) => {
    const { chatId, messageId } = req.params;
    const userId = req.user;

    const session = await LiveChatSession.findById(chatId);
    if (!session || session.userId.toString() !== userId) return res.status(403).json({ message: 'Access denied.' });

    const result = await LiveChatSession.updateOne(
        { _id: chatId },
        { $pull: { messages: { _id: new mongoose.Types.ObjectId(messageId), senderId: userId } } }
    );

    if (result.modifiedCount === 0) return res.status(404).json({ message: "Message not found or you are not authorized to delete it." });

    res.status(200).json({ message: 'Message deleted successfully.' });
}));

app.get('/api/notifications', checkAuth, asyncHandler(async (req, res) => {
    const notifications = await Notification.find({ userId: req.user }).sort({ createdAt: -1 });
    res.json(notifications);
}));

app.post('/api/notifications/mark-read', checkAuth, asyncHandler(async (req, res) => {
    const { ids } = req.body;
    const query = { userId: req.user };
    if (ids && ids.length > 0) query._id =  { $in: ids };
    await Notification.updateMany(query, { read: true });
    res.status(200).json({ message: 'Notifications marked as read' });
}));

app.post('/api/notifications/delete', checkAuth, asyncHandler(async (req, res) => {
    const { ids } = req.body;
    if (!ids || ids.length === 0) return res.status(400).json({ message: 'No notification IDs provided' });
    await Notification.deleteMany({ userId: req.user, _id: { $in: ids } });
    res.status(200).json({ message: 'Notifications deleted' });
}));

// --- Admin Routes ---
const adminRouter = express.Router();
app.use('/api/admin', checkAdmin, adminRouter);

adminRouter.get('/subscriptions/pending', asyncHandler(async (req, res) => {
    const pending = await Subscription.find({ $or: [{ status: 'pending_verification' }, { status: 'pending_installation' }] })
        .populate('userId', 'displayName email')
        .sort({ createdAt: 1 });
    res.json(pending);
}));

adminRouter.post('/subscriptions/:id/decline', asyncHandler(async (req, res) => {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ message: 'Decline reason is required.' });

    const sub = await Subscription.findById(req.params.id);
    if (!sub) return res.status(404).json({ message: 'Subscription not found.' });

    sub.status = 'declined';
    sub.declineReason = reason;
    sub.history.unshift({ type: 'declined', details: `Admin declined subscription. Reason: ${reason}` });
    await sub.save();

    await new Notification({
        userId: sub.userId,
        title: 'Subscription Update',
        message: `Your payment submission was declined. Reason: ${reason}`,
        type: 'warning'
    }).save();

    res.json({ message: 'Subscription declined successfully.' });
}));

adminRouter.get('/tickets', asyncHandler(async (req, res) => {
    const tickets = await SupportTicket.find().sort({ updatedAt: -1 });
    res.json(tickets);
}));

adminRouter.post('/tickets/:id/status', asyncHandler(async (req, res) => {
    const { status, adminComment } = req.body;
    const validStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
    if (!status || !validStatuses.includes(status)) return res.status(400).json({ message: 'A valid status is required.' });

    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ message: 'Ticket not found.' });

    const oldStatus = ticket.status;
    ticket.status = status;
    if (adminComment) ticket.adminComment = adminComment;
    await ticket.save();

    await new Notification({
        userId: ticket.userId,
        title: 'Support Ticket Updated',
        message: `Your ticket "${ticket.subject}" status changed from ${oldStatus} to ${status}.`,
        type: 'update'
    }).save();

    res.json({ message: 'Ticket status updated successfully.' });
}));

adminRouter.post('/broadcast', asyncHandler(async (req, res) => {
    const { title, message } = req.body;
    if (!title || !message) return res.status(400).json({ message: 'Title and message are required.' });

    const users = await User.find({ isAdmin: false }, '_id');
    if (users.length === 0) return res.status(404).json({ message: 'No users found to broadcast to.' });

    const notifications = users.map(user => ({
        userId: user._id,
        title,
        message,
        type: 'promo',
        read: false
    }));

    await Notification.insertMany(notifications);

    res.json({ message: `Broadcast sent to ${users.length} users.` });
}));

adminRouter.get('/chats', asyncHandler(async (req, res) => {
    const sessions = await LiveChatSession.find({ status: { $in: ['open', 'active'] } })
        .populate('userId', 'displayName email')
        .sort({ updatedAt: -1 });
    res.json(sessions);
}));

adminRouter.get('/chats/:chatId', asyncHandler(async (req, res) => {
    const session = await LiveChatSession.findById(req.params.chatId).populate('userId', 'displayName email');
    if (!session) return res.status(404).json({ message: "Chat session not found." });
    res.json(session);
}));

adminRouter.post('/chats/:chatId/message', asyncHandler(async (req, res) => {
    const { chatId } = req.params;
    const { text } = req.body;
    const adminUser = req.user;

    if (!text) return res.status(400).json({ message: "Message text cannot be empty." });

    const session = await LiveChatSession.findById(chatId);
    if (!session) return res.status(404).json({ message: "Chat session not found." });

    const adminReply = {
        senderId: adminUser._id.toString(), senderName: adminUser.displayName || 'Admin Support',
        text: text, isAdmin: true, timestamp: new Date()
    };

    session.messages.push(adminReply);
    if (session.status === 'open') session.status = 'active';

    const updatedSession = await session.save();

    await new Notification({
        userId: session.userId,
        title: 'New message from support',
        message: `An agent has replied in your live chat session.`,
        type: 'chat'
    }).save();

    res.status(201).json(updatedSession);
}));

adminRouter.post('/chats/:chatId/close', asyncHandler(async (req, res) => {
    const updatedSession = await LiveChatSession.findByIdAndUpdate(
        req.params.chatId, { status: 'closed' }, { new: true }
    );
    if (!updatedSession) return res.status(404).json({ message: 'Chat session not found.' });
    res.json({ message: 'Chat session closed successfully.' });
}));

// --- Deprecated Chatbot Route ---
app.post('/api/chat', (req, res) => res.status(410).json({ message: "This endpoint is deprecated and no longer available. Please use the AI Chat service." }));

// --- HTTPS Redirection ---
app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'https') return next();
    res.redirect(`https://${req.headers.host}${req.url}`);
});

// --- Logging Middleware ---
app.use((req, res, next) => {
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
    });

    next();
});

// --- Error Handler ---
app.use(errorHandler);

// --- Unhandled Rejection Handler ---
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Optionally, shut down the application
    // process.exit(1);
});

// --- Uncaught Exception Handler ---
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // Optionally, shut down the application
    // process.exit(1);
});

// --- Security Best Practices ---
console.warn("SECURITY: Implement automated security scanning in CI/CD.");
console.warn("SECURITY: Schedule regular security audits by experts.");
console.warn("SECURITY: Establish a vulnerability disclosure program.");
console.warn("SECURITY: Define and practice an incident response plan.");

// --- Server Start ---
const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('MongoDB connection error:', err));
