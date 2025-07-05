/// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss-clean');
const multer = require('multer');
const Joi = require('joi');
const winston = require('winston');

// --- Logger Configuration ---
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [ new winston.transports.File({ filename: 'error.log', level: 'error' }), new winston.transports.File({ filename: 'combined.log' }) ],
});
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({ format: winston.format.combine(winston.format.colorize(), winston.format.simple()) }));
}

// --- Safety Check ---
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET || !process.env.MONGODB_URI) {
    logger.error('FATAL ERROR: A required environment variable is not defined.');
    process.exit(1);
}

const app = express();

// --- Core Middleware ---
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(mongoSanitize());
app.use(hpp());
app.use(xss());

// --- Rate Limiting ---
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: "Too many authentication attempts.", standardHeaders: true, legacyHeaders: false });
app.use('/api/auth', authLimiter);
const generalLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 200, message: 'Too many requests.', standardHeaders: true, legacyHeaders: false });
app.use(['/api/support', '/api/subscriptions', '/api/users', '/api/admin', '/api/feedback', '/api/notifications'], generalLimiter);

// --- Mongoose Schemas & Models ---
const UserSchema = new mongoose.Schema({ refreshToken: { type: String, index: true }, email: { type: String, required: true, unique: true, lowercase: true, trim: true }, password: { type: String, required: true }, displayName: { type: String }, isAdmin: { type: Boolean, default: false }, isModemInstalled: { type: Boolean, default: false }, photoUrl: { type: String }, mobileNumber: { type: String }, birthday: { type: String }, gender: { type: String }, address: { type: String }, phase: { type: String }, city: { type: String }, province: { type: String }, zipCode: { type: String }, pushToken: { type: String } }, { timestamps: true });
UserSchema.pre('save', async function (next) { if (!this.isModified('password')) return next(); const salt = await bcrypt.genSalt(12); this.password = await bcrypt.hash(this.password, salt); next(); });
UserSchema.methods.matchPassword = async function (enteredPassword) { return await bcrypt.compare(enteredPassword, this.password); };
const User = mongoose.model('User', UserSchema);

const SubscriptionSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, status: { type: String, enum: ['active', 'pending_verification', 'pending_installation', 'declined', 'cancelled'], required: true }, plan: { name: String, price: Number, priceLabel: String, features: [String] }, paymentMethod: { type: String }, startDate: { type: Date }, renewalDate: { type: Date }, declineReason: { type: String }, history: [{ type: { type: String, required: true }, details: String, date: { type: Date, default: Date.now }, amount: Number, receiptNumber: String, planName: String }], proofOfPayment: { type: String, default: null } }, { timestamps: true });
const Subscription = mongoose.model('Subscription', SubscriptionSchema);

const BillSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, subscriptionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription', required: true }, planName: String, amount: Number, statementDate: { type: Date, default: Date.now }, dueDate: Date, status: { type: String, enum: ['Due', 'Paid', 'Overdue'], default: 'Due' }, paymentDate: Date, }, { timestamps: true });
const Bill = mongoose.model('Bill', BillSchema);

const FeedbackSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, userName: String, userPhotoUrl: String, rating: { type: Number, required: true }, text: { type: String, required: true }, }, { timestamps: true });
const Feedback = mongoose.model('Feedback', FeedbackSchema);

const SupportTicketSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, userName: String, subject: { type: String, required: true }, description: { type: String, required: true }, status: { type: String, enum: ['Open', 'In Progress', 'Resolved', 'Closed'], default: 'Open' }, adminComment: { type: String, default: '' }, imageUrl: { type: String } }, { timestamps: true });
const SupportTicket = mongoose.model('SupportTicket', SupportTicketSchema);

const NotificationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, title: { type: String, required: true }, message: { type: String, required: true }, type: { type: String, default: 'default' }, read: { type: Boolean, default: false }, }, { timestamps: true });
const Notification = mongoose.model('Notification', NotificationSchema);

const LiveChatSessionSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, userName: String, status: { type: String, enum: ['open', 'active', 'closed'], default: 'open' }, messages: [{ senderId: { type: String, required: true }, senderName: String, text: { type: String, required: true }, isAdmin: { type: Boolean, default: false }, timestamp: { type: Date, default: Date.now } }] }, { timestamps: true });
const LiveChatSession = mongoose.model('LiveChatSession', LiveChatSessionSchema);

// --- Utility & Security Middleware ---
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const validate = (schema) => (req, res, next) => { const { error } = schema.validate(req.body); if (error) return res.status(400).json({ message: error.details[0].message }); next(); };

const authorize = (role = null) => asyncHandler(async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) { return res.status(401).json({ message: 'Authorization token is required.' }); }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) { return res.status(401).json({ message: "User not found, authorization denied." }); }
        req.user = user;
        if (role === 'admin' && !user.isAdmin) { return res.status(403).json({ message: 'Access denied. Admin role required.' }); }
        next();
    } catch (error) {
        logger.warn(`Token verification failed: ${error.message}`);
        return res.status(401).json({ message: 'Token is not valid or has expired.' });
    }
});

// --- Validation Schemas ---
const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$/).message("Password must be at least 8 characters and include an uppercase letter, a number, and a special character").required(),
    displayName: Joi.string().required(),
});
const passwordChangeSchema = Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$/).message("New password must meet complexity requirements.").required()
});


// --- API ROUTES ---
// --- Auth Routes ---
app.get('/api/health', (req, res) => res.status(200).json({ status: "ok", message: "Server is healthy." }));

app.post('/api/auth/register', validate(registerSchema), asyncHandler(async (req, res) => {
    const { displayName, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(409).json({ message: 'User with this email already exists.' });
    const user = new User({ displayName, email, password });
    await user.save();
    res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
    const { email, password, rememberMe } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password))) {
        return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const accessToken = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: rememberMe ? '30d' : '1d' });
    user.refreshToken = refreshToken;
    await user.save();
    res.json({
        accessToken,
        refreshToken,
        user: { _id: user._id, displayName: user.displayName, email: user.email, isAdmin: user.isAdmin, photoUrl: user.photoUrl }
    });
}));

app.post('/api/auth/refresh', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "Refresh token is required." });
    const userInDb = await User.findOne({ refreshToken });
    if (!userInDb) return res.status(403).json({ message: "Invalid session. Please log in again." });
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
        if (err || decoded.id !== userInDb._id.toString()) {
            return res.status(403).json({ message: "Invalid or expired session. Please log in again." });
        }
        const newAccessToken = jwt.sign({ id: userInDb._id, isAdmin: userInDb.isAdmin }, process.env.JWT_SECRET, { expiresIn: '15m' });
        res.json({ accessToken: newAccessToken });
    });
}));

app.post('/api/auth/logout', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(204);
    await User.findOneAndUpdate({ refreshToken }, { $set: { refreshToken: null } });
    res.sendStatus(204);
}));

// --- User Routes ---
app.get('/api/users/me', authorize(), asyncHandler(async (req, res) => {
    res.json(req.user);
}));

app.put('/api/users/me', authorize(), asyncHandler(async (req, res) => {
    const { password, isAdmin, email, ...updateData } = req.body;
    const updatedUser = await User.findByIdAndUpdate(req.user.id, { $set: updateData }, { new: true, runValidators: true }).select('-password');
    if (!updatedUser) return res.status(404).json({ message: 'User not found' });
    res.json(updatedUser);
}));

app.post('/api/users/me/photo', authorize(), fileUpload.single('profilePic'), asyncHandler(async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    const filetype = await fileTypeFromBuffer(req.file.buffer);
    if (!filetype || !allowedMimeTypes.includes(filetype.mime)) {
        return res.status(400).json({ message: 'Invalid file type. Only JPEG, PNG, and GIF are allowed.' });
    }
    const photoUrl = `data:${filetype.mime};base64,${req.file.buffer.toString('base64')}`;
    const user = await User.findByIdAndUpdate(req.user.id, { photoUrl }, { new: true }).select('-password');
    res.status(200).json({ message: 'Photo uploaded successfully.', user });
}));

app.put('/api/users/change-password', authorize(), validate(passwordChangeSchema), asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    if (!(await user.matchPassword(currentPassword))) {
        return res.status(401).json({ message: "Incorrect current password." });
    }
    user.password = newPassword;
    user.refreshToken = null; 
    await user.save();
    res.status(200).json({ message: "Password changed successfully. You have been logged out from other devices." });
}));

app.post('/api/users/push-token', authorize(), asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user.id, { pushToken: req.body.token });
    res.status(200).json({ message: 'Token updated successfully' });
}));

// --- Subscription & Billing Routes ---
app.get('/api/subscriptions/details', authorize(), asyncHandler(async (req, res) => {
    const subscription = await Subscription.findOne({ userId: req.user.id }).sort({ createdAt: -1 });
    const bills = await Bill.find({ userId: req.user.id }).sort({ createdAt: -1 });
    if (!subscription && bills.length === 0) return res.json({ status: null, subscriptionData: null, activePlan: null, paymentHistory: [], renewalDate: null });
    const billHistory = bills.map(b => ({ id: b._id, type: 'bill', status: b.status, amount: b.amount, planName: b.planName, statementDate: b.statementDate, paymentDate: b.paymentDate, date: b.createdAt }));
    const combinedHistory = [...(subscription?.history || []), ...billHistory].sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json({
        status: subscription?.status, subscriptionData: subscription, activePlan: subscription?.plan,
        paymentHistory: combinedHistory, renewalDate: subscription?.renewalDate,
    });
}));

app.post('/api/subscriptions/subscribe', authorize(), asyncHandler(async (req, res, next) => {
    const { plan, paymentMethod, proofOfPayment } = req.body;
    const userId = req.user.id;
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const needsInstallation = req.user.isModemInstalled !== true;
        let newSubscription, notificationTitle, notificationMessage;
        if (paymentMethod === 'Cash on Delivery') {
            if (needsInstallation) {
                newSubscription = new Subscription({ userId, status: 'pending_installation', plan, paymentMethod, history: [{ type: 'subscribed', details: `Subscription initiated. Awaiting field agent for installation and payment.` }] });
                notificationTitle = 'Application Received!';
                notificationMessage = `We've received your application for ${plan.name}. Our agent will contact you for the installation schedule.`;
            } else {
                const startDate = new Date();
                const renewalDate = new Date(startDate);
                renewalDate.setMonth(startDate.getMonth() + 1);
                newSubscription = new Subscription({ userId, status: 'active', plan, paymentMethod, startDate, renewalDate, history: [{ type: 'activated', details: `Re-subscribed to ${plan.name} via Cash on Delivery.`, amount: plan.price, planName: plan.name }] });
                await new Bill({ userId, subscriptionId: newSubscription._id, planName: plan.name, amount: plan.price, dueDate: new Date(new Date().setDate(new Date().getDate() + 7)), status: 'Due' }).save({ session });
                notificationTitle = 'Subscription Reactivated!';
                notificationMessage = `Your ${plan.name} plan is now active. Your first bill is due soon.`;
            }
        } else if (paymentMethod === 'GCash') {
            if (!proofOfPayment) throw new Error("Proof of payment is required for GCash.");
            newSubscription = new Subscription({ userId, status: 'pending_verification', plan, paymentMethod, proofOfPayment, history: [{ type: 'submitted_payment', details: `User submitted GCash payment for ${plan.name}`, amount: plan.price, planName: plan.name }] });
            notificationTitle = 'Payment Submitted!';
            notificationMessage = `We've received your payment proof for ${plan.name}. We'll verify it shortly.`;
        } else {
            return res.status(400).json({ message: "Invalid payment method specified." });
        }
        await newSubscription.save({ session });
        await new Notification({ userId, title: notificationTitle, message: notificationMessage }).save({ session });
        await session.commitTransaction();
        res.status(201).json(newSubscription);
    } catch (error) {
        await session.abortTransaction();
        next(error);
    } finally {
        session.endSession();
    }
}));

app.post('/api/billing/pay', authorize(), asyncHandler(async (req, res) => {
    const { billId, amount, planName } = req.body;
    await Bill.findByIdAndUpdate(billId, { status: 'Paid', paymentDate: new Date() });
    await Subscription.findOneAndUpdate(
        { userId: req.user.id, status: 'active' },
        { $push: { history: { $each: [{ type: 'payment_success', details: `Paid bill for ${planName}`, amount, planName, receiptNumber: `RCPT-${Date.now()}` }], $sort: { date: -1 } } } }
    );
    res.status(200).json({ message: "Payment successful" });
}));

app.post('/api/subscriptions/cancel', authorize(), asyncHandler(async (req, res) => {
    const subscription = await Subscription.findOneAndUpdate(
        { userId: req.user.id, status: { $in: ['active', 'pending_verification', 'pending_installation'] } },
        { $set: { status: 'cancelled' }, $push: { history: { type: 'cancelled', details: `User cancelled the subscription.`, date: new Date() } } },
        { new: true }
    );
    if (!subscription) return res.status(404).json({ message: 'No cancellable subscription found.' });
    res.status(200).json({ message: 'Subscription cancelled successfully.' });
}));

app.post('/api/subscriptions/clear', authorize(), asyncHandler(async (req, res) => {
    await Subscription.deleteOne({ userId: req.user.id, status: 'declined' });
    res.status(204).send();
}));

// --- Feedback Routes ---
app.get('/api/feedback', asyncHandler(async (req, res) => {
    const feedbacks = await Feedback.find().sort({ createdAt: -1 }).limit(parseInt(req.query.limit) || 5);
    res.json(feedbacks);
}));

app.post('/api/feedback', authorize(), asyncHandler(async (req, res) => {
    const newFeedback = new Feedback({ ...req.body, userId: req.user.id, userName: req.user.displayName, userPhotoUrl: req.user.photoUrl });
    await newFeedback.save();
    res.status(201).json(newFeedback);
}));

app.put('/api/feedback/:id', authorize(), asyncHandler(async (req, res) => {
    const { rating, text } = req.body;
    const updatedFeedback = await Feedback.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        { $set: { rating, text } },
        { new: true }
    );
    if (!updatedFeedback) return res.status(404).json({ message: 'Feedback not found or you are not authorized to edit it.' });
    res.json(updatedFeedback);
}));

app.delete('/api/feedback/:id', authorize(), asyncHandler(async (req, res) => {
    const feedback = await Feedback.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!feedback) return res.status(404).json({ message: 'Feedback not found or you are not authorized to delete it.' });
    res.json({ message: 'Feedback removed successfully.' });
}));

// --- Support & Notification Routes ---
app.post('/api/support/tickets', authorize(), asyncHandler(async (req, res) => {
    const { subject, description, imageData } = req.body;
    const openTickets = await SupportTicket.countDocuments({ userId: req.user.id, status: 'Open' });
    if (openTickets >= 5) return res.status(429).json({ message: "You have reached the maximum number of open tickets." });
    const newTicket = new SupportTicket({ userId: req.user.id, userName: req.user.displayName, subject, description, imageUrl: imageData || null });
    await newTicket.save();
    await new Notification({ userId: req.user.id, title: 'Support Ticket Received', message: `We've received your ticket: "${newTicket.subject}".` }).save();
    res.status(201).json(newTicket);
}));

app.get('/api/support/tickets', authorize(), asyncHandler(async (req, res) => {
    const tickets = await SupportTicket.find({ userId: req.user.id }).sort({ updatedAt: -1 });
    res.json(tickets);
}));

app.get('/api/support/tickets/:id', authorize(), asyncHandler(async (req, res) => {
    const ticket = await SupportTicket.findOne({ _id: req.params.id, userId: req.user.id });
    if (!ticket) return res.status(404).json({ message: "Ticket not found or you're not authorized to view it." });
    res.json(ticket);
}));

app.post('/api/support/tickets/:id/reply', authorize(), asyncHandler(async (req, res) => {
    const ticket = await SupportTicket.findOne({ _id: req.params.id, userId: req.user.id });
    if (!ticket) return res.status(404).json({ message: "Ticket not found or you're not authorized to reply." });
    const newReply = { senderId: req.user.id, senderName: req.user.displayName, text: req.body.text, isAdmin: false };
    ticket.messages.push(newReply);
    if (['Resolved', 'Closed'].includes(ticket.status)) ticket.status = 'In Progress';
    const updatedTicket = await ticket.save();
    res.status(201).json(updatedTicket);
}));

// --- Admin Routes ---
const adminRouter = express.Router();
app.use('/api/admin', authorize('admin'), adminRouter);

adminRouter.get('/subscriptions/pending', asyncHandler(async (req, res) => {
    const pending = await Subscription.find({ status: { $in: ['pending_verification', 'pending_installation'] } })
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
    await new Notification({ userId: sub.userId, title: 'Subscription Update', message: `Your payment submission was declined. Reason: ${reason}`, type: 'warning' }).save();
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

// --- Deprecated Route ---
app.post('/api/chat', (req, res) => res.status(410).json({ message: "This endpoint is deprecated. Please use the AI Chat service." }));

// --- Final Middleware ---
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

const centralErrorHandler = (err, req, res, next) => {
    logger.error(err.message, { stack: err.stack, path: req.path, method: req.method });
    const statusCode = err.statusCode || 500;
    const response = {
        success: false,
        message: err.message || 'An unexpected server error occurred.'
    };
    if (process.env.NODE_ENV !== 'production') {
        response.stack = err.stack;
    }
    res.status(statusCode).json(response);
};
app.use(centralErrorHandler);

// --- Server Start ---
const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        logger.info('MongoDB Connected Successfully.');
        app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
    })
    .catch(err => {
        logger.error('FATAL: MongoDB connection error:', err);
        process.exit(1);
    });

process.on('unhandledRejection', (reason, promise) => { logger.error('Unhandled Rejection at:', { promise, reason: reason.message }); });
process.on('uncaughtException', (err) => { logger.error('Uncaught Exception:', err); });
