// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');// FIX: This was a typo, should be require('jsonwebtoken')
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');

// --- Safety Check ---
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET or REFRESH_TOKEN_SECRET is not defined in the .env file.');
    process.exit(1);
}

const API_SECRET_KEY = process.env.API_SECRET_KEY;

const app = express();

app.use(cors());
app.use(express.json({
    limit: '10mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));

// --- DB Connection ---
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('MongoDB Connected Successfully.'))
.catch((err) => console.error('MongoDB Connection Error:', err));

// =================================================================
// --- SCHEMAS ---
// =================================================================

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
}, { timestamps: true });

UserSchema.pre('save', async function(next) { if (!this.isModified('password')) return next(); const salt = await bcrypt.genSalt(10); this.password = await bcrypt.hash(this.password, salt); next(); });
UserSchema.methods.matchPassword = async function(enteredPassword) { return await bcrypt.compare(enteredPassword, this.password); };

const SubscriptionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: { type: String, enum: ['active', 'pending_verification', 'pending_installation', 'declined', 'cancelled'], required: true },
    plan: { name: String, price: Number, priceLabel: String, features: [String], },
    paymentMethod: { type: String },
    startDate: { type: Date },
    renewalDate: { type: Date },
    declineReason: { type: String },
    history: [{ type: { type: String, required: true }, details: String, date: { type: Date, default: Date.now }, amount: Number, receiptNumber: String, planName: String, }],
    proofOfPayment: { type: String, default: null } 
}, { timestamps: true });
const BillSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, subscriptionId: { type: String, ref: 'Subscription', required: true }, planName: String, amount: Number, statementDate: { type: Date, default: Date.now }, dueDate: Date, status: { type: String, enum: ['Due', 'Paid', 'Overdue'], default: 'Due' }, paymentDate: Date, }, { timestamps: true });
const FeedbackSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, userName: String, userPhotoUrl: String, rating: { type: Number, required: true }, text: { type: String, required: true }, }, { timestamps: true });
const SupportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userName: String,
    subject: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['Open', 'In Progress', 'Resolved', 'Closed'], default: 'Open' },
    adminComment: { type: String, default: '' },
    imageUrl: { type: String }, // For image uploads
    // --- FIX: Added messages array to the schema to store conversation history ---
    messages: [{
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        senderName: String,
        text: { type: String, required: true },
        isAdmin: { type: Boolean, default: false },
        timestamp: { type: Date, default: Date.now }
    }],
}, { timestamps: true });
const NotificationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, title: { type: String, required: true }, message: { type: String, required: true }, type: { type: String, default: 'default' }, read: { type: Boolean, default: false }, }, { timestamps: true });
const LiveChatSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userName: String,
    status: { type: String, enum: ['open', 'active', 'closed'], default: 'open' },
    messages: [{
        senderId: { type: String, required: true }, // Can be user ID or 'system'
        senderName: String,
        text: { type: String, required: true },
        // --- FIX: Added isAdmin field to differentiate message styling on the frontend ---
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

// --- AUTH MIDDLEWARE ---
const checkAuth = (req, res, next) => { let token; const authHeader = req.headers.authorization; if (authHeader && authHeader.startsWith('Bearer ')) { try { token = authHeader.split(' ')[1]; const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET); req.user = decoded.id; next(); } catch (error) { res.status(401).json({ message: 'Not authorized, token failed' }); } } if (!token) { res.status(401).json({ message: 'Not authorized, no token' }); } };
const checkAdmin = async (req, res, next) => {
    let token;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            token = authHeader.split(' ')[1];
            const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id).select('-password');
            if (user && user.isAdmin) {
                req.user = user; // Attach full admin user object to request
                return next();
            } else {
                return res.status(403).json({ message: 'Access denied. Admin role required.' });
            }
        } catch (error) {
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    if (!token) {
        return res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const checkSignature = (req, res, next) => {
    // Whitelist public routes that should not be signed
    const publicRoutes = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/api/health'];
    if (publicRoutes.includes(req.path)) {
        return next();
    }

    const timestamp = req.header('X-Request-Timestamp');
    const signatureFromClient = req.header('X-Request-Signature');

    if (!timestamp || !signatureFromClient) {
        return res.status(400).json({ message: 'Missing security headers.' });
    }

    // --- Replay Attack Prevention ---
    const now = Math.floor(Date.now() / 1000);
    if (now - parseInt(timestamp) > 60) { // 60-second tolerance
        return res.status(408).json({ message: 'Request has expired. Please check your device time.' });
    }

    
    // --- Reconstruct the exact same string as the client ---
    const method = req.method;
    const path = req.originalUrl; // Use originalUrl to include query params
    const body = req.rawBody && req.rawBody.length > 0 ? req.rawBody : null;
    
    let dataToSign = `${timestamp}.${method}.${path}`;
    if (body) {
        dataToSign += `.${body}`;
    }

    // --- Generate the signature on the server ---
    const expectedSignature = crypto.createHmac('sha256', API_SECRET_KEY)
                                  .update(dataToSign)
                                  .digest('base64');
    
    // --- Compare signatures ---
    if (signatureFromClient !== expectedSignature) {
        return res.status(403).json({ message: 'Invalid request signature.' });
    }
    
    next();
};

// --- Apply the signature middleware globally to all routes ---
app.use('/api', checkSignature);
// =================================================================
// --- API ROUTES ---
// =================================================================

// --- Auth Routes (Public) ---
// --- NEW/UPDATED: Health Check Route ---
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: "ok", message: "Node.js server is running." });
});
app.post('/api/auth/register', async (req, res) => { const { displayName, email, password } = req.body; try { const userExists = await User.findOne({ email }); if (userExists) return res.status(400).json({ message: 'User with this email already exists.' }); const user = new User({ displayName, email, password }); await user.save(); res.status(201).json({ message: 'User registered successfully.' }); } catch (error) { console.error("Registration Error:", error); res.status(500).json({ message: "Server error during registration." }); } });
// Replace your existing /api/auth/login route with this

app.post('/api/auth/login', async (req, res) => {
    // We now expect a `rememberMe` boolean from the client
    const { email, password, rememberMe } = req.body; 
    try {
        const user = await User.findOne({ email });

        if (user && (await user.matchPassword(password))) {
            // --- NEW TOKEN LOGIC ---

            // 1. Create a short-lived Access Token (for accessing APIs)
            const accessToken = require('jsonwebtoken').sign(
                { id: user._id },
                process.env.JWT_SECRET, // Or a dedicated ACCESS_TOKEN_SECRET
                { expiresIn: '15m' }   // Expires in 15 minutes
            );

            // 2. Create a long-lived Refresh Token (for getting a new access token)
            const refreshToken = require('jsonwebtoken').sign(
                { id: user._id },
                process.env.REFRESH_TOKEN_SECRET, // Use a DIFFERENT secret for refresh tokens
                { expiresIn: rememberMe ? '30d' : '1d' } // 30 days if "Remember Me", 1 day otherwise
            );

            // 3. Store the new refresh token in the user's DB record.
            // This allows you to invalidate their session from the server if needed.
            user.refreshToken = refreshToken;
            await user.save();

            // 4. Send BOTH tokens and user info back to the client
            res.json({
                accessToken,
                refreshToken,
                user: {
                    _id: user._id,
                    displayName: user.displayName,
                    email: user.email,
                    isAdmin: user.isAdmin,
                }
            });
        } else {
            res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server error during login." });
    }
});

// REFRESH TOKEN ROUTE
app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "Refresh token is required." });

    try {
        const userInDb = await User.findOne({ refreshToken });
        if (!userInDb) return res.status(403).json({ message: "Invalid session. Please log in again." });
        
        // Verify the incoming refresh token
        require('jsonwebtoken').verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
            if (err) return res.status(403).json({ message: "Invalid or expired session. Please log in again." });

            // --- TOKEN ROTATION LOGIC ---
            // 1. Issue a new access token (short-lived)
            const newAccessToken = require('jsonwebtoken').sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
            
            // 2. Issue a NEW refresh token (long-lived)
            const newRefreshToken = require('jsonwebtoken').sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' });

            // 3. Save the NEW refresh token to the database, overwriting the old one.
            userInDb.refreshToken = newRefreshToken;
            await userInDb.save();

            // 4. Send both new tokens to the client
            res.json({ 
                accessToken: newAccessToken,
                refreshToken: newRefreshToken, // Send the new refresh token back
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Internal server error." });
    }
});

// LOGOUT ROUTE
app.post('/api/auth/logout', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.sendStatus(204);

    try {
        // Invalidate the session by removing the refresh token from the database
        await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
        res.sendStatus(204);
    } catch (error) {
        res.sendStatus(500).json({ message: "Internal server error." });
    }
});

// --- User Routes (Protected) ---
app.get('/api/users/me', checkAuth, async (req, res) => { try { const user = await User.findById(req.user).select('-password'); if (!user) return res.status(404).json({ message: 'User not found' }); res.json(user); } catch (error) { console.error(`Error in GET /api/users/me for user ${req.user}:`, error); res.status(500).json({ message: "An internal server error occurred." }); } });
app.put('/api/users/me', checkAuth, async (req, res) => { try { const user = await User.findById(req.user); if (!user) return res.status(404).json({ message: 'User not found' }); user.displayName = req.body.displayName ?? user.displayName; user.mobileNumber = req.body.mobileNumber ?? user.mobileNumber; user.birthday = req.body.birthday ?? user.birthday; user.gender = req.body.gender ?? user.gender; user.address = req.body.address ?? user.address; user.phase = req.body.phase ?? user.phase; user.city = req.body.city ?? user.city; user.province = req.body.province ?? user.province; user.zipCode = req.body.zipCode ?? user.zipCode; if (req.body.photoData && req.body.photoData.base64) { user.photoUrl = `data:${req.body.photoData.mimeType};base64,${req.body.photoData.base64}`; } const updatedUser = await user.save(); const userResponse = updatedUser.toObject(); delete userResponse.password; res.json(userResponse); } catch (error) { res.status(500).json({ message: error.message }); } });
app.put('/api/users/change-password', checkAuth, async (req, res) => { const { currentPassword, newPassword } = req.body; try { const user = await User.findById(req.user); if (!user) return res.status(404).json({ message: "User not found." }); if (await user.matchPassword(currentPassword)) { user.password = newPassword; await user.save(); res.status(200).json({ message: "Password changed successfully." }); } else { res.status(401).json({ message: "Incorrect current password." }); } } catch(error) { console.error("Change Password Error:", error); res.status(500).json({ message: "Server error while changing password." }); } });
app.post('/api/users/push-token', checkAuth, async (req, res) => { try { await User.findByIdAndUpdate(req.user, { pushToken: req.body.token }); res.status(200).json({ message: 'Token updated successfully' }); } catch (error) { res.status(500).json({ message: error.message }); }});

// --- Subscription & Billing Routes (Protected) ---
app.get('/api/subscriptions/details', checkAuth, async (req, res) => { try { const subscription = await Subscription.findOne({ userId: req.user }).sort({ createdAt: -1 }); const bills = await Bill.find({ userId: req.user }).sort({ createdAt: -1 }); if (!subscription && bills.length === 0) return res.json({ status: null, subscriptionData: null, activePlan: null, paymentHistory: [], renewalDate: null }); const billHistory = bills.map(b => ({ id: b._id, type: 'bill', status: b.status, amount: b.amount, planName: b.planName, statementDate: b.statementDate, paymentDate: b.paymentDate, date: b.createdAt })); const combinedHistory = [...(subscription?.history || []), ...billHistory].sort((a, b) => new Date(b.date) - new Date(a.date)); res.json({ status: subscription?.status, subscriptionData: subscription, activePlan: subscription?.plan, paymentHistory: combinedHistory, renewalDate: subscription?.renewalDate, }); } catch (error) { res.status(500).json({ message: error.message }); }});
app.post('/api/subscriptions/subscribe', checkAuth, async (req, res) => {
    try {
        const { plan, paymentMethod, proofOfPayment, location } = req.body;
        const user = await User.findById(req.user);

        if (!user) { return res.status(404).json({ message: "User not found." }); }
        const needsInstallation = (user.isModemInstalled !== true);

        if (paymentMethod === 'Cash on Delivery') {
            if (needsInstallation){
                const newSubscription = new Subscription({
                    userId: req.user, status: 'pending_installation', plan: plan, paymentMethod: paymentMethod,
                    history: [{ type: 'subscribed', details: `Subscription initiated. Awaiting field agent for installation and payment.` }],
                });
                await newSubscription.save();
                await new Notification({
                    userId: req.user, title: 'Application Received!',
                    message: `We've received your application for ${plan.name}. Please wait for our field agent to contact you for the installation schedule.`,
                }).save();
                return res.status(201).json(newSubscription);
            } else {
                const startDate = new Date();
                const renewalDate = new Date();
                renewalDate.setMonth(renewalDate.getMonth() + 1);
                const newSubscription = new Subscription({
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
                return res.status(201).json(savedSubscription);
            }
        } else if (paymentMethod === 'GCash') {
            if (!proofOfPayment) { return res.status(400).json({ message: "Proof of payment is required for GCash." }); }
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
    } catch (error) {
        console.error("Subscription Error:", error);
        res.status(500).json({ message: "Server error during subscription." });
    }
});

app.post('/api/billing/pay', checkAuth, async (req, res) => { try { const { billId, amount, planName } = req.body; await Bill.findByIdAndUpdate(billId, { status: 'Paid', paymentDate: new Date() }); await Subscription.findOneAndUpdate( { userId: req.user, status: 'active' }, { $push: { history: { $each: [{ type: 'payment_success', details: `Paid bill for ${planName}`, amount: amount, planName: planName, receiptNumber: `RCPT-${Date.now()}` }], $sort: { date: -1 } } } } ); res.status(200).json({ message: "Payment successful" }); } catch (error) { res.status(500).json({ message: error.message }); }});

app.post('/api/subscriptions/cancel', checkAuth, async (req, res) => {
    try {
        const subscription = await Subscription.findOne({
            userId: req.user,
            // Added 'pending_installation' to the list of cancellable statuses
            status: { $in: ['active', 'pending_verification', 'pending_installation'] }
        });

        if (!subscription) {
            return res.status(404).json({ message: 'No cancellable subscription found.' });
        }

        const originalStatus = subscription.status;
        subscription.history.unshift({
            type: 'cancelled',
            details: `User cancelled the subscription while its status was '${originalStatus}'.`,
            date: new Date(),
        });
        subscription.status = 'cancelled';
        await subscription.save();

        res.status(200).json({ message: 'Subscription cancelled successfully.' });

    } catch (error) {
        console.error("Cancellation error:", error);
        res.status(500).json({ message: 'An internal server error occurred during cancellation.' });
    }
});
app.post('/api/subscriptions/clear', checkAuth, async (req, res) => { try { await Subscription.deleteOne({userId: req.user, status: 'declined'}); res.status(204).send(); } catch(error) { res.status(500).json({ message: error.message }); }});

// --- Feedback Routes ---
app.get('/api/feedback', async (req, res) => { try { const feedbacks = await Feedback.find().sort({ createdAt: -1 }).limit(parseInt(req.query.limit) || 5); res.json(feedbacks); } catch (error) { res.status(500).json({ message: error.message }); }});
app.post('/api/feedback', checkAuth, async (req, res) => { try { const user = await User.findById(req.user); if(!user) return res.status(404).json({ message: "User not found" }); const newFeedback = new Feedback({ ...req.body, userId: req.user, userName: user.displayName, userPhotoUrl: user.photoUrl, }); await newFeedback.save(); res.status(201).json(newFeedback); } catch (error) { res.status(500).json({ message: error.message }); }});
app.put('/api/feedback/:id', checkAuth, async (req, res) => {
    try {
        const { rating, text } = req.body;
        const feedback = await Feedback.findById(req.params.id);

        if (!feedback) {
            return res.status(404).json({ message: 'Feedback not found.' });
        }

        // --- Security Check: Ensure the user owns the feedback ---
        if (feedback.userId.toString() !== req.user) {
            return res.status(403).json({ message: 'User not authorized to edit this feedback.' });
        }

        feedback.rating = rating;
        feedback.text = text;
        
        const updatedFeedback = await feedback.save();
        res.json(updatedFeedback);

    } catch (error) {
        console.error("Feedback update error:", error);
        res.status(500).json({ message: 'Server error while updating feedback.' });
    }
});


// --- NEW: Delete a specific feedback item ---
app.delete('/api/feedback/:id', checkAuth, async (req, res) => {
    try {
        const feedback = await Feedback.findById(req.params.id);

        if (!feedback) {
            return res.status(404).json({ message: 'Feedback not found.' });
        }

        // --- Security Check: Ensure the user owns the feedback ---
        if (feedback.userId.toString() !== req.user) {
            return res.status(403).json({ message: 'User not authorized to delete this feedback.' });
        }

        await feedback.deleteOne(); // Use deleteOne() on the document
        res.json({ message: 'Feedback removed successfully.' });

    } catch (error) {
        console.error("Feedback delete error:", error);
        res.status(500).json({ message: 'Server error while deleting feedback.' });
    }
});
// --- Support & Notification Routes ---
app.post('/api/support/tickets', checkAuth, async (req, res) => {
    try {
        // --- FIX: Destructure `imageData` but use it for the `imageUrl` field ---
        const { subject, description, imageData } = req.body;
        const user = await User.findById(req.user);
        const openTickets = await SupportTicket.countDocuments({ userId: req.user, status: 'Open' });
        if (openTickets >= 5) {
            return res.status(429).json({ message: "You have reached the maximum number of open tickets." });
        }
        
        const newTicket = new SupportTicket({
            userId: req.user,
            userName: user.displayName,
            subject: subject,
            description: description,
            // --- FIX: The field in the schema is `imageUrl` ---
            imageUrl: imageData || null
        });

        await newTicket.save();
        
        await new Notification({
            userId: req.user,
            title: 'Support Ticket Received',
            message: `We've received your ticket: "${newTicket.subject}".`,
        }).save();
        
        res.status(201).json(newTicket);
    } catch (error) {
        if (error.type === 'entity.too.large') {
            return res.status(413).json({ message: "Image file is too large." });
        }
        res.status(500).json({ message: error.message });
    }
});
// --- NEW: Get all tickets for the logged-in user ---
app.get('/api/support/tickets', checkAuth, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ userId: req.user }).sort({ updatedAt: -1 });
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// --- NEW: Get a single ticket's details and full message history ---
app.get('/api/support/tickets/:id', checkAuth, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket || ticket.userId.toString() !== req.user) {
            return res.status(404).json({ message: "Ticket not found or you're not authorized to view it." });
        }
        res.json(ticket);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// --- NEW: Add a reply to a ticket (can be from a user or an admin) ---
app.post('/api/support/tickets/:id/reply', checkAuth, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        
        // --- FIX: Logic needs to handle replies from admins too. This requires checkAdmin middleware.
        // For now, we'll assume this endpoint is for USERS ONLY to simplify.
        // The admin-specific reply endpoint in the adminRouter is the correct place for admin replies.
        if (!ticket || ticket.userId.toString() !== req.user) {
            return res.status(404).json({ message: "Ticket not found or you're not authorized to reply." });
        }
        
        const user = await User.findById(req.user);

        const newReply = {
            senderId: req.user,
            senderName: user.displayName,
            text: req.body.text,
            isAdmin: false // User replies are never admin replies
        };
        
        // --- FIX: Push the reply into the `messages` array ---
        ticket.messages.push(newReply);
        
        // If a user replies, re-open the ticket.
        if (ticket.status === 'Resolved' || ticket.status === 'Closed') {
            ticket.status = 'In Progress';
        }

        const updatedTicket = await ticket.save();
        res.status(201).json(updatedTicket);

    } catch (error) {
        console.error("Ticket reply error:", error)
        res.status(500).json({ message: error.message });
    }
});
app.post('/api/support/request-agent', checkAuth, async (req, res) => {
    try {
        const userId = req.user;
        
        // Step 1: Look for an existing, non-closed chat session for this user.
        let session = await LiveChatSession.findOne({ 
            userId, 
            status: { $in: ['open', 'active'] } 
        });

        // Step 2: If a session already exists, just return its ID.
        if (session) {
            console.log(`Found existing session for user ${userId}: ${session._id}`);
            return res.status(200).json({ 
                message: 'Existing chat session found.', 
                chatId: session._id 
            });
        }

        // Step 3: If no session exists, create a new one.
        console.log(`No active session found for user ${userId}. Creating new one.`);
        const user = await User.findById(userId).select('displayName');
        session = new LiveChatSession({
            userId: userId,
            userName: user.displayName,
            status: 'open',
            messages: [{
                senderId: 'system',
                senderName: 'System',
                text: 'A support agent will be with you shortly.'
            }]
        });
        await session.save();

        res.status(201).json({ 
            message: 'Live chat session requested.', 
            chatId: session._id 
        });

    } catch (error) {
        console.error("Agent request error:", error);
        res.status(500).json({ message: "Could not request an agent." });
    }
});


app.post('/api/support/live-chat/:chatId/message', checkAuth, async (req, res) => {
    try {
        // --- SECURITY FIX: Do NOT trust `isAdmin` from the client. ---
        // We only need the `text` from the request body.
        const { text } = req.body;
        const { chatId } = req.params;
        const userId = req.user;

        const session = await LiveChatSession.findById(chatId);
        
        // Security check: Only the customer who owns the session can post.
        if (!session || session.userId.toString() !== userId) {
            return res.status(403).json({ message: 'You are not authorized to post in this chat session.' });
        }

        const sender = await User.findById(userId).select('displayName');
        session.messages.push({
            senderId: userId,
            senderName: sender.displayName,
            text,
            // --- SECURITY FIX: `isAdmin` is ALWAYS false for this user-facing endpoint. ---
            // The admin-only endpoint will be responsible for setting it to true.
            isAdmin: false, 
        });
        await session.save();
        res.status(201).json(session);
    } catch (error) {
        console.error("Send message error:", error);
        res.status(500).json({ message: 'Could not send message.' });
    }
});

app.get('/api/support/live-chat/:chatId', checkAuth, async (req, res) => {
    try {
        const { chatId } = req.params;
        const session = await LiveChatSession.findById(chatId);

        // Security check: User must own the session. Admins will use a separate route.
        if (!session || (session.userId.toString() !== req.user)) {
            return res.status(404).json({ message: "Chat session not found or access denied." });
        }
        
        res.status(200).json(session);

    } catch (error) {
        console.error("Fetch chat session error:", error);
        res.status(500).json({ message: "Could not retrieve chat session." });
    }
});

app.get('/api/support/live-chat/:chatId/listen', checkAuth, async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const { chatId } = req.params;

    const sendMessages = (messages) => {
        res.write(`data: ${JSON.stringify(messages)}\n\n`);
    };
    
    // Immediately send the current messages
    try {
        const initialSession = await LiveChatSession.findById(chatId);
        // Security check: Ensure the user is authorized before setting up the stream
        if (initialSession && initialSession.userId.toString() === req.user) {
            sendMessages(initialSession.messages);
        } else {
            // If not authorized, send an error and close the connection.
            res.write(`data: ${JSON.stringify({error: "Access Denied"})}\n\n`);
            return res.end();
        }
    } catch (e) { console.error(e); }

    // Set up MongoDB Change Stream
    const changeStream = LiveChatSession.watch([
        { $match: { 'fullDocument._id': new mongoose.Types.ObjectId(chatId) } }
    ]);

    changeStream.on('change', (change) => {
        // Double-check the document exists and has the messages field
        if (change.operationType === 'update' && change.fullDocument && change.fullDocument.messages) {
             sendMessages(change.fullDocument.messages);
        }
    });

    req.on('close', () => {
        changeStream.close();
        res.end();
    });
});
app.delete('/api/support/live-chat/:chatId', checkAuth, async (req, res) => {
    try {
        const { chatId } = req.params;
        const session = await LiveChatSession.findById(chatId);

        // Security check: only the user who owns the chat can delete it
        if (!session || session.userId.toString() !== req.user) {
            return res.status(404).json({ message: 'Chat session not found or access denied.' });
        }

        await session.deleteOne();
        res.status(200).json({ message: 'Chat session deleted successfully.' });

    } catch (error) {
        console.error("Delete chat session error:", error);
        res.status(500).json({ message: 'Could not delete chat session.' });
    }
});
app.delete('/api/support/live-chat/:chatId/message/:messageId', checkAuth, async (req, res) => {
    try {
        const { chatId, messageId } = req.params;
        const userId = req.user;

        const session = await LiveChatSession.findById(chatId);

        if (!session || session.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        // --- FIX: More secure pull. Only let users delete their OWN messages. ---
        // An admin's deletion logic would be in an admin-specific route.
        const result = await LiveChatSession.updateOne(
            { _id: chatId },
            { $pull: { messages: { _id: new mongoose.Types.ObjectId(messageId), senderId: userId } } }
        );

        if (result.modifiedCount === 0) {
            // This now means either the message doesn't exist OR the user doesn't own it.
            return res.status(404).json({ message: "Message not found or you are not authorized to delete it." });
        }
        
        res.status(200).json({ message: 'Message deleted successfully.' });

    } catch (error) {
        console.error("Delete message error:", error);
        res.status(500).json({ message: 'Could not delete message.' });
    }
});
app.get('/api/notifications', checkAuth, async (req, res) => { try { const notifications = await Notification.find({ userId: req.user }).sort({ createdAt: -1 }); res.json(notifications); } catch (error) { res.status(500).json({ message: error.message }); }});
app.post('/api/notifications/mark-read', checkAuth, async (req, res) => { try { const { ids } = req.body; const query = { userId: req.user }; if (ids && ids.length > 0) { query._id = { $in: ids }; } await Notification.updateMany(query, { read: true }); res.status(200).json({ message: 'Notifications marked as read' }); } catch (error) { res.status(500).json({ message: error.message }); }});
app.post('/api/notifications/delete', checkAuth, async (req, res) => { try { const { ids } = req.body; if (!ids || ids.length === 0) return res.status(400).json({ message: 'No notification IDs provided' }); await Notification.deleteMany({ userId: req.user, _id: { $in: ids } }); res.status(200).json({ message: 'Notifications deleted' }); } catch (error) { res.status(500).json({ message: error.message }); }});

// --- SECURITY FIX: These powerful routes MUST be protected by checkAdmin, not checkAuth. ---
app.post('/api/admin/approve-payment/:subscriptionId', checkAdmin, async (req, res) => {
    try {
        const { subscriptionId } = req.params;
        const subscription = await Subscription.findById(subscriptionId);
        if (!subscription || subscription.status !== 'pending_verification') {
            return res.status(404).json({ message: "Subscription not found or not awaiting verification." });
        }

        const user = await User.findById(subscription.userId);
        if (!user) { return res.status(404).json({ message: "Associated user not found." }); }
        const needsInstallation = (user.isModemInstalled !== true);
        
        if (needsInstallation) {
            subscription.status = 'pending_installation';
            subscription.history.unshift({ type: 'payment_success', details: 'GCash payment approved by admin. Awaiting installation.' });
            await subscription.save();
            
            await new Notification({
                userId: subscription.userId, title: 'Payment Approved!',
                message: `Your GCash payment has been approved. Please wait for our field agent to schedule your installation.`,
            }).save();
            res.status(200).json({ message: "Payment approved. Subscription is now pending installation." });
        
        } else {
            subscription.status = 'active';
            subscription.startDate = new Date();
            subscription.renewalDate = new Date(new Date().setMonth(new Date().getMonth() + 1));
            subscription.history.unshift({ type: 'activated', details: 'GCash payment approved. Subscription reactivated.' });
            await subscription.save();

            await new Bill({
                userId: subscription.userId, subscriptionId: subscription._id, planName: subscription.plan.name, amount: subscription.plan.price,
                dueDate: new Date(new Date().setDate(new Date().getDate() + 7)), status: 'Due',
            }).save();
            
            await new Notification({
                userId: subscription.userId, title: 'Subscription Reactivated!',
                message: `Your ${subscription.plan.name} is now active. Your first bill has been generated.`,
            }).save();
            res.status(200).json({ message: "Payment approved and subscription reactivated." });
        }
    } catch (error) {
        console.error("Admin Approval Error:", error);
        res.status(500).json({ message: "Server error during payment approval." });
    }
});

// --- SECURITY FIX: This route MUST be protected by checkAdmin, not checkAuth. ---
app.post('/api/admin/confirm-installation/:subscriptionId', checkAdmin, async (req, res) => {
    try {
        const { subscriptionId } = req.params;
        const subscription = await Subscription.findById(subscriptionId);
        if (!subscription || subscription.status !== 'pending_installation') {
            return res.status(404).json({ message: "Subscription not found or not awaiting installation." });
        }

        const user = await User.findById(subscription.userId);
        if (!user) { return res.status(404).json({ message: "Associated user not found." }); }

        // ACTIVATE THE PLAN
        subscription.status = 'active';
        subscription.startDate = new Date();
        subscription.renewalDate = new Date(new Date().setMonth(new Date().getMonth() + 1));
        subscription.history.unshift({ type: 'activated', details: `Installation complete. Plan is now active.` });
        
        // CREATE THE FIRST BILL
        const firstBill = new Bill({
            userId: subscription.userId,
            subscriptionId: subscription._id,
            planName: subscription.plan.name,
            amount: subscription.plan.price,
            dueDate: new Date(new Date().setDate(new Date().getDate() + 7)),
            status: 'Due',
        });
        
        // UPDATE USER'S PERMANENT RECORD
        user.isModemInstalled = true;

        await subscription.save();
        await firstBill.save();
        await user.save();

        await new Notification({
            userId: subscription.userId,
            title: 'Installation Complete!',
            message: `Welcome to the Fibear family! Your ${subscription.plan.name} plan is now active. You can now manage your subscription.`,
        }).save();

        res.status(200).json({ message: "Installation confirmed and subscription activated." });
    } catch (error) {
        console.error("Admin Installation Confirmation Error:", error);
        res.status(500).json({ message: "Server error during installation confirmation." });
    }
});
// --- Chatbot Route (Mock) ---
app.post('/api/chat', (req, res) => { 
    // FIX: Using 410 Gone is more semantically correct for a deprecated endpoint.
    res.status(410).json({ message: "This endpoint is deprecated and no longer available. Please use the AI Chat service." });
});

// =================================================================
// --- NEW ADMIN ROUTES ---
// =================================================================
const adminRouter = express.Router();
app.use('/api/admin', checkAdmin, adminRouter); // Protect all admin routes with middleware

// --- ADMIN: Get Pending Subscriptions ---
adminRouter.get('/subscriptions/pending', async (req, res) => {
    try {
        const pending = await Subscription.find({ $or: [{ status: 'pending_verification' }, { status: 'pending_installation' }] })
            .populate('userId', 'displayName email') // Populate with user's name and email
            .sort({ createdAt: 1 }); // Oldest first
        res.json(pending);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching pending subscriptions.' });
    }
});

// --- ADMIN: Decline Subscription ---
adminRouter.post('/subscriptions/:id/decline', async (req, res) => {
    try {
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
    } catch (error) {
        res.status(500).json({ message: 'Server error declining subscription.' });
    }
});

// --- ADMIN: Get All Support Tickets ---
adminRouter.get('/tickets', async (req, res) => {
    try {
        const tickets = await SupportTicket.find().sort({ updatedAt: -1 }); // Most recently updated first
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching tickets.' });
    }
});

// --- ADMIN: Update Support Ticket Status ---
adminRouter.post('/tickets/:id/status', async (req, res) => {
    try {
        const { status, adminComment } = req.body;
        const validStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
        if (!status || !validStatuses.includes(status)) {
            return res.status(400).json({ message: 'A valid status is required.' });
        }

        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' });
        
        const oldStatus = ticket.status;
        ticket.status = status;
        if(adminComment) ticket.adminComment = adminComment;
        await ticket.save();

        await new Notification({
            userId: ticket.userId,
            title: 'Support Ticket Updated',
            message: `Your ticket "${ticket.subject}" status changed from ${oldStatus} to ${status}.`,
            type: 'update'
        }).save();
        
        res.json({ message: 'Ticket status updated successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error updating ticket status.' });
    }
});

// --- ADMIN: Send Broadcast Notification ---
adminRouter.post('/broadcast', async (req, res) => {
    const { title, message } = req.body;
    if (!title || !message) return res.status(400).json({ message: 'Title and message are required.' });

    try {
        // Find all non-admin users
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
    } catch (error) {
        console.error("Broadcast Error:", error);
        res.status(500).json({ message: 'Server error sending broadcast.' });
    }
});

adminRouter.get('/chats', async (req, res) => {
    try {
        const sessions = await LiveChatSession.find({ status: { $in: ['open', 'active'] } })
            .populate('userId', 'displayName email')
            .sort({ updatedAt: -1 }); // Show most recently active first
        res.json(sessions);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching chat sessions.' });
    }
});

// --- ADMIN: Get a specific chat session's details ---
adminRouter.get('/chats/:chatId', async (req, res) => {
    try {
        const session = await LiveChatSession.findById(req.params.chatId).populate('userId', 'displayName email');
        if (!session) {
            return res.status(404).json({ message: "Chat session not found." });
        }
        res.json(session);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching chat details.' });
    }
});

// --- ADMIN: Send a message to a chat session ---
adminRouter.post('/chats/:chatId/message', async (req, res) => {
    const { chatId } = req.params;
    const { text } = req.body;
    const adminUser = req.user; // Admin user object from checkAdmin middleware

    if (!text) {
        return res.status(400).json({ message: "Message text cannot be empty." });
    }

    try {
        const session = await LiveChatSession.findById(chatId);
        if (!session) {
            return res.status(404).json({ message: "Chat session not found." });
        }

        const adminReply = {
            senderId: adminUser._id.toString(),
            senderName: adminUser.displayName || 'Admin Support',
            text: text,
            isAdmin: true, // Mark this message as from an admin
            timestamp: new Date()
        };

        session.messages.push(adminReply);
        if(session.status === 'open') session.status = 'active'; // Mark session as active
        
        const updatedSession = await session.save();

        // Notify the user they have a new message
        await new Notification({
            userId: session.userId,
            title: 'New message from support',
            message: `An agent has replied in your live chat session.`,
            type: 'chat'
        }).save();

        res.status(201).json(updatedSession);

    } catch (error) {
        res.status(500).json({ message: 'Server error sending message.' });
    }
});

// --- ADMIN: Close a chat session ---
adminRouter.post('/chats/:chatId/close', async (req, res) => {
    try {
        const updatedSession = await LiveChatSession.findByIdAndUpdate(
            req.params.chatId,
            { status: 'closed' },
            { new: true }
        );
        if (!updatedSession) {
            return res.status(404).json({ message: 'Chat session not found.' });
        }
        res.json({ message: 'Chat session closed successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error closing chat.' });
    }
});

// =================================================================
// --- SERVER START ---
// =================================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
