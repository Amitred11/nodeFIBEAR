// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// --- Safety Check ---
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET or REFRESH_TOKEN_SECRET is not defined in the .env file.');
    process.exit(1);
}


const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

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
    proofOfPayment: { type: String },
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
    imageUrl: { type: String } // For image uploads
}, { timestamps: true });
const NotificationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, title: { type: String, required: true }, message: { type: String, required: true }, type: { type: String, default: 'default' }, read: { type: Boolean, default: false }, }, { timestamps: true });
const LiveChatSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userName: String,
    status: { type: String, enum: ['open', 'active', 'closed'], default: 'open' },
    messages: [{
        senderId: { type: String, required: true }, // Can be user ID or 'admin'
        senderName: String,
        text: { type: String, required: true },
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
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id).select('-password');
            if (user && user.isAdmin) {
                req.user = user; // Attach admin user object to request
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
                    user: { _id: user._id, displayName: user.displayName, email: user.email, isAdmin: user.isAdmin }
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
        // --- FIX: Destructure imageData from the body ---
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
            imageData: imageData || null
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
        // In a real app with an admin panel, an admin would bypass this check
        if (!ticket || ticket.userId.toString() !== req.user) {
            return res.status(404).json({ message: "Ticket not found or you're not authorized to reply." });
        }
        
        const user = await User.findById(req.user);
        const isAdminReply = req.body.isAdmin || false; // This would be 'true' if sent from an admin panel

        const newReply = {
            senderId: req.user,
            senderName: user.displayName,
            text: req.body.text,
            isAdmin: isAdminReply
        };
        
        ticket.messages.push(newReply);
        
        // If a user replies, re-open the ticket. If an admin replies, they set the status.
        if (!isAdminReply && (ticket.status === 'Resolved' || ticket.status === 'Closed')) {
            ticket.status = 'In Progress';
        }

        const updatedTicket = await ticket.save();
        res.status(201).json(updatedTicket);

    } catch (error) {
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
        const { text, isAdmin } = req.body; // <-- Receive isAdmin flag from the request
        const { chatId } = req.params;
        const userId = req.user; // This is the ID of whoever is logged in (customer or admin)

        const session = await LiveChatSession.findById(chatId);
        
        // Security check: Only the customer who owns the session or an admin can post.
        // In a real app, you would have a proper role check: if (session.userId.toString() !== userId && !user.isAdmin)
        if (!session) {
            return res.status(404).json({ message: 'Chat session not found.' });
        }

        const sender = await User.findById(userId).select('displayName');
        session.messages.push({
            senderId: userId,
            senderName: sender.displayName,
            text,
            // --- THE FIX: Use the flag from the request body ---
            // A customer app will send `false` or nothing. An admin app will send `true`.
            isAdmin: isAdmin || false, 
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

        // Security check
        if (!session || (session.userId.toString() !== req.user /* && !user.isAdmin */)) {
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
        if (initialSession && initialSession.userId.toString() === req.user) {
            sendMessages(initialSession.messages);
        }
    } catch (e) { console.error(e); }

    // Set up MongoDB Change Stream
    const changeStream = LiveChatSession.watch([
        { $match: { 'fullDocument._id': new mongoose.Types.ObjectId(chatId) } }
    ]);

    changeStream.on('change', (change) => {
        if (change.operationType === 'update' && change.updateDescription.updatedFields.messages) {
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

        // Security check: Ensure the user owns the chat session.
        if (!session || session.userId.toString() !== userId) {
            return res.status(404).json({ message: 'Chat session not found or access denied.' });
        }

        // Use $pull to efficiently remove the message from the array
        const result = await LiveChatSession.updateOne(
            { _id: chatId },
            { $pull: { messages: { _id: new mongoose.Types.ObjectId(messageId) } } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Message not found." });
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
app.post('/api/admin/approve-payment/:subscriptionId', checkAuth, async (req, res) => {
    try {
        const { subscriptionId } = req.params;
        const subscription = await Subscription.findById(subscriptionId);
        if (!subscription || subscription.status !== 'pending_verification') {
            return res.status(404).json({ message: "Subscription not found or not awaiting verification." });
        }

        const user = await User.findById(subscription.userId);
        if (!user) { return res.status(404).json({ message: "Associated user not found." }); }
        const needsInstallation = (user.isModemInstalled !== true);
        // NEW USER (needs installation)
        if (needsInstallation) {
            subscription.status = 'pending_installation';
            subscription.history.unshift({ type: 'payment_success', details: 'GCash payment approved by admin. Awaiting installation.' });
            await subscription.save();
            
            await new Notification({
                userId: subscription.userId, title: 'Payment Approved!',
                message: `Your GCash payment has been approved. Please wait for our field agent to schedule your installation.`,
            }).save();
            res.status(200).json({ message: "Payment approved. Subscription is now pending installation." });
        
        // RETURNING USER (has modem, activate immediately)
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

// --- NEW ENDPOINT - ACTION 2: Confirm Installation ---
app.post('/api/admin/confirm-installation/:subscriptionId', checkAuth, async (req, res) => {
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

        // --- REFINED NOTIFICATION LOGIC ---
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
    res.status(404).json({ message: "This endpoint is deprecated. Please use the AI Chat service." });
});

// =================================================================
// --- NEW ADMIN ROUTES ---
// =================================================================
const adminRouter = express.Router();
app.use('/api/admin', checkAdmin, adminRouter); // Protect all admin routes with middleware

// --- ADMIN: Get Pending Subscriptions ---
adminRouter.get('/subscriptions/pending', async (req, res) => {
    try {
        const pending = await Subscription.find({ status: 'pending_verification' })
            .populate('userId', 'displayName email') // Populate with user's name and email
            .sort({ submittedDate: 1 }); // Oldest first
        res.json(pending);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching pending subscriptions.' });
    }
});

// --- ADMIN: Approve Subscription ---
adminRouter.post('/subscriptions/:id/approve', async (req, res) => {
    try {
        const sub = await Subscription.findById(req.params.id);
        if (!sub) return res.status(404).json({ message: 'Subscription not found.' });
        
        // Logic for approval
        sub.status = 'active';
        sub.renewalDate = new Date(new Date().setDate(new Date().getDate() + 30));
        await sub.save();

        await new Notification({
            userId: sub.userId,
            title: 'Subscription Approved!',
            message: `Your subscription to ${sub.plan.name} is now active.`,
            type: 'promo' // Using 'promo' to match client's theme colors
        }).save();
        
        res.json({ message: 'Subscription approved successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error approving subscription.' });
    }
});

// --- ADMIN: Decline Subscription ---
adminRouter.post('/subscriptions/:id/decline', async (req, res) => {
    try {
        const { reason } = req.body;
        if (!reason) return res.status(400).json({ message: 'Decline reason is required.' });
        
        const sub = await Subscription.findByIdAndUpdate(
            req.params.id, 
            { status: 'declined', declineReason: reason },
            { new: true }
        );
        if (!sub) return res.status(404).json({ message: 'Subscription not found.' });

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

// --- ADMIN: Get Open Support Tickets ---
adminRouter.get('/tickets/open', async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ status: 'Open' }).sort({ createdAt: 1 }); // Oldest first
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching open tickets.' });
    }
});

// --- ADMIN: Close Support Ticket ---
adminRouter.post('/tickets/:id/close', async (req, res) => {
    try {
        const ticket = await SupportTicket.findByIdAndUpdate(
            req.params.id,
            { status: 'Closed', updatedAt: new Date() },
            { new: true }
        );
        if (!ticket) return res.status(404).json({ message: 'Ticket not found.' });

        await new Notification({
            userId: ticket.userId,
            title: 'Support Ticket Closed',
            message: `Your support ticket regarding "${ticket.subject}" has been closed.`,
            type: 'update'
        }).save();
        
        res.json({ message: 'Ticket closed successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error closing ticket.' });
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
            .sort({ updatedAt: -1 }); // Show most recently active first
        res.json(sessions);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching chat sessions.' });
    }
});

// --- ADMIN: Get a specific chat session's details ---
adminRouter.get('/chats/:chatId', async (req, res) => {
    try {
        const session = await LiveChatSession.findById(req.params.chatId);
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
            senderId: adminUser._id,
            senderName: adminUser.displayName || 'Admin',
            text: text,
            isAdmin: true, // Mark this message as from an admin
            timestamp: new Date()
        };

        session.messages.push(adminReply);
        session.status = 'active'; // Ensure session is marked as active
        
        const updatedSession = await session.save();

        // Notify the user they have a new message
        await new Notification({
            userId: session.userId,
            title: 'New message from support',
            message: `You have a new reply in your live chat session.`,
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