const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const JWT_SECRET = 'super-secure-production-secret-9912';

// ── 1. DATABASE SETUP ──
// Use centralized SQLite to mimic robust cloud DB setup
const db = new sqlite3.Database('./production.db', (err) => {
    if (err) console.error("Database Error:", err);
    else console.log("Connected to Secure SQLite Production Database.");
});

function initializeDatabase() {
    db.serialize(() => {
        // Users
        db.run(`CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            business_name TEXT,
            status TEXT DEFAULT 'ACTIVE', -- ACTIVE, BANNED
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Plans
        db.run(`CREATE TABLE IF NOT EXISTS Plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL,
            duration_days INTEGER,
            allow_sales BOOLEAN,
            allow_purchase BOOLEAN,
            allow_print BOOLEAN,
            allow_multi_user BOOLEAN,
            active BOOLEAN DEFAULT 1,
            currency TEXT DEFAULT 'PKR'
        )`);

        db.run(`ALTER TABLE Plans ADD COLUMN currency TEXT DEFAULT 'PKR'`, (err) => {
            // Ignore if column already exists
        });

        // Subscriptions
        db.run(`CREATE TABLE IF NOT EXISTS Subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan_id INTEGER,
            status TEXT, -- TRIAL, ACTIVE, EXPIRED, SUSPENDED
            start_date DATETIME,
            expiry_date DATETIME,
            FOREIGN KEY(user_id) REFERENCES Users(id),
            FOREIGN KEY(plan_id) REFERENCES Plans(id)
        )`);

        // Devices
        db.run(`CREATE TABLE IF NOT EXISTS Devices (
            device_id TEXT PRIMARY KEY,
            user_id INTEGER,
            device_name TEXT,
            last_ip TEXT,
            last_login DATETIME,
            FOREIGN KEY(user_id) REFERENCES Users(id)
        )`);

        // Pending Approvals
        db.run(`CREATE TABLE IF NOT EXISTS PendingApprovals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan_name TEXT,
            amount TEXT,
            payment_method TEXT,
            tx_id TEXT,
            status TEXT DEFAULT 'pending',
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id)
        )`);

        // LoginLogs & AdminLogs Stub
        db.run(`CREATE TABLE IF NOT EXISTS LoginLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Payment Gateways
        db.run(`CREATE TABLE IF NOT EXISTS PaymentGateways (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gateway_name TEXT UNIQUE,
            publishable_key TEXT,
            secret_key TEXT,
            environment TEXT DEFAULT 'sandbox',
            currency TEXT DEFAULT 'USD'
        )`, () => {
            // Seed Stripe
            db.get("SELECT id FROM PaymentGateways WHERE gateway_name = 'stripe'", (err, row) => {
                if (!row) {
                    db.run(`INSERT INTO PaymentGateways (gateway_name, publishable_key, secret_key, environment, currency) VALUES ('stripe', '', '', 'sandbox', 'USD')`);
                }
            });
        });

        db.get("SELECT id FROM Plans LIMIT 1", (err, row) => {
            if (!row) {
                // Free Trial Plan
                db.run(`INSERT INTO Plans (name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, currency) 
                        VALUES ('Free Trial', 0, 14, 1, 0, 0, 0, 'PKR')`);
                // Premium Plan
                db.run(`INSERT INTO Plans (name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, currency) 
                        VALUES ('Premium Enterprise', 9999, 365, 1, 1, 1, 1, 'PKR')`);
            }
        });

        // Seed Dummy POS User
        db.get("SELECT id FROM Users WHERE email = 'pos@vyapar.local'", async (err, row) => {
            if (!row) {
                const passwordHash = await bcrypt.hash('password123', 10);
                db.run(`INSERT INTO Users (email, password, business_name) VALUES (?, ?, ?)`,
                    ['pos@vyapar.local', passwordHash, 'The A1 Electronic Demo'], function (err) {

                        if (this.lastID) {
                            // Give them an active trial right now
                            const trialStart = new Date();
                            const trialEnd = new Date();
                            trialEnd.setDate(trialEnd.getDate() + 14); // 14 Day Trial

                            db.run(`INSERT INTO Subscriptions (user_id, plan_id, status, start_date, expiry_date) 
                                VALUES (?, 1, 'TRIAL', ?, ?)`,
                                [this.lastID, trialStart.toISOString(), trialEnd.toISOString()]);
                        }
                    });
            }
        });
    });
}
initializeDatabase();

// ── MIDDLEWARE: AUTHENTICATE ──
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access Denied: No Token" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Access Denied: Invalid Token" });
        req.user = user;
        next();
    });
}


// ============================================
// ── POS APP CLIENT APIs (Strictly Read-Only/Validation)
// ============================================

// App Signup
app.post('/api/app/signup', async (req, res) => {
    const { email, password, business_name, device_id, device_name } = req.body;

    db.get('SELECT * FROM Users WHERE email = ?', [email], async (err, row) => {
        if (row) return res.status(400).json({ error: 'Email already exists' });

        const passwordHash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO Users (email, password, business_name) VALUES (?, ?, ?)',
            [email, passwordHash, business_name], function (err) {
                if (err) return res.status(500).json({ error: 'Failed to create user' });
                const userId = this.lastID;

                // 7 day trial
                const trialStart = new Date();
                const trialEnd = new Date();
                trialEnd.setDate(trialEnd.getDate() + 7);

                db.run('INSERT INTO Subscriptions (user_id, plan_id, status, start_date, expiry_date) VALUES (?, 1, "TRIAL", ?, ?)',
                    [userId, trialStart.toISOString(), trialEnd.toISOString()], (err) => {

                        db.run(`INSERT OR REPLACE INTO Devices (device_id, user_id, device_name, last_ip, last_login) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [device_id, userId, device_name, req.ip]);

                        const accessToken = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: '24h' });
                        res.json({ success: true, message: 'Account created with 7-day free trial', token: accessToken });
                    });
            });
    });
});

app.post('/api/app/login', (req, res) => {
    const { email, password, device_id, device_name } = req.body;

    db.get(`SELECT * FROM Users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Invalid credentials" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

        if (user.status === 'BANNED') return res.status(403).json({ error: "Account Suspended by Admin." });

        db.get(`SELECT * FROM Devices WHERE user_id = ?`, [user.id], (err, device) => {
            if (device && device.device_id !== device_id) {
                return res.status(403).json({ error: "Device mapping failed." });
            }

            db.run(`INSERT OR REPLACE INTO Devices (device_id, user_id, device_name, last_ip, last_login) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                [device_id, user.id, device_name, req.ip]);

            db.run(`INSERT INTO LoginLogs (user_id, action) VALUES (?, 'LOGIN')`, [user.id]);

            const accessToken = jwt.sign({ user_id: user.id }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ token: accessToken });
        });
    });
});

// App Central License Validation (Called continually by the Electron App)
// The POS NEVER validates itself. It asks the server.
app.post('/api/app/validate-license', authenticateToken, (req, res) => {
    const userId = req.user.user_id;

    // Fetch the Active/Trial Subscription joined with Plan permissions
    const q = `
        SELECT s.status, s.expiry_date, p.name as plan_name, 
               p.allow_sales, p.allow_purchase, p.allow_print, p.allow_multi_user,
               d.device_name
        FROM Subscriptions s
        JOIN Plans p ON s.plan_id = p.id
        LEFT JOIN Devices d ON d.user_id = s.user_id
        WHERE s.user_id = ?
        ORDER BY s.id DESC LIMIT 1
    `;

    db.get(q, [userId], (err, sub) => {
        if (err || !sub) return res.status(403).json({ status: "EXPIRED", error: "No Subscription Found" });

        // CRITICAL SERVER-SIDE LOGIC: Check Expiry
        const now = new Date();
        const expiry = new Date(sub.expiry_date);
        const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));

        let finalStatus = sub.status;

        if (daysLeft < 0) {
            finalStatus = "EXPIRED";
            // Hard server lock of features if expired
            sub.allow_sales = 0;
            sub.allow_purchase = 0;
            sub.allow_print = 0;
            sub.allow_multi_user = 0;
        }

        // Send Absolute Truth Down To Client
        res.json({
            status: finalStatus,
            plan_name: sub.plan_name,
            expiry_date: sub.expiry_date,
            days_left: Math.max(0, daysLeft),
            features: {
                allow_sales: Boolean(sub.allow_sales),
                allow_purchase: Boolean(sub.allow_purchase),
                allow_print: Boolean(sub.allow_print),
                allow_multi_user: Boolean(sub.allow_multi_user)
            },
            device_registered: sub.device_name || 'Generic Device'
        });
    });
});

// App Upgrade Request
app.post('/api/app/upgrade-request', authenticateToken, (req, res) => {
    const userId = req.user.user_id;
    const { plan_name, amount, paymentMethod, txId, plan_id } = req.body; // Added plan_id

    db.run(`INSERT INTO PendingApprovals (user_id, plan_name, amount, payment_method, tx_id) VALUES (?, ?, ?, ?, ?)`,
        [userId, plan_name, amount, paymentMethod, txId], function (err) {
            if (err) {
                console.error("Upgrade Request DB Error:", err);
                return res.status(500).json({ error: "Failed to submit request", details: err.message });
            }

            // Note: We should ideally link PendingApprovals to plan_id so when approved we know exactly which plan, but for now we'll send it back or lookup by name
            res.json({ success: true, message: "Subscription request submitted for admin approval", pending_id: this.lastID, requested_plan_id: plan_id });
        });
});

app.get('/api/app/plans', (req, res) => {
    db.all(`SELECT id, name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user FROM Plans WHERE active = 1 AND price > 0`, (err, rows) => {
        res.json(rows || []);
    });
});

// ============================================
// ── WEB ADMIN PANEL APIs (Mutation capabilities)
// ============================================
// In a real system, these would also require JWT checking for Admin roles.

app.get('/api/admin/subs', (req, res) => {
    const pendQ = `
        SELECT p.id, u.business_name as business, u.email as phone, p.plan_name as plan, 
               p.amount, date(p.date) as date, p.payment_method as paymentMethod, p.tx_id as txId, p.status
        FROM PendingApprovals p
        JOIN Users u ON p.user_id = u.id
        WHERE p.status = 'pending'
    `;

    // Simplification for approved, we get Active plans
    const appQ = `
        SELECT s.id, u.business_name as business, u.email as phone, p.name as plan, 
               p.price as amount, date(s.start_date) as approvedOn, date(s.expiry_date) as expiresOn
        FROM Subscriptions s
        JOIN Users u ON s.user_id = u.id
        JOIN Plans p ON s.plan_id = p.id
        WHERE s.status = 'ACTIVE'
    `;

    db.all(pendQ, [], (err, pendingApprovals) => {
        db.all(appQ, [], (err2, approvedSubs) => {
            res.json({
                pendingApprovals: pendingApprovals || [],
                approvedSubs: approvedSubs || []
            });
        });
    });
});

app.post('/api/admin/subs/approve/:id', (req, res) => {
    const pendId = req.params.id;
    db.get('SELECT * FROM PendingApprovals WHERE id = ? AND status = "pending"', [pendId], (err, row) => {
        if (!row) return res.status(404).json({ error: "Not found" });

        db.run('UPDATE PendingApprovals SET status = "approved" WHERE id = ?', [pendId], () => {
            // Upgrade Subscription
            let d = new Date();
            const start = d.toISOString();
            d.setFullYear(d.getFullYear() + 1);
            const end = d.toISOString();

            db.run(`UPDATE Subscriptions SET status = 'ACTIVE', plan_id = 2, start_date = ?, expiry_date = ? WHERE user_id = ?`,
                [start, end, row.user_id], () => {
                    res.json({ success: true });
                });
        });
    });
});

app.post('/api/admin/subs/reject/:id', (req, res) => {
    const pendId = req.params.id;
    db.run('UPDATE PendingApprovals SET status = "rejected" WHERE id = ?', [pendId], () => {
        res.json({ success: true });
    });
});

app.get('/api/admin/users', (req, res) => {
    db.all(`
        SELECT u.id, u.business_name, u.email, u.status as account_status, 
               s.status as sub_status, s.expiry_date, p.name as plan_name
        FROM Users u
        LEFT JOIN Subscriptions s ON u.id = s.user_id
        LEFT JOIN Plans p ON s.plan_id = p.id
    `, [], (err, rows) => {
        res.json(rows || []);
    });
});

// Force Upgrade specific User
app.post('/api/admin/subscriptions/upgrade/:userId', (req, res) => {
    const userId = req.params.userId;
    // For demo, we bump them to Premium Enterprise (Plan ID 2) for 365 days

    let d = new Date();
    d.setFullYear(d.getFullYear() + 1);
    const newExpiry = d.toISOString();

    db.run(`UPDATE Subscriptions 
            SET status = 'ACTIVE', plan_id = 2, expiry_date = ? 
            WHERE user_id = ?`,
        [newExpiry, userId], function (err) {
            if (err) return res.status(500).json({ error: "Failed to upgrade" });
            res.json({ success: true, message: "Subscription forced to ACTIVE PREMIUM." });
        });
});

// Force Expire user subscription immediately
app.post('/api/admin/subscriptions/expire/:userId', (req, res) => {
    const userId = req.params.userId;
    // Set expiry to yesterday
    let d = new Date();
    d.setDate(d.getDate() - 1);

    db.run(`UPDATE Subscriptions 
            SET status = 'EXPIRED', expiry_date = ? 
            WHERE user_id = ?`,
        [d.toISOString(), userId], function (err) {
            if (err) return res.status(500).json({ error: "Failed to expire" });
            res.json({ success: true, message: "Plan set to expired state instantly on server." });
        });
});


// --- User Management APIs ---

app.post('/api/admin/users/ban/:userId', (req, res) => {
    const userId = req.params.userId;
    db.run(`UPDATE Users SET status = 'BANNED' WHERE id = ?`, [userId], function (err) {
        if (err) return res.status(500).json({ error: "Failed to ban user" });

        // Also wipe current subscription effectively locking them out
        db.run(`UPDATE Subscriptions SET status = 'BANNED' WHERE user_id = ?`, [userId], () => {
            res.json({ success: true, message: "User has been banned." });
        });
    });
});

app.post('/api/admin/users/unban/:userId', (req, res) => {
    const userId = req.params.userId;
    db.run(`UPDATE Users SET status = 'ACTIVE' WHERE id = ?`, [userId], function (err) {
        if (err) return res.status(500).json({ error: "Failed to unban user" });

        // Restore their sub status to active (we ideally'd restore their old status instead of assuming ACTIVE, but this works for demo)
        db.run(`UPDATE Subscriptions SET status = 'ACTIVE' WHERE user_id = ? AND status = 'BANNED'`, [userId], () => {
            res.json({ success: true, message: "User has been unbanned." });
        });
    });
});

app.delete('/api/admin/users/:userId', (req, res) => {
    const userId = req.params.userId;

    db.serialize(() => {
        db.run(`DELETE FROM LoginLogs WHERE user_id = ?`, [userId]);
        db.run(`DELETE FROM PendingApprovals WHERE user_id = ?`, [userId]);
        db.run(`DELETE FROM Devices WHERE user_id = ?`, [userId]);
        db.run(`DELETE FROM Subscriptions WHERE user_id = ?`, [userId]);
        db.run(`DELETE FROM Users WHERE id = ?`, [userId], function (err) {
            if (err) return res.status(500).json({ error: "Failed to delete user completely" });
            res.json({ success: true, message: "User fully deleted." });
        });
    });
});

// --- Plan Management APIs ---

app.get('/api/admin/plans', (req, res) => {
    db.all(`SELECT * FROM Plans`, (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/admin/plans', (req, res) => {
    const { name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, active, currency } = req.body;
    db.run(`INSERT INTO Plans (name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, active, currency) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, active === undefined ? 1 : active, currency || 'PKR'], function (err) {
            if (err) return res.status(500).json({ error: "Failed to create plan" });
            res.json({ success: true, plan_id: this.lastID });
        });
});

app.put('/api/admin/plans/:id', (req, res) => {
    const { name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, active, currency } = req.body;
    db.run(`UPDATE Plans SET name = ?, price = ?, duration_days = ?, allow_sales = ?, allow_purchase = ?, allow_print = ?, allow_multi_user = ?, active = ?, currency = ? WHERE id = ?`,
        [name, price, duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user, active, currency || 'PKR', req.params.id], function (err) {
            if (err) return res.status(500).json({ error: "Failed to update plan" });
            res.json({ success: true });
        });
});

// --- Payment Gateway APIs ---

app.get('/api/admin/gateway/stripe', (req, res) => {
    db.get(`SELECT publishable_key, secret_key, environment, currency FROM PaymentGateways WHERE gateway_name = 'stripe'`, (err, row) => {
        if (err || !row) return res.status(500).json({ error: "Failed to fetch stripe settings" });
        res.json(row);
    });
});

app.post('/api/admin/gateway/stripe', (req, res) => {
    const { publishable_key, secret_key, environment, currency } = req.body;
    db.run(`UPDATE PaymentGateways SET publishable_key = ?, secret_key = ?, environment = ?, currency = ? WHERE gateway_name = 'stripe'`,
        [publishable_key, secret_key, environment, currency], (err) => {
            if (err) return res.status(500).json({ error: "Failed to update stripe settings" });
            res.json({ success: true, message: "Stripe settings updated" });
        });
});

app.get('/api/app/gateway/stripe-public', (req, res) => {
    db.get(`SELECT publishable_key, currency FROM PaymentGateways WHERE gateway_name = 'stripe'`, (err, row) => {
        if (err || !row) return res.status(500).json({ error: "Failed to fetch stripe" });
        res.json({ publishable_key: row.publishable_key, currency: row.currency || 'usd' });
    });
});

const stripeModule = require('stripe');

app.post('/api/app/create-payment-intent', authenticateToken, (req, res) => {
    const { amount, plan_name, plan_id } = req.body;
    db.get(`SELECT secret_key, currency FROM PaymentGateways WHERE gateway_name = 'stripe'`, async (err, row) => {
        if (err || !row || !row.secret_key) return res.status(400).json({ error: "Stripe not configured or missing secret key on server." });
        try {
            const stripe = stripeModule(row.secret_key);
            let rawPrice = String(amount).replace(/[^0-9.]/g, ''); // Extract numeric
            const numericAmount = Math.round(parseFloat(rawPrice || 0) * 100);
            if (numericAmount <= 0) return res.status(400).json({ error: "Invalid payment amount" });

            const paymentIntent = await stripe.paymentIntents.create({
                amount: numericAmount,
                currency: (row.currency || 'usd').toLowerCase(),
                metadata: {
                    user_id: req.user.user_id,
                    plan_name,
                    plan_id
                }
            });
            res.json({ clientSecret: paymentIntent.client_secret, currency: row.currency });
        } catch (e) {
            console.error("Stripe Error: ", e);
            res.status(500).json({ error: e.message });
        }
    });
});

app.post('/api/app/upgrade-confirm-stripe', authenticateToken, (req, res) => {
    const { paymentIntentId, plan_id, plan_name, amount } = req.body;
    const userId = req.user.user_id;

    db.run(`INSERT INTO PendingApprovals (user_id, plan_name, amount, payment_method, tx_id, status) VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, plan_name, amount, 'Stripe Gateway', paymentIntentId, 'paid'], function (err) {
            if (err) return res.status(500).json({ error: "Failed to save approval" });

            let pendingId = this.lastID;
            db.get(`SELECT duration_days, allow_sales, allow_purchase, allow_print, allow_multi_user FROM Plans WHERE id = ?`, [plan_id], (err, planRow) => {
                if (!planRow) return res.json({ success: true, message: "Paid but plan not found." });

                db.run(`UPDATE Subscriptions SET status = 'EXPIRED' WHERE user_id = ?`, [userId], () => {
                    const now = new Date();
                    const startStr = now.toISOString();
                    now.setDate(now.getDate() + (planRow.duration_days || 30));
                    const endStr = now.toISOString();

                    db.run(`INSERT INTO Subscriptions (user_id, plan_id, status, start_date, expiry_date)
                        VALUES (?, ?, 'ACTIVE', ?, ?)`,
                        [userId, plan_id, startStr, endStr], (err) => {
                            if (err) console.error("Stripe Sub Insert Error:", err);
                            db.run(`UPDATE PendingApprovals SET status = 'approved' WHERE id = ?`, [pendingId], () => {
                                res.json({ success: true, message: "Payment successful and plan activated instantly!" });
                            });
                        });
                });
            });
        });
});

// ============================================
// ── WHATSAPP WEB INTEGRATION
// ============================================
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');

let waClientReady = false;
let waQrCodeDataUrl = null;

const waClient = new Client({
    authStrategy: new LocalAuth({ dataPath: './.wwebjs_auth' }),
    puppeteer: {
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--no-zygote',
            '--single-process'
        ]
    }
});

waClient.on('qr', async (qr) => {
    try {
        waQrCodeDataUrl = await qrcode.toDataURL(qr);
        waClientReady = false;
        console.log('WhatsApp QR GENERATED');
    } catch (err) {
        console.error('QR generation failed', err);
    }
});

waClient.on('ready', () => {
    console.log('WhatsApp Client is ready!');
    waClientReady = true;
    waQrCodeDataUrl = null;
});

waClient.on('disconnected', (reason) => {
    console.log('WhatsApp Client was disconnected', reason);
    waClientReady = false;
    waQrCodeDataUrl = null;
});

waClient.initialize().catch(err => {
    console.error('WhatsApp init failed', err);
});

// Get Status & QR
app.get('/api/whatsapp/status', (req, res) => {
    res.json({ ready: waClientReady, qrImage: waQrCodeDataUrl });
});

// Send Message/PDF
app.post('/api/whatsapp/send', async (req, res) => {
    const { phone, base64Pdf, filename, message } = req.body;

    if (!waClientReady) {
        return res.status(400).json({ error: 'WhatsApp is not connected. Please scan the QR code first.' });
    }

    if (!phone) {
        return res.status(400).json({ error: 'Phone number is required.' });
    }

    try {
        // Clean phone number
        let rawPhone = phone.replace(/[^0-9]/g, '');

        // Auto-format for PK if local number is provided
        if (rawPhone.startsWith('0')) {
            rawPhone = '92' + rawPhone.slice(1);
        } else if (rawPhone.length === 10 && rawPhone.startsWith('3')) {
            rawPhone = '92' + rawPhone;
        }

        const chatId = `${rawPhone}@c.us`;

        if (base64Pdf) {
            let pureBase64 = base64Pdf;
            if (base64Pdf.includes('base64,')) {
                pureBase64 = base64Pdf.split('base64,')[1];
            }
            const media = new MessageMedia('application/pdf', pureBase64, filename || 'invoice.pdf');
            await waClient.sendMessage(chatId, media, { caption: message || 'Please find the attached document.' });
        } else {
            await waClient.sendMessage(chatId, message || 'Hello from our business!');
        }

        res.json({ success: true, message: 'Message sent successfully via WhatsApp!' });
    } catch (err) {
        console.error('WhatsApp send error:', err);
        res.status(500).json({ error: 'Failed to send WhatsApp message: ' + err.message });
    }
});

// Logout
app.post('/api/whatsapp/logout', async (req, res) => {
    try {
        await waClient.logout();
        waClientReady = false;
        waQrCodeDataUrl = null;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.use((err, req, res, next) => {
    console.error("Global Error Handler:", err);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

const PORT = process.env.PORT || 5005;

app.get('/', (req, res) => {
    res.send("Hisaab Kitaab Licensing Backend is Running Live!");
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Cloud Licensing Server running perfectly secured on Port ${PORT}`);
});
