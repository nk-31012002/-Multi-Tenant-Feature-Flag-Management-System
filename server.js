const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Datastore = require('@seald-io/nedb');
const path = require('path');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-use-env-var';

// DATABASE INITIALIZATION
const db = {
    organizations: new Datastore({ filename: 'orgs.db', autoload: true }),
    users: new Datastore({ filename: 'users.db', autoload: true }),
    flags: new Datastore({ filename: 'flags.db', autoload: true })
};

db.users.ensureIndex({ fieldName: 'username', unique: true }, (err) => {
    if (err) console.error('Index error on users.username:', err);
});
db.flags.ensureIndex({ fieldName: ['organizationId', 'featureKey'], unique: true }, (err) => {
    if (err) console.error('Index error on flags compound key:', err);
});

// STATIC SUPER ADMIN CREDENTIALS
const SUPER_ADMIN_USER = process.env.SUPER_ADMIN_USER || "superadmin";
const SUPER_ADMIN_PASS = process.env.SUPER_ADMIN_PASS || "admin123";

// MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

const requireRole = (role) => (req, res, next) => {
    if (req.user.role !== role) {
        return res.status(403).json({ error: 'Forbidden: Insufficient privileges.' });
    }
    next();
};

// Simpl rate limiter
const rateLimitMap = new Map();
const rateLimit = (maxRequests, windowMs) => (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, start: now };

    if (now - entry.start > windowMs) {
        entry.count = 1;
        entry.start = now;
    } else {
        entry.count++;
    }
    rateLimitMap.set(ip, entry);

    if (entry.count > maxRequests) {
        return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    }
    next();
};


// ─── SUPER ADMIN ENDPOINTS ──────────────────────────────────────────────────
app.post('/api/super/login', (req, res) => {
    const { username, password } = req.body;

    // FIX 3: Validate inputs before comparing
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    if (username === SUPER_ADMIN_USER && password === SUPER_ADMIN_PASS) {
        const token = jwt.sign({ username, role: 'super' }, JWT_SECRET, { expiresIn: '2h' });
        return res.json({ token });
    }
    res.status(401).json({ error: 'Invalid credentials.' });
});

app.post('/api/super/organizations', authenticateToken, requireRole('super'), (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Organization name is required.' });

    db.organizations.findOne({ name: name.trim() }, (err, existing) => {
        if (err) return res.status(500).json({ error: err.message });
        if (existing) return res.status(409).json({ error: 'An organization with this name already exists.' });

        db.organizations.insert({ name: name.trim() }, (err, newOrg) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json(newOrg);
        });
    });
});

app.get('/api/super/organizations', authenticateToken, requireRole('super'), (req, res) => {
    db.organizations.find({}, (err, orgs) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(orgs);
    });
});

app.delete('/api/super/organizations/:id', authenticateToken, requireRole('super'), (req, res) => {
    db.organizations.remove({ _id: req.params.id }, {}, (err, numRemoved) => {
        if (err) return res.status(500).json({ error: err.message });
        if (numRemoved === 0) return res.status(404).json({ error: 'Organization not found.' });

        // Cascade: remove all admins and flags belonging to this org
        db.users.remove({ organizationId: req.params.id }, { multi: true }, () => {});
        db.flags.remove({ organizationId: req.params.id }, { multi: true }, () => {});

        res.json({ message: 'Organization and all associated data deleted.' });
    });
});


// ─── ORG ADMIN ENDPOINTS ────────────────────────────────────────────────────
app.post('/api/admin/signup', async (req, res) => {
    const { username, password, organizationId } = req.body;
    if (!username || !password || !organizationId) {
        return res.status(400).json({ error: 'username, password, and organizationId are all required.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    db.organizations.findOne({ _id: organizationId }, async (err, org) => {
        if (err || !org) return res.status(400).json({ error: 'Invalid Organization ID.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { username: username.trim(), password: hashedPassword, organizationId, role: 'admin' };

        db.users.insert(newUser, (insertErr) => {
            if (insertErr && insertErr.errorType === 'uniqueViolated') {
                return res.status(409).json({ error: 'Username already exists. Please choose another.' });
            }
            if (insertErr) return res.status(500).json({ error: insertErr.message });
            res.status(201).json({ message: 'Org Admin registered successfully.' });
        });
    });
});

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    db.users.findOne({ username }, async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role, organizationId: user.organizationId },
            JWT_SECRET,
            { expiresIn: '2h' }
        );
        res.json({ token, organizationId: user.organizationId });
    });
});


app.post('/api/flags', authenticateToken, requireRole('admin'), (req, res) => {
    const { featureKey, enabled } = req.body;
    if (!featureKey || !featureKey.trim()) {
        return res.status(400).json({ error: 'featureKey is required.' });
    }

    const newFlag = {
        featureKey: featureKey.trim().toLowerCase(),
        enabled: !!enabled,
        organizationId: req.user.organizationId
    };

    db.flags.insert(newFlag, (err, flag) => {
        if (err && err.errorType === 'uniqueViolated') {
            return res.status(409).json({ error: 'A flag with this key already exists in your organization.' });
        }
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json(flag);
    });
});

app.get('/api/flags', authenticateToken, requireRole('admin'), (req, res) => {
    db.flags.find({ organizationId: req.user.organizationId }, (err, flags) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(flags);
    });
});

app.put('/api/flags/:id', authenticateToken, requireRole('admin'), (req, res) => {
    const { enabled, featureKey } = req.body;
    const updates = {};

    if (typeof enabled !== 'undefined') updates.enabled = !!enabled;

    if (featureKey && featureKey.trim()) {
        updates.featureKey = featureKey.trim().toLowerCase();
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No valid fields to update. Provide enabled or featureKey.' });
    }

    db.flags.update(
        { _id: req.params.id, organizationId: req.user.organizationId },
        { $set: updates },
        {},
        (err, numUpdated) => {
            if (err && err.errorType === 'uniqueViolated') {
                return res.status(409).json({ error: 'A flag with that key already exists in your organization.' });
            }
            if (err) return res.status(500).json({ error: err.message });
            if (numUpdated === 0) return res.status(404).json({ error: 'Flag not found or unauthorized.' });
            res.json({ message: 'Flag updated successfully.' });
        }
    );
});

app.delete('/api/flags/:id', authenticateToken, requireRole('admin'), (req, res) => {
    db.flags.remove({ _id: req.params.id, organizationId: req.user.organizationId }, {}, (err, numRemoved) => {
        if (err) return res.status(500).json({ error: err.message });
        if (numRemoved === 0) return res.status(404).json({ error: 'Flag not found or unauthorized.' });
        res.json({ message: 'Flag removed successfully.' });
    });
});


// ─── END USER EVALUATION ENDPOINT ───────────────────────────────────────────
app.get('/api/user/check-flag', rateLimit(60, 60 * 1000), (req, res) => {
    const { organizationId, featureKey } = req.query;
    if (!organizationId || !featureKey) {
        return res.status(400).json({ error: 'Missing organizationId or featureKey.' });
    }

    db.organizations.findOne({ _id: organizationId }, (err, org) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!org) return res.status(404).json({ error: 'Organization not found.' });

        db.flags.findOne(
            { organizationId, featureKey: featureKey.trim().toLowerCase() },
            (err, flag) => {
                if (err) return res.status(500).json({ error: err.message });
                if (!flag) return res.json({ enabled: false, message: 'Flag does not exist (defaulting to disabled).' });
                res.json({ enabled: flag.enabled });
            }
        );
    });
});


app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));