const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Datastore = require('@seald-io/nedb');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const SUPER_USER = process.env.SUPER_ADMIN_USER || 'superadmin';
const SUPER_PASS = process.env.SUPER_ADMIN_PASS || 'admin123';

function createApp(db = {}) {
    const app = express();
    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));

    // ── Database ────────────────────────────────────────────────────────────
    const orgs  = db.orgs  || new Datastore({ filename: 'orgs.db',  autoload: true });
    const users = db.users || new Datastore({ filename: 'users.db', autoload: true });
    const flags = db.flags || new Datastore({ filename: 'flags.db', autoload: true });

    users.ensureIndex({ fieldName: 'username', unique: true });
    flags.ensureIndex({ fieldName: ['organizationId', 'featureKey'], unique: true });

    // ── Middleware ──────────────────────────────────────────────────────────
    function auth(role) {
        return (req, res, next) => {
            const token = (req.headers.authorization || '').split(' ')[1];
            if (!token) return res.status(401).json({ error: 'Token missing.' });
            jwt.verify(token, JWT_SECRET, (err, user) => {
                if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
                if (user.role !== role) return res.status(403).json({ error: 'Forbidden.' });
                req.user = user;
                next();
            });
        };
    }

    // ── Super Admin ─────────────────────────────────────────────────────────
    app.post('/api/super/login', (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
        if (username !== SUPER_USER || password !== SUPER_PASS)
            return res.status(401).json({ error: 'Invalid credentials.' });
        const token = jwt.sign({ username, role: 'super' }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token });
    });

    app.post('/api/super/organizations', auth('super'), (req, res) => {
        const { name } = req.body;
        if (!name || !name.trim()) return res.status(400).json({ error: 'Organization name required.' });
        orgs.findOne({ name: name.trim() }, (err, existing) => {
            if (existing) return res.status(409).json({ error: 'Organization name already exists.' });
            orgs.insert({ name: name.trim() }, (err, org) => {
                if (err) return res.status(500).json({ error: err.message });
                res.status(201).json(org);
            });
        });
    });

    app.get('/api/super/organizations', auth('super'), (req, res) => {
        orgs.find({}, (err, all) => res.json(all));
    });

    // ── Org Admin ───────────────────────────────────────────────────────────
    app.post('/api/admin/signup', async (req, res) => {
        const { username, password, organizationId } = req.body;
        if (!username || !password || !organizationId)
            return res.status(400).json({ error: 'All fields required.' });
        orgs.findOne({ _id: organizationId }, async (err, org) => {
            if (!org) return res.status(400).json({ error: 'Invalid organization ID.' });
            const hashed = await bcrypt.hash(password, 10);
            users.insert({ username, password: hashed, organizationId, role: 'admin' }, (err) => {
                if (err && err.errorType === 'uniqueViolated')
                    return res.status(409).json({ error: 'Username already taken.' });
                if (err) return res.status(500).json({ error: err.message });
                res.status(201).json({ message: 'Account created.' });
            });
        });
    });

    app.post('/api/admin/login', (req, res) => {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
        users.findOne({ username }, async (err, user) => {
            if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
            const match = await bcrypt.compare(password, user.password);
            if (!match) return res.status(401).json({ error: 'Invalid credentials.' });
            const token = jwt.sign(
                { id: user._id, username: user.username, role: 'admin', organizationId: user.organizationId },
                JWT_SECRET, { expiresIn: '8h' }
            );
            res.json({ token, organizationId: user.organizationId });
        });
    });

    // ── Feature Flags ───────────────────────────────────────────────────────
    app.get('/api/flags', auth('admin'), (req, res) => {
        flags.find({ organizationId: req.user.organizationId }, (err, all) => res.json(all));
    });

    app.post('/api/flags', auth('admin'), (req, res) => {
        const { featureKey, enabled } = req.body;
        if (!featureKey) return res.status(400).json({ error: 'featureKey required.' });
        flags.insert(
            { featureKey: featureKey.trim().toLowerCase(), enabled: !!enabled, organizationId: req.user.organizationId },
            (err, flag) => {
                if (err && err.errorType === 'uniqueViolated')
                    return res.status(409).json({ error: 'Flag key already exists.' });
                if (err) return res.status(500).json({ error: err.message });
                res.status(201).json(flag);
            }
        );
    });

    app.put('/api/flags/:id', auth('admin'), (req, res) => {
        const { enabled } = req.body;
        if (typeof enabled === 'undefined') return res.status(400).json({ error: 'enabled field required.' });
        flags.update(
            { _id: req.params.id, organizationId: req.user.organizationId },
            { $set: { enabled: !!enabled } }, {},
            (err, n) => {
                if (err) return res.status(500).json({ error: err.message });
                if (n === 0) return res.status(404).json({ error: 'Flag not found.' });
                res.json({ message: 'Flag updated.' });
            }
        );
    });

    app.delete('/api/flags/:id', auth('admin'), (req, res) => {
        flags.remove({ _id: req.params.id, organizationId: req.user.organizationId }, {}, (err, n) => {
            if (err) return res.status(500).json({ error: err.message });
            if (n === 0) return res.status(404).json({ error: 'Flag not found.' });
            res.json({ message: 'Flag deleted.' });
        });
    });

    // ── End User ────────────────────────────────────────────────────────────
    app.get('/api/check-flag', (req, res) => {
        const { organizationId, featureKey } = req.query;
        if (!organizationId || !featureKey)
            return res.status(400).json({ error: 'organizationId and featureKey required.' });
        orgs.findOne({ _id: organizationId }, (err, org) => {
            if (!org) return res.status(404).json({ error: 'Organization not found.' });
            flags.findOne({ organizationId, featureKey: featureKey.toLowerCase() }, (err, flag) => {
                res.json({ enabled: flag ? flag.enabled : false });
            });
        });
    });

    return app;
}

if (require.main === module) {
    const app = createApp();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
}

module.exports = createApp;
