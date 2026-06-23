const request = require('supertest');
const createApp = require('../server');
const Datastore = require('@seald-io/nedb');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';

// Each test suite gets its own fresh in-memory DB
function freshApp() {
    const db = {
        orgs:  new Datastore(),
        users: new Datastore(),
        flags: new Datastore()
    };
    return createApp(db);
}

// ── helpers ──────────────────────────────────────────────────────────────────
async function superLogin(app) {
    const res = await request(app).post('/api/super/login').send({ username: 'superadmin', password: 'admin123' });
    return res.body.token;
}
async function createOrg(app, token, name = 'Test Org') {
    const res = await request(app).post('/api/super/organizations')
        .set('Authorization', `Bearer ${token}`).send({ name });
    return res.body;
}
async function signupAdmin(app, orgId, username = 'admin1', password = 'pass123') {
    return request(app).post('/api/admin/signup').send({ username, password, organizationId: orgId });
}
async function loginAdmin(app, username = 'admin1', password = 'pass123') {
    const res = await request(app).post('/api/admin/login').send({ username, password });
    return res.body;
}
async function createFlag(app, token, featureKey, enabled = false) {
    return request(app).post('/api/flags').set('Authorization', `Bearer ${token}`).send({ featureKey, enabled });
}

// ── Super Admin auth ──────────────────────────────────────────────────────────
describe('Super Admin — Auth', () => {
    let app;
    beforeEach(() => { app = freshApp(); });

    test('valid login returns token', async () => {
        const res = await request(app).post('/api/super/login').send({ username: 'superadmin', password: 'admin123' });
        expect(res.status).toBe(200);
        expect(res.body.token).toBeDefined();
    });
    test('wrong password returns 401', async () => {
        const res = await request(app).post('/api/super/login').send({ username: 'superadmin', password: 'wrong' });
        expect(res.status).toBe(401);
    });
    test('empty body returns 400', async () => {
        const res = await request(app).post('/api/super/login').send({});
        expect(res.status).toBe(400);
    });
});

// ── Organizations ─────────────────────────────────────────────────────────────
describe('Organizations', () => {
    let app, token;
    beforeEach(async () => { app = freshApp(); token = await superLogin(app); });

    test('create org returns 201', async () => {
        const res = await request(app).post('/api/super/organizations')
            .set('Authorization', `Bearer ${token}`).send({ name: 'Acme' });
        expect(res.status).toBe(201);
        expect(res.body._id).toBeDefined();
    });
    test('duplicate org name returns 409', async () => {
        await createOrg(app, token, 'DupOrg');
        const res = await request(app).post('/api/super/organizations')
            .set('Authorization', `Bearer ${token}`).send({ name: 'DupOrg' });
        expect(res.status).toBe(409);
    });
    test('empty name returns 400', async () => {
        const res = await request(app).post('/api/super/organizations')
            .set('Authorization', `Bearer ${token}`).send({ name: '' });
        expect(res.status).toBe(400);
    });
    test('list orgs returns array', async () => {
        await createOrg(app, token, 'OrgA');
        const res = await request(app).get('/api/super/organizations').set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
    });
});

// ── Admin signup & login ──────────────────────────────────────────────────────
describe('Admin — Signup & Login', () => {
    let app, token, org;
    beforeEach(async () => {
        app = freshApp();
        token = await superLogin(app);
        org = await createOrg(app, token, 'SignupOrg');
    });

    test('valid signup returns 201', async () => {
        const res = await signupAdmin(app, org._id);
        expect(res.status).toBe(201);
    });
    test('invalid org ID returns 400', async () => {
        const res = await signupAdmin(app, 'fake-id');
        expect(res.status).toBe(400);
    });
    test('duplicate username returns 409', async () => {
        await signupAdmin(app, org._id, 'dupuser');
        const res = await signupAdmin(app, org._id, 'dupuser');
        expect(res.status).toBe(409);
    });
    test('missing fields returns 400', async () => {
        const res = await request(app).post('/api/admin/signup').send({ username: 'x' });
        expect(res.status).toBe(400);
    });
    test('valid login returns token + organizationId', async () => {
        await signupAdmin(app, org._id);
        const res = await request(app).post('/api/admin/login').send({ username: 'admin1', password: 'pass123' });
        expect(res.status).toBe(200);
        expect(res.body.token).toBeDefined();
        expect(res.body.organizationId).toBe(org._id);
    });
    test('wrong password returns 401 with generic message', async () => {
        await signupAdmin(app, org._id);
        const res = await request(app).post('/api/admin/login').send({ username: 'admin1', password: 'wrong' });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Invalid credentials.');
    });
    test('nonexistent user returns same 401 (no enumeration)', async () => {
        const res = await request(app).post('/api/admin/login').send({ username: 'ghost', password: 'pass123' });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Invalid credentials.');
    });
});

// ── Authorization ─────────────────────────────────────────────────────────────
describe('Authorization', () => {
    let app, superToken, adminToken;
    beforeEach(async () => {
        app = freshApp();
        superToken = await superLogin(app);
        const org = await createOrg(app, superToken, 'AuthOrg');
        await signupAdmin(app, org._id);
        ({ token: adminToken } = await loginAdmin(app));
    });

    test('no token returns 401', async () => {
        expect((await request(app).get('/api/flags')).status).toBe(401);
    });
    test('bad token returns 403', async () => {
        const res = await request(app).get('/api/flags').set('Authorization', 'Bearer bad.token');
        expect(res.status).toBe(403);
    });
    test('admin token blocked from super routes', async () => {
        const res = await request(app).get('/api/super/organizations').set('Authorization', `Bearer ${adminToken}`);
        expect(res.status).toBe(403);
    });
    test('super token blocked from flag routes', async () => {
        const res = await request(app).get('/api/flags').set('Authorization', `Bearer ${superToken}`);
        expect(res.status).toBe(403);
    });
    test('expired token returns 403', async () => {
        const expired = jwt.sign({ role: 'admin', organizationId: 'x' }, JWT_SECRET, { expiresIn: '0s' });
        await new Promise(r => setTimeout(r, 50));
        const res = await request(app).get('/api/flags').set('Authorization', `Bearer ${expired}`);
        expect(res.status).toBe(403);
    });
});

// ── Feature flags ─────────────────────────────────────────────────────────────
describe('Feature Flags', () => {
    let app, adminToken, org;
    beforeEach(async () => {
        app = freshApp();
        const superToken = await superLogin(app);
        org = await createOrg(app, superToken, 'FlagOrg');
        await signupAdmin(app, org._id);
        ({ token: adminToken } = await loginAdmin(app));
    });

    test('create flag returns 201', async () => {
        const res = await createFlag(app, adminToken, 'dark_mode', true);
        expect(res.status).toBe(201);
        expect(res.body.featureKey).toBe('dark_mode');
    });
    test('key is normalized to lowercase', async () => {
        const res = await createFlag(app, adminToken, 'DARK_MODE');
        expect(res.body.featureKey).toBe('dark_mode');
    });
    test('duplicate key in same org returns 409', async () => {
        await createFlag(app, adminToken, 'beta');
        const res = await createFlag(app, adminToken, 'beta');
        expect(res.status).toBe(409);
    });
    test('same key in different orgs is allowed', async () => {
        const superToken = await superLogin(app);
        const org2 = await createOrg(app, superToken, 'Org2');
        await signupAdmin(app, org2._id, 'admin2');
        const { token: token2 } = await loginAdmin(app, 'admin2');
        await createFlag(app, adminToken, 'shared');
        const res = await createFlag(app, token2, 'shared');
        expect(res.status).toBe(201);
    });
    test('list flags only shows own org', async () => {
        const superToken = await superLogin(app);
        const org2 = await createOrg(app, superToken, 'Org2b');
        await signupAdmin(app, org2._id, 'admin2b');
        const { token: token2 } = await loginAdmin(app, 'admin2b');
        await createFlag(app, adminToken, 'flag1');
        await createFlag(app, token2, 'flag2');
        const res = await request(app).get('/api/flags').set('Authorization', `Bearer ${adminToken}`);
        expect(res.body.length).toBe(1);
        expect(res.body[0].featureKey).toBe('flag1');
    });
    test('toggle flag enabled', async () => {
        const { body: flag } = await createFlag(app, adminToken, 'toggle_me', false);
        const res = await request(app).put(`/api/flags/${flag._id}`)
            .set('Authorization', `Bearer ${adminToken}`).send({ enabled: true });
        expect(res.status).toBe(200);
    });
    test('toggle without enabled field returns 400', async () => {
        const { body: flag } = await createFlag(app, adminToken, 'noupdate');
        const res = await request(app).put(`/api/flags/${flag._id}`)
            .set('Authorization', `Bearer ${adminToken}`).send({});
        expect(res.status).toBe(400);
    });
    test('delete flag returns 200', async () => {
        const { body: flag } = await createFlag(app, adminToken, 'to_delete');
        const res = await request(app).delete(`/api/flags/${flag._id}`)
            .set('Authorization', `Bearer ${adminToken}`);
        expect(res.status).toBe(200);
    });
    test('admin cannot delete another orgs flag', async () => {
        const superToken = await superLogin(app);
        const org2 = await createOrg(app, superToken, 'Org2c');
        await signupAdmin(app, org2._id, 'admin2c');
        const { token: token2 } = await loginAdmin(app, 'admin2c');
        const { body: flag } = await createFlag(app, token2, 'protected');
        const res = await request(app).delete(`/api/flags/${flag._id}`)
            .set('Authorization', `Bearer ${adminToken}`);
        expect(res.status).toBe(404);
    });
});

// ── End user check-flag ───────────────────────────────────────────────────────
describe('End User — Check Flag', () => {
    let app, adminToken, orgId;
    beforeEach(async () => {
        app = freshApp();
        const superToken = await superLogin(app);
        const org = await createOrg(app, superToken, 'UserOrg');
        orgId = org._id;
        await signupAdmin(app, orgId, 'useradmin');
        ({ token: adminToken } = await loginAdmin(app, 'useradmin'));
    });

    test('enabled flag returns { enabled: true }', async () => {
        await createFlag(app, adminToken, 'feature_x', true);
        const res = await request(app).get(`/api/check-flag?organizationId=${orgId}&featureKey=feature_x`);
        expect(res.status).toBe(200);
        expect(res.body.enabled).toBe(true);
    });
    test('disabled flag returns { enabled: false }', async () => {
        await createFlag(app, adminToken, 'feature_y', false);
        const res = await request(app).get(`/api/check-flag?organizationId=${orgId}&featureKey=feature_y`);
        expect(res.body.enabled).toBe(false);
    });
    test('nonexistent key returns { enabled: false }', async () => {
        const res = await request(app).get(`/api/check-flag?organizationId=${orgId}&featureKey=ghost`);
        expect(res.body.enabled).toBe(false);
    });
    test('fake org ID returns 404', async () => {
        const res = await request(app).get('/api/check-flag?organizationId=fake&featureKey=anything');
        expect(res.status).toBe(404);
    });
    test('missing params returns 400', async () => {
        const res = await request(app).get('/api/check-flag');
        expect(res.status).toBe(400);
    });
    test('check is case-insensitive', async () => {
        await createFlag(app, adminToken, 'beta_ui', true);
        const res = await request(app).get(`/api/check-flag?organizationId=${orgId}&featureKey=BETA_UI`);
        expect(res.body.enabled).toBe(true);
    });
    test('two orgs with same key are independent', async () => {
        const superToken = await superLogin(app);
        const org2 = await createOrg(app, superToken, 'Org2d');
        await signupAdmin(app, org2._id, 'admin2d');
        const { token: token2, organizationId: orgId2 } = await loginAdmin(app, 'admin2d');
        await createFlag(app, adminToken, 'feature_z', true);
        await createFlag(app, token2, 'feature_z', false);
        const r1 = await request(app).get(`/api/check-flag?organizationId=${orgId}&featureKey=feature_z`);
        const r2 = await request(app).get(`/api/check-flag?organizationId=${orgId2}&featureKey=feature_z`);
        expect(r1.body.enabled).toBe(true);
        expect(r2.body.enabled).toBe(false);
    });
});
