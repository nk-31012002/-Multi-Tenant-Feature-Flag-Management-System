# 🚩 Multi-Tenant Feature Flag Management System

A SaaS-style feature flag platform where organizations can manage feature toggles independently.

## Roles

| Role | Access |
|---|---|
| **Super Admin** | Create & manage organizations |
| **Org Admin** | Create & toggle feature flags for their org |
| **End User** | Check if a feature is enabled for their org |

## Tech Stack

- **Backend** — Node.js + Express
- **Database** — NeDB (file-based, no setup needed)
- **Auth** — Custom JWT + bcrypt
- **Frontend** — Vanilla HTML/JS
- **Testing** — Jest + Supertest

## Setup

```bash
npm install
npm start
```

App runs at `http://localhost:3000`

> Set `JWT_SECRET` as an environment variable before running in production.

## Default Super Admin

```
username: superadmin
password: admin123
```

## Running Tests

```bash
npm test
```