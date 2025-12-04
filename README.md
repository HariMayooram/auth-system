# Better Auth Service

Shared authentication service using [Better Auth](https://better-auth.com) for WebRoot sites.

## Features

- **JWT-based authentication** stored in secure HTTP-only cookies
- **Multiple OAuth providers**: Google, GitHub, Microsoft, Facebook, LinkedIn
- **Email/Password authentication** with future OTP support
- **Database-backed sessions** using PostgreSQL
- **CORS-enabled** for multiple frontend origins
- **Shared service** - can be used across multiple webroot instances

## Quick Start

### 1. Install Dependencies

```bash
cd auth-system
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env` with your:
- Database connection (can use team/.env DATABASE_URL)
- OAuth client IDs and secrets
- BETTER_AUTH_SECRET (generate with `openssl rand -base64 32`)

### 3. Run Database Migrations

```bash
npm run migrate
```

This creates the necessary Better Auth tables in your database.

### 4. Start the Server

```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm run prod
```

Server runs on `http://localhost:3002` by default.

## API Endpoints

Better Auth automatically provides these endpoints:

- `POST /api/auth/sign-up/email` - Email/password signup
- `POST /api/auth/sign-in/email` - Email/password login
- `GET /api/auth/sign-in/social` - OAuth provider login
- `POST /api/auth/sign-out` - Logout
- `GET /api/auth/session` - Get current session
- `POST /api/auth/verify-email` - Verify email (future)

## Using with Multiple Sites

This service is designed to be shared across multiple webroot instances:

1. **Single auth-system service** runs on port 3002
2. **Multiple frontends** (feed, team, etc.) point to it via VITE_AUTH_URL
3. **Add allowed origins** to ALLOWED_ORIGINS in .env

Example:
```bash
ALLOWED_ORIGINS=http://localhost:8887,http://site1.com,http://site2.com
```

## Reading Config from team/.env

To share OAuth credentials from team/.env:

```bash
# In auth-system/.env, reference the team database
DATABASE_URL=postgresql://user:pass@host:5432/membercommons?sslmode=require

# Or use a script to sync values
./sync-from-team-env.sh
```

## Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  feed (React)   │ ◄─────► │  auth-system     │
│  - Auth Client  │  HTTP   │  - Better Auth   │
│  - Sign Up UI   │         │  - /api/auth/*   │
└─────────────────┘         └──────────────────┘
                                      │
┌─────────────────┐                   │
│  team (site)    │ ◄─────────────────┤
│  - Auth Client  │                   │
└─────────────────┘                   ▼
                              ┌──────────────┐
                              │  PostgreSQL  │
                              │  (Commons)   │
                              └──────────────┘
```

## Pivoting to Different Auth Options

This standalone structure makes it easy to:

1. **Keep this service** and switch Better Auth versions
2. **Create auth-custom/** for custom implementation
3. **Create auth-supabase/** for Supabase auth
4. **Run multiple** auth services simultaneously for testing

Just update your frontend's `VITE_AUTH_URL` to point to the desired service.
