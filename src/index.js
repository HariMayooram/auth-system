import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { toNodeHandler } from "better-auth/node";
import { auth } from "./auth.js";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;
const HOST = process.env.HOST || "0.0.0.0";

// Parse allowed origins from environment
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(origin => origin.trim())
  : ["http://localhost:8887", "http://localhost:8888"];

// HTTPS enforcement in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
      return res.redirect('https://' + req.get('host') + req.url);
    }
  }
  next();
});

// Security headers
app.use((req, res, next) => {
  // HSTS header in production
  if (process.env.NODE_ENV === 'production') {
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // Security headers for all environments
  res.set('X-Frame-Options', 'DENY');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Content Security Policy
  res.set('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self'; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none';"
  );

  next();
});

// CORS configuration - allow credentials for cookie-based auth
app.use(
  cors({
    origin: (origin, callback) => {
      // In production, reject requests without origin header
      if (!origin) {
        return process.env.NODE_ENV === 'production'
          ? callback(new Error('Origin required'))
          : callback(null, true); // Allow in development for testing
      }

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`Blocked CORS request from: ${origin}`);
        callback(new Error(`Not allowed by CORS: ${origin}`));
      }
    },
    credentials: true, // Allow cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Removed OPTIONS, handled automatically
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400, // Cache preflight for 24 hours
  })
);

// Rate limiting for authentication endpoints
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many authentication attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting in development mode
  skip: (req) => process.env.NODE_ENV === 'development',
});

// Stricter rate limit for OAuth callback endpoints to prevent abuse
const oauthCallbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 OAuth attempts per 15 minutes
  message: 'Too many authentication attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development',
});

// Apply rate limiting to all auth endpoints
app.use('/api/auth/', authRateLimiter);

// Apply stricter rate limiting to OAuth callback endpoints
app.use('/api/auth/callback/', oauthCallbackLimiter);

// Health check endpoint (before Better Auth handler)
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "better-auth",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Mount Better Auth routes at /api/auth (MUST come before express.json())
app.all("/api/auth/*", toNodeHandler(auth));

// Parse JSON bodies (MUST come after Better Auth handler)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Get auth status (for debugging)
app.get("/api/auth-status", async (req, res) => {
  try {
    const session = await auth.api.getSession({
      headers: req.headers,
    });

    if (session) {
      res.json({
        authenticated: true,
        user: session.user,
      });
    } else {
      res.json({
        authenticated: false,
      });
    }
  } catch (error) {
    console.error("Error checking auth status:", error);
    res.status(500).json({
      error: "Failed to check authentication status",
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  // Log full error server-side only (never send to client)
  console.error("[ERROR]", {
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString(),
    path: req.path,
  });

  // Determine if we should show detailed errors
  const isDevelopment = process.env.NODE_ENV === 'development';

  // Generic error message for production
  const errorMessage = isDevelopment
    ? err.message || "Internal server error"
    : "Internal server error";

  // Send safe error response
  res.status(err.status || 500).json({
    error: errorMessage,
    ...(isDevelopment && { stack: err.stack }) // Only in development
  });
});

// Start the server
app.listen(PORT, HOST, () => {
  console.log(`\n Better Auth Service running on http://${HOST}:${PORT}`);
  console.log(`Auth endpoints: http://${HOST}:${PORT}/api/auth/*`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`\n Allowed Origins:`);
  allowedOrigins.forEach(origin => {
    console.log(`   ✓ ${origin}`);
  });

  console.log(`\n🔐 OAuth Providers Configured:`);
  const providers = [];
  if (process.env.GOOGLE_CLIENT_ID) providers.push("Google");
  if (process.env.GITHUB_CLIENT_ID) providers.push("GitHub");
  if (process.env.MICROSOFT_CLIENT_ID) providers.push("Microsoft");
  if (process.env.FACEBOOK_CLIENT_ID) providers.push("Facebook");
  if (process.env.LINKEDIN_CLIENT_ID) providers.push("LinkedIn");

  if (providers.length > 0) {
    providers.forEach(p => console.log(`   ✓ ${p}`));
  } else {
    console.log(`   ⚠ None (configure in .env file)`);
  }

  console.log(`\n💡 Stateless JWT authentication with database-backed sessions\n`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("SIGINT signal received: closing HTTP server");
  process.exit(0);
});
