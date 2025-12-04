import { betterAuth } from "better-auth";
// import { Pool } from "pg";
import dotenv from "dotenv";

dotenv.config();
// Note: globalThis.crypto is available natively in Node.js 20+

// Create PostgreSQL connection pool (optional)
// Commented out to run in stateless mode without database
// const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
// });

export const auth = betterAuth({
  // Database configuration - disabled for stateless mode
  // database: pool,

  // Secret for signing JWTs (must be at least 32 characters)
  secret: (() => {
    if (!process.env.BETTER_AUTH_SECRET) {
      throw new Error("BETTER_AUTH_SECRET environment variable is required and must be at least 32 characters");
    }
    if (process.env.BETTER_AUTH_SECRET.length < 32) {
      throw new Error("BETTER_AUTH_SECRET must be at least 32 characters long");
    }
    return process.env.BETTER_AUTH_SECRET;
  })(),

  // Base URL where this auth service runs
  baseURL: process.env.BASE_URL || "http://localhost:3002",

  // Trusted origins (frontends that can use this auth service)
  trustedOrigins: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
    : ["http://localhost:8887", "http://localhost:8888"],

  // Session configuration
  session: {
    // Use cookies for session storage
    cookieCache: {
      enabled: true,
      maxAge: 5 * 60 // 5 minutes
    },
    expiresIn: 60 * 60 * 24, // 24 hours (reduced from 7 days for security)
    updateAge: 60 * 60 * 4 // Update session every 4 hours
  },

  // Email and password authentication - Disabled (OAuth-only)
  emailAndPassword: {
    enabled: false, // Disabled - using OAuth providers only
  },

  // Social OAuth providers
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      enabled: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID || "",
      clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
      enabled: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
    },
    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID || "",
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET || "",
      enabled: !!(process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET),
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID || "",
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET || "",
      enabled: !!(process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET),
    },
  },

  // User configuration
  user: {
    additionalFields: {
      // Add custom fields to user model if needed
      // avatarUrl: {
      //   type: "string",
      //   required: false,
      // },
    },
  },

  // Advanced options
  advanced: {
    // Generate shorter session tokens
    useSecureCookies: process.env.NODE_ENV === "production",
    cookieSameSite: "lax",
    crossSubDomainCookies: {
      enabled: false,
    },
  },
});
