import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import dotenv from "dotenv";

dotenv.config();
// Note: globalThis.crypto is available natively in Node.js 20+

// JWT-only mode with in-memory OAuth state storage
// IMPORTANT: In-memory storage works for development or single-instance deployments
// Data is lost on server restart. For production, consider using a database.

export const auth = betterAuth({
  // Built-in memory adapter - no external database required
  // Stores OAuth state, sessions, and user data in memory (JWT-based)
  database: memoryAdapter(),

  // Secret for signing JWTs and cookies (must be at least 32 characters)
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

  // Session configuration - uses memory adapter for storage
  session: {
    expiresIn: 60 * 60 * 24, // 24 hours
    updateAge: 60 * 60 * 4, // Update session every 4 hours
    cookieCache: {
      enabled: true,
      maxAge: 60 * 60 * 24 // 24 hours - cache session in cookies
    }
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

  // Advanced options - proper cookie security for OAuth
  advanced: {
    useSecureCookies: process.env.NODE_ENV === "production",
    // IMPORTANT: sameSite must be "lax" for OAuth redirects to work
    // "none" would require all cookies to be secure (HTTPS only)
    cookieSameSite: "lax",
    crossSubDomainCookies: {
      enabled: false,
    },
  },
});
