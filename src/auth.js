import { betterAuth } from "better-auth";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

// In-memory OAuth state store (stateless, no database)
// Automatically cleans up expired states
const oauthStateStore = new Map();

// Cleanup expired states every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of oauthStateStore.entries()) {
    // Remove states older than 10 minutes
    if (now - data.timestamp > 600000) {
      oauthStateStore.delete(state);
      console.log(`[State Store] Cleaned up expired state: ${state}`);
    }
  }
}, 300000);

console.log('[State Store] In-memory OAuth state storage initialized');

export const auth = betterAuth({
  // No database configuration - this automatically enables stateless mode
  secret: (() => {
    if (!process.env.BETTER_AUTH_SECRET) {
      throw new Error("BETTER_AUTH_SECRET environment variable is required and must be at least 32 characters");
    }
    if (process.env.BETTER_AUTH_SECRET.length < 32) {
      throw new Error("BETTER_AUTH_SECRET must be at least 32 characters long");
    }
    return process.env.BETTER_AUTH_SECRET;
  })(),
  baseURL: (() => {
    const baseURL = process.env.NODE_ENV !== 'production'
      ? (process.env.BASE_URL || "http://localhost:3002")
      : process.env.BASE_URL;

    // console.log('[Better Auth Config] NODE_ENV:', process.env.NODE_ENV);
    // console.log('[Better Auth Config] BASE_URL from env:', process.env.BASE_URL);
    // console.log('[Better Auth Config] Final baseURL:', baseURL);

    if (process.env.NODE_ENV === 'production' && !process.env.BASE_URL) {
      throw new Error("BASE_URL environment variable is required in production");
    }

    return baseURL;
  })(),
  trustedOrigins: (() => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS;
    if (!allowedOrigins) {
      if (process.env.NODE_ENV !== 'production') {
        return ["http://localhost:8887", "http://localhost:8888"];
      }
      throw new Error("ALLOWED_ORIGINS environment variable is required in production");
    }
    return allowedOrigins.split(',').map(origin => origin.trim());
  })(),
  session: {
    cookieCache: {
      enabled: true,
      maxAge: 7 * 24 * 60 * 60, // 7 days cache duration
      strategy: "jwe", // "jwe" is recommended for encrypted cookies
    },
  },
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      enabled: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    },
    linkedin: {
      clientId: process.env.LINKEDIN_CLIENT_ID || "",
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET || "",
      enabled: !!(process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET),
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
    discord: {
      clientId: process.env.DISCORD_CLIENT_ID || "",
      clientSecret: process.env.DISCORD_CLIENT_SECRET || "",
      enabled: !!(process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET),
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID || "",
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET || "",
      enabled: !!(process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET),
    },
  },
  advanced: {
    cookies: {
      // Specific configuration for OAuth state cookie
      state: {
        attributes: {
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          secure: process.env.NODE_ENV === "production",
          httpOnly: true,
          path: "/",
        },
      },
    },
    useSecureCookies: process.env.NODE_ENV === "production",
    crossSubDomainCookies: {
      enabled: false,
    },
    defaultCookieAttributes: {
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      path: "/",
    },
  },
  hooks: {
    before: [
      {
        matcher: (context) => {
          // Intercept OAuth sign-in requests
          return context.path === "/sign-in/social";
        },
        handler: async (request) => {
          // Generate and store state in memory
          const state = crypto.randomBytes(32).toString('base64url');
          const body = await request.json();

          oauthStateStore.set(state, {
            timestamp: Date.now(),
            callbackURL: body.callbackURL,
            provider: body.provider
          });

          console.log(`[State Store] Stored state for ${body.provider}: ${state}`);

          // Pass the state through
          return {
            request: new Request(request.url, {
              ...request,
              body: JSON.stringify({ ...body, state })
            })
          };
        }
      },
      {
        matcher: (context) => {
          // Intercept OAuth callback
          return context.path.startsWith("/callback/");
        },
        handler: async (request) => {
          const url = new URL(request.url);
          const state = url.searchParams.get('state');

          if (state && oauthStateStore.has(state)) {
            console.log(`[State Store] Valid state found: ${state}`);
            const data = oauthStateStore.get(state);
            oauthStateStore.delete(state); // One-time use

            // State is valid, allow the request to proceed
            return { request };
          } else {
            console.error(`[State Store] Invalid or missing state: ${state}`);
            // Let Better Auth handle the error
            return { request };
          }
        }
      }
    ]
  },
});
