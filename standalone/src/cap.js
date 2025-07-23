import { Elysia } from "elysia";
import Cap from "@cap.js/server";
import { cors } from "@elysiajs/cors";
import { rateLimit } from "elysia-rate-limit";
import { db } from "./db.js";
import { join } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { ratelimitGenerator } from "./ratelimit.js";
import { trackRequest, getMetrics } from "./performance.js";

const getSitekeyConfigQuery = db.query(`SELECT (config) FROM keys WHERE siteKey = ?`);
const getSitekeyWithSecretQuery = db.query(`SELECT * FROM keys WHERE siteKey = ?`);

const insertChallengeQuery = db.query(`
  INSERT INTO challenges (siteKey, token, data, expires)
  VALUES (?, ?, ?, ?)
`);
const getChallengeQuery = db.query(`
  SELECT * FROM challenges WHERE siteKey = ? AND token = ?
`);
const deleteChallengeQuery = db.query(`
  DELETE FROM challenges WHERE siteKey = ? AND token = ?
`);

const insertTokenQuery = db.query(`
  INSERT INTO tokens (siteKey, token, expires)
  VALUES (?, ?, ?)
`);
const getTokenQuery = db.query(`
  SELECT * FROM tokens WHERE siteKey = ? AND token = ?
`);
const deleteTokenQuery = db.query(`
  DELETE FROM tokens WHERE siteKey = ? AND token = ?
`);

const upsertSolutionQuery = db.query(`
  INSERT INTO solutions (siteKey, bucket, count)
  VALUES (?, ?, 1)
  ON CONFLICT (siteKey, bucket)
  DO UPDATE SET count = count + 1
`);

let cacheAuth = {};
let dataDir = "./.data";

// Performance optimizations for 200 QPS
const CONFIG_CACHE = new Map();
const CONFIG_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const CONFIG_CACHE_MAX_SIZE = 1000;

// Cap instance pool for better performance
const CAP_INSTANCE_POOL = [];
const CAP_POOL_SIZE = 20;

// Initialize Cap instance pool
const initCapPool = () => {
  for (let i = 0; i < CAP_POOL_SIZE; i++) {
    CAP_INSTANCE_POOL.push(new Cap({ noFSState: true }));
  }
};

// Get Cap instance from pool
const getCapInstance = () => {
  if (CAP_INSTANCE_POOL.length > 0) {
    return CAP_INSTANCE_POOL.pop();
  }
  return new Cap({ noFSState: true });
};

// Return Cap instance to pool
const returnCapInstance = (cap) => {
  if (CAP_INSTANCE_POOL.length < CAP_POOL_SIZE) {
    CAP_INSTANCE_POOL.push(cap);
  }
};

// Cache for site key configs with TTL
const getCachedSiteKeyConfig = (siteKey) => {
  const cached = CONFIG_CACHE.get(siteKey);
  if (cached && Date.now() - cached.timestamp < CONFIG_CACHE_TTL) {
    return cached.data;
  }

  const _keyConfig = getSitekeyConfigQuery.get(siteKey);
  if (_keyConfig) {
    // Implement LRU eviction
    if (CONFIG_CACHE.size >= CONFIG_CACHE_MAX_SIZE) {
      const firstKey = CONFIG_CACHE.keys().next().value;
      CONFIG_CACHE.delete(firstKey);
    }

    const config = JSON.parse(_keyConfig.config);
    CONFIG_CACHE.set(siteKey, {
      data: { _keyConfig, config },
      timestamp: Date.now(),
    });
    return { _keyConfig, config };
  }

  return null;
};

const initBasicAuth = async () => {
  try {
    const authFilePath = join(dataDir, "basic-auth.json");

    const base64 = process.env.BASIC_AUTH?.trim();
    if (!base64) {
      console.warn("BASIC_AUTH environment variable is not set, basic auth will not be initialized.");
      return;
    }
    const decoded = Buffer.from(base64, "base64").toString("utf-8");
    const [username, password] = decoded.split(":");
    if (!username || !password) {
      console.warn("BASIC_AUTH environment variable is not properly formatted, basic auth will not be initialized.");
      return;
    }
    cacheAuth["username"] = username;
    cacheAuth["password"] = password;

    writeFileSync(authFilePath, JSON.stringify({ username, password }));
  } catch (error) {
    console.error("Error initializing basic auth:", error);
  }
};

const isVerifyBasicAuthEnabled = () => {
  return Boolean(process.env.BASIC_AUTH?.trim());
};

const verifyBasicAuth = async (headers, set) => {
  const authFilePath = join(dataDir, "basic-auth.json");

  if (!cacheAuth["username"] || !cacheAuth["password"]) {
    cacheAuth = JSON.parse(await readFileSync(authFilePath, "utf-8"));
  }

  try {
    const authHeader = headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Basic ")) {
      set.status = 401;
      set.headers["WWW-Authenticate"] = 'Basic realm="CAP.js Admin"';
      return false;
    }
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
    const [username, password] = credentials.split(":");
    if (username !== cacheAuth["username"] || password !== cacheAuth["password"]) {
      set.status = 401;
      set.headers["WWW-Authenticate"] = 'Basic realm="CAP.js Admin"';
      return false;
    }

    return true;
  } catch (error) {
    console.error("Error verifying basic auth:", error);
    set.status = 500;
    return false;
  }
};

export const capServer = new Elysia({
  detail: {
    tags: ["Challenges"],
  },
})
  .onRequest(({ request }) => {
    // Track request start time
    request.startTime = Date.now();
  })
  .onAfterResponse(({ request, set }) => {
    // Track request completion
    if (request.startTime) {
      const responseTime = Date.now() - request.startTime;
      const isError = set.status >= 400;
      trackRequest(responseTime, isError);
    }
  })
  .use(
    rateLimit({
      scoping: "scoped",
      max: 200, // Allow 200 requests per duration window
      duration: 5_000, // 5 second window
      generator: ratelimitGenerator,
      skip: (req) => {
        // Skip rate limiting for health checks
        return req.url.includes("/health") || req.url.includes("/metrics");
      },
    })
  )
  .use(
    cors({
      origin: process.env.CORS_ORIGIN || true,
      methods: ["POST", "GET"],
      credentials: true,
      maxAge: 86400, // Cache preflight requests for 24 hours
    })
  )
  .post("/:siteKey/challenge", async ({ set, params }) => {
    // Use cached config lookup
    const cachedConfig = getCachedSiteKeyConfig(params.siteKey);

    if (!cachedConfig) {
      set.status = 404;
      return { error: "Invalid site key or secret" };
    }

    const { _keyConfig, config: keyConfig } = cachedConfig;

    // Get Cap instance from pool
    const cap = getCapInstance();

    try {
      const challenge = cap.createChallenge({
        challengeCount: keyConfig.challengeCount,
        challengeSize: keyConfig.saltSize,
        challengeDifficulty: keyConfig.difficulty,
      });

      // Use prepared statement for better performance
      insertChallengeQuery.run(
        params.siteKey,
        challenge.token,
        Object.values(challenge.challenge).join(","),
        challenge.expires
      );

      return challenge;
    } finally {
      // Return Cap instance to pool
      returnCapInstance(cap);
    }
  })
  .post("/:siteKey/redeem", async ({ body, set, params }) => {
    const challenge = getChallengeQuery.get(params.siteKey, body.token);

    if (!challenge) {
      set.status = 404;
      return { error: "Challenge not found" };
    }

    // Delete challenge first to prevent race conditions
    try {
      deleteChallengeQuery.run(params.siteKey, body.token);
    } catch {
      set.status = 404;
      return { error: "Challenge not found" };
    }

    // Get Cap instance from pool
    const cap = getCapInstance();

    try {
      // Parse challenge data once
      const challengeData = challenge.data.split(",");

      // Set up Cap state
      cap.state = {
        challengesList: {
          [challenge.token]: {
            challenge: {
              c: challengeData[0],
              s: challengeData[1],
              d: challengeData[2],
            },
            expires: challenge.expires,
          },
        },
      };

      const { success, token, expires } = await cap.redeemChallenge(body);

      if (!success) {
        set.status = 403;
        return { error: "Invalid solution" };
      }

      // Use batch operations for better performance
      const now = Math.floor(Date.now() / 1000);
      const hourlyBucket = Math.floor(now / 3600) * 3600;

      // Run token insert and solution upsert in parallel
      await Promise.all([
        new Promise((resolve) => {
          insertTokenQuery.run(params.siteKey, token, expires);
          resolve();
        }),
        new Promise((resolve) => {
          upsertSolutionQuery.run(params.siteKey, hourlyBucket);
          resolve();
        }),
      ]);

      return {
        success: true,
        token,
        expires,
      };
    } finally {
      // Return Cap instance to pool
      returnCapInstance(cap);
    }
  })
  .post("/:siteKey/siteverify", async ({ body, set, params, headers }) => {
    const sitekey = params.siteKey;
    const { secret, response } = body;

    // Early validation for better performance
    if (!sitekey || !secret || !response) {
      set.status = 400;
      return { error: "Missing required parameters" };
    }

    if (isVerifyBasicAuthEnabled()) {
      const verify = await verifyBasicAuth(headers, set);

      if (!verify) {
        set.status = 401;
        return { success: false, message: "Unauthorized", error: "Invalid basic auth credentials" };
      }
    }

    const keyData = getSitekeyWithSecretQuery.get(sitekey);
    if (!keyData?.secretHash) {
      set.status = 404;
      return { error: "Invalid site key or secret" };
    }

    // Verify password hash
    if (!(await Bun.password.verify(secret, keyData.secretHash))) {
      set.status = 403;
      return { error: "Invalid site key or secret" };
    }

    const token = getTokenQuery.get(params.siteKey, response);

    if (!token) {
      set.status = 404;
      return { error: "Token not found" };
    }

    const now = Date.now();
    if (token.expires < now) {
      deleteTokenQuery.run(params.siteKey, response);
      set.status = 403;
      return { error: "Token expired" };
    }

    deleteTokenQuery.run(params.siteKey, response);
    return { success: true };
  })
  .get("/health", async ({ headers, set }) => {
    if (isVerifyBasicAuthEnabled()) {
      const verify = await verifyBasicAuth(headers, set);

      if (!verify) {
        set.status = 401;
        return { success: false, message: "Unauthorized", error: "Invalid basic auth credentials" };
      }
    }
    // Health check endpoint for load balancers
    return { status: "healthy", timestamp: Date.now() };
  })
  .get("/metrics", async ({ headers, set }) => {
    if (isVerifyBasicAuthEnabled()) {
      const verify = await verifyBasicAuth(headers, set);

      if (!verify) {
        set.status = 401;
        return { success: false, message: "Unauthorized", error: "Invalid basic auth credentials" };
      }
    }
    // Performance metrics endpoint
    return getMetrics();
  });

await initBasicAuth();
// Initialize Cap instance pool for better performance
initCapPool();

// Warm up config cache with most frequently used keys on startup
