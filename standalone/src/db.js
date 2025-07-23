import fs from "fs";
import { Database } from "bun:sqlite";

fs.mkdirSync("./.data", {
  recursive: true,
});

const db = new Database("./.data/db.sqlite");

// Performance optimizations for 200 QPS
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA synchronous = NORMAL");
db.exec("PRAGMA cache_size = 10000");
db.exec("PRAGMA temp_store = MEMORY");
db.exec("PRAGMA mmap_size = 268435456"); // 256MB

db.query(
  `create table if not exists sessions (
    token string primary key not null,
    expires integer not null,
    created integer not null
  )`
).run();

db.query(
  `create table if not exists keys (
    siteKey string primary key not null,
    name string not null,
    secretHash string not null,
    config string not null,
    created integer not null
  )`
).run();

db.query(
  `create table if not exists solutions (
    siteKey text not null,
    bucket integer not null,
    count integer default 0,
    primary key (siteKey, bucket)
  )`
).run();

db.query(
  `create table if not exists challenges (
    siteKey string not null,
    token string not null,
    data string not null,
    expires integer not null,
    primary key (siteKey, token)
  )`
).run();

db.query(
  `create table if not exists tokens (
    siteKey string not null,
    token string not null,
    expires integer not null,
    primary key (siteKey, token)
  )`
).run();

db.query(
  `create table if not exists api_keys (
    id string not null,
    name string not null,
    tokenHash string not null,
    created integer not null,
    primary key (id, tokenHash)
  )`
).run();

// Create performance indexes
db.exec(`CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_solutions_sitekey_bucket ON solutions(siteKey, bucket)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_challenges_sitekey ON challenges(siteKey)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_tokens_sitekey ON tokens(siteKey)`);

// Optimized cleanup with batch operations and less frequent runs
const cleanupExpiredData = () => {
  const now = Date.now();
  try {
    db.transaction(() => {
      const deletedSessions = db.query("DELETE FROM sessions WHERE expires < ?").run(now);
      const deletedTokens = db.query("DELETE FROM tokens WHERE expires < ?").run(now);
      const deletedChallenges = db.query("DELETE FROM challenges WHERE expires < ?").run(now);

      if (deletedSessions.changes > 0 || deletedTokens.changes > 0 || deletedChallenges.changes > 0) {
        console.log(
          `Cleaned up: ${deletedSessions.changes} sessions, ${deletedTokens.changes} tokens, ${deletedChallenges.changes} challenges`
        );
      }
    })();
  } catch (error) {
    console.error("Cleanup error:", error);
  }
};

// Run cleanup every 5 minutes instead of every minute for better performance
setInterval(cleanupExpiredData, 5 * 60 * 1000);

// Initial cleanup
cleanupExpiredData();

export { db };
