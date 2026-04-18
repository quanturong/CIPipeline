"use strict";

const fs = require("fs");
const path = require("path");

// ─── Sensitive keyword list (dùng chung cho IOC-1 và IOC-2) ───────────────
const SENSITIVE_ENV_KEYWORDS = [
  "TOKEN",
  "SECRET",
  "KEY",
  "PASSWORD",
  "PASS",
  "CREDENTIAL",
  "AUTH",
  "PRIVATE_KEY",
  "ACCESS_KEY",
  "API_KEY",
  "NPM_TOKEN",
  "CI_JOB_TOKEN",
  "GITHUB_TOKEN",
  "AWS_SECRET",
  "DEPLOY_KEY",
];

const KNOWN_SAFE_HOSTS = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "nodejs.org",
  "github.com",
  "objects.githubusercontent.com",
];

// Paths — __dirname = detector/lib, so go up one level to detector/
const ALERT_LOG           = path.join(__dirname, "..", "detector-alerts.log");
const ARTIFACT_HASHES_FILE = path.join(__dirname, "..", "artifact-hashes.json");

// Files to exclude from artifact integrity checks (not build outputs)
const ARTIFACT_IGNORE = [
  "av-bypass-report.txt",
  "detector-alerts.log",
  ".gitkeep",
];

// ─── Alert counter (mutable singleton) ────────────────────────────────────
let _alertCount = 0;

function getAlertCount() {
  return _alertCount;
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function timestamp() {
  return new Date().toISOString();
}

function log(level, message) {
  const line = `[${timestamp()}] [${level}] ${message}`;
  if (level === "ALERT") {
    _alertCount++;
    console.log(`\x1b[31m${line}\x1b[0m`); // red
  } else if (level === "WARN") {
    console.log(`\x1b[33m${line}\x1b[0m`); // yellow
  } else {
    console.log(line);
  }
  fs.appendFileSync(ALERT_LOG, line + "\n", "utf8");
}

module.exports = {
  SENSITIVE_ENV_KEYWORDS,
  KNOWN_SAFE_HOSTS,
  ALERT_LOG,
  ARTIFACT_HASHES_FILE,
  ARTIFACT_IGNORE,
  timestamp,
  log,
  getAlertCount,
};
