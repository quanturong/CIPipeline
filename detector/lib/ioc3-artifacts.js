"use strict";

/**
 * IOC-3: Build artifact integrity check (SHA-256 hash comparison).
 *
 * baseline — lưu hash của artifacts TRƯỚC khi chạy CI steps.
 * verify   — so sánh hash hiện tại với baseline, alert nếu mismatch.
 */

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");
const { log, timestamp, ARTIFACT_HASHES_FILE, ARTIFACT_IGNORE } = require("./utils");

// ─── Helpers ───────────────────────────────────────────────────────────────

function sha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

// ─── Exports ───────────────────────────────────────────────────────────────

/**
 * Baseline: lưu hash của tất cả artifacts TRƯỚC khi chạy CI steps.
 */
function baselineArtifactHashes(artifactDir) {
  log("INFO", `[IOC-3] Creating artifact baseline hashes for: ${artifactDir}`);

  if (!fs.existsSync(artifactDir)) {
    log("WARN", `[IOC-3] Artifact directory not found: ${artifactDir}`);
    return;
  }

  const hashes = {};
  const files = fs.readdirSync(artifactDir).filter((f) => {
    return fs.statSync(path.join(artifactDir, f)).isFile() && !ARTIFACT_IGNORE.includes(f);
  });

  for (const file of files) {
    const fullPath = path.join(artifactDir, file);
    hashes[file] = {
      hash:      sha256(fullPath),
      size:      fs.statSync(fullPath).size,
      timestamp: timestamp(),
    };
    log("INFO", `[IOC-3] Baseline: ${file} → ${hashes[file].hash.substring(0, 16)}...`);
  }

  fs.writeFileSync(ARTIFACT_HASHES_FILE, JSON.stringify(hashes, null, 2), "utf8");
  log("INFO", `[IOC-3] Baseline saved to: ${ARTIFACT_HASHES_FILE}`);
  return hashes;
}

/**
 * Verify: so sánh hash hiện tại với baseline.
 * Alert nếu hash thay đổi (artifact bị tamper).
 */
function verifyArtifactHashes(artifactDir) {
  log("INFO", `[IOC-3] Verifying artifact integrity for: ${artifactDir}`);

  if (!fs.existsSync(ARTIFACT_HASHES_FILE)) {
    log("WARN", "[IOC-3] No baseline found. Run with --baseline first.");
    return [];
  }

  const baseline = JSON.parse(fs.readFileSync(ARTIFACT_HASHES_FILE, "utf8"));
  const alerts   = [];

  for (const [file, info] of Object.entries(baseline)) {
    const fullPath = path.join(artifactDir, file);

    if (!fs.existsSync(fullPath)) {
      log("ALERT", `[IOC-3] MISSING: Artifact "${file}" was deleted!`);
      alerts.push({ file, issue: "deleted" });
      continue;
    }

    const currentHash = sha256(fullPath);
    const currentSize = fs.statSync(fullPath).size;

    if (currentHash !== info.hash) {
      log(
        "ALERT",
        `[IOC-3] TAMPERED: "${file}" hash changed!\n` +
        `         Baseline: ${info.hash.substring(0, 16)}... (${info.size} bytes)\n` +
        `         Current:  ${currentHash.substring(0, 16)}... (${currentSize} bytes)`
      );
      alerts.push({
        file,
        issue:         "hash_mismatch",
        baseline_hash: info.hash,
        current_hash:  currentHash,
        size_diff:     currentSize - info.size,
      });
    } else {
      log("INFO", `[IOC-3] OK: "${file}" integrity verified.`);
    }
  }

  // Kiểm tra file mới bất thường
  const currentFiles = fs.readdirSync(artifactDir).filter(
    (f) => fs.statSync(path.join(artifactDir, f)).isFile() && !ARTIFACT_IGNORE.includes(f)
  );
  for (const file of currentFiles) {
    if (!baseline[file]) {
      log("WARN", `[IOC-3] NEW FILE: "${file}" appeared after baseline (investigate!)`);
      alerts.push({ file, issue: "new_file" });
    }
  }

  if (alerts.length === 0) {
    log("INFO", "[IOC-3] All artifacts pass integrity check.");
  }

  return alerts;
}

module.exports = { baselineArtifactHashes, verifyArtifactHashes };
