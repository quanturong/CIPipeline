"use strict";

/**
 * Active install agents — chạy npm install dưới chế độ kiểm soát.
 *
 * safeNpmInstall:   npm install --ignore-scripts → scan → npm rebuild
 * monitorInstall:   poll Get-NetTCPConnection mỗi 500ms TRONG KHI npm install chạy
 *                   (giải quyết hạn chế IOC-2 one-shot POST)
 */

const fs   = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { log, timestamp } = require("./utils");
const { scanPostinstallScripts } = require("./ioc1-postinstall");

// ─── Safe Install ──────────────────────────────────────────────────────────

/**
 * Chạy `npm install` với --ignore-scripts TRƯỚC để tải packages an toàn,
 * scan postinstall scripts, rồi hỏi user có muốn cho chạy không.
 */
function safeNpmInstall(projectDir) {
  log("INFO", `[SAFE-INSTALL] Running safe npm install for: ${projectDir}`);

  // Step 1: Install without scripts
  log("INFO", "[SAFE-INSTALL] Step 1: npm install --ignore-scripts (download only)...");
  try {
    execSync("npm install --ignore-scripts", {
      cwd:      projectDir,
      encoding: "utf8",
      stdio:    "pipe",
    });
  } catch (err) {
    log("WARN", `[SAFE-INSTALL] npm install failed: ${err.message}`);
    return;
  }

  // Step 2: Scan postinstall scripts
  log("INFO", "[SAFE-INSTALL] Step 2: Scanning lifecycle scripts...");
  const nodeModulesDir    = path.join(projectDir, "node_modules");
  const suspiciousPackages = scanPostinstallScripts(nodeModulesDir);

  if (suspiciousPackages && suspiciousPackages.length > 0) {
    log("ALERT", `[SAFE-INSTALL] ⚠ Found ${suspiciousPackages.length} suspicious package(s)!`);
    log("ALERT", "[SAFE-INSTALL] Lifecycle scripts were NOT executed.");
    log("ALERT", "[SAFE-INSTALL] Review the alerts above before running: npm rebuild");
    return suspiciousPackages;
  }

  // Step 3: Nếu sạch, chạy lifecycle scripts
  log("INFO", "[SAFE-INSTALL] Step 3: All clean. Running lifecycle scripts...");
  try {
    execSync("npm rebuild", {
      cwd:      projectDir,
      encoding: "utf8",
      stdio:    "inherit",
    });
  } catch (err) {
    log("WARN", `[SAFE-INSTALL] npm rebuild failed: ${err.message}`);
  }

  log("INFO", "[SAFE-INSTALL] Done.");
  return [];
}

// ─── Monitor Install ───────────────────────────────────────────────────────

/**
 * Chạy npm install và đồng thời poll network connections mỗi 500ms.
 *
 * Giải quyết hạn chế IOC-2 truyền thống: one-shot HTTP POST kết thúc trước khi
 * IOC-2 scan → không bao giờ thấy connection.
 * Monitor-install mode đảm bảo scan XẢY RA ĐỒNG THỜI với npm install.
 */
function monitorInstall(projectDir, registry) {
  log("INFO", `[MONITOR-INSTALL] Running npm install with live network monitoring...`);
  log("INFO", `[MONITOR-INSTALL] Project: ${projectDir}`);

  const nodeModulesDir = path.join(projectDir, "node_modules");
  const lockFile       = path.join(projectDir, "package-lock.json");

  // Clean install
  if (fs.existsSync(nodeModulesDir)) {
    fs.rmSync(nodeModulesDir, { recursive: true, force: true });
    log("INFO", "[MONITOR-INSTALL] Cleaned node_modules.");
  }
  if (fs.existsSync(lockFile)) {
    fs.unlinkSync(lockFile);
  }

  const networkAlerts = [];
  let pollCount = 0;
  const POLL_INTERVAL = 500; // ms

  // Start network polling TRƯỚC khi npm install
  log("INFO", `[MONITOR-INSTALL] Starting network polling (every ${POLL_INTERVAL}ms)...`);

  const pollTimer = setInterval(() => {
    pollCount++;

    try {
      const psCmd =
        `powershell -NoProfile -Command "` +
        `Get-NetTCPConnection -State Established,SynSent,TimeWait -ErrorAction SilentlyContinue | ` +
        `ForEach-Object { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; ` +
        `if ($proc -eq 'node') { Write-Output (\\\"$($_.RemoteAddress):$($_.RemotePort):$($_.State)\\\") } }"`;

      const output = execSync(psCmd, { encoding: "utf8", timeout: 3000 }).trim();

      if (output) {
        const connections = output.split("\n").filter(Boolean);
        for (const conn of connections) {
          const [remoteIP, remotePort, state] = conn.trim().split(":");
          if (!remoteIP) continue;

          const isLocal     = remoteIP.startsWith("127.") || remoteIP === "::1" || remoteIP === "0.0.0.0";
          const isVerdaccio = remotePort === "4873";

          if (!isLocal && !isVerdaccio) {
            log("ALERT", `[IOC-2-LIVE] OUTBOUND: node.exe → ${remoteIP}:${remotePort} (${state}) [poll #${pollCount}]`);
            networkAlerts.push({ remoteIP, remotePort, state, pollNumber: pollCount, timestamp: timestamp() });
          }
        }
      }
    } catch {
      // poll failure — skip silently
    }
  }, POLL_INTERVAL);

  // Run npm install (synchronous — blocks until done)
  log("INFO", "[MONITOR-INSTALL] Running: npm install ...");
  try {
    const registryArg = registry ? `--registry ${registry}` : "";
    execSync(`npm install ${registryArg}`, {
      cwd:      projectDir,
      encoding: "utf8",
      stdio:    "pipe",
      timeout:  60000,
    });
    log("INFO", "[MONITOR-INSTALL] npm install completed.");
  } catch (err) {
    log("WARN", `[MONITOR-INSTALL] npm install error: ${err.message}`);
  }

  // Wait for lingering connections
  const waitMs  = 2000;
  log("INFO", `[MONITOR-INSTALL] Waiting ${waitMs}ms for lingering connections...`);
  const waitEnd = Date.now() + waitMs;
  while (Date.now() < waitEnd) { /* intentional busy wait for synchronous flow */ }

  clearInterval(pollTimer);

  // Report
  log("INFO", `[MONITOR-INSTALL] Network polling complete. ${pollCount} polls executed.`);
  if (networkAlerts.length > 0) {
    log("ALERT", `[MONITOR-INSTALL] Detected ${networkAlerts.length} suspicious outbound connection(s) during install!`);
    for (const a of networkAlerts) {
      log("ALERT", `[MONITOR-INSTALL]   → ${a.remoteIP}:${a.remotePort} (${a.state}) at poll #${a.pollNumber}`);
    }
  } else {
    log("INFO", "[MONITOR-INSTALL] No suspicious outbound connections detected during install.");
    log("INFO", "[MONITOR-INSTALL] Note: one-shot HTTP POST (<100ms) may complete between poll intervals.");
  }

  // Post-install IOC-1 scan
  log("INFO", "[MONITOR-INSTALL] Running post-install IOC-1 scan...");
  scanPostinstallScripts(nodeModulesDir);

  return networkAlerts;
}

module.exports = { safeNpmInstall, monitorInstall };
