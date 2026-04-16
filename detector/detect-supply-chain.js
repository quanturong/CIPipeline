/**
 * [PoC - NT230] Detector — Phát hiện Supply Chain Attack qua npm postinstall
 *
 * Phần C: Công cụ phát hiện kỹ thuật malware sử dụng
 *
 * IOCs monitored:
 *   IOC-1: npm postinstall script truy cập env vars nhạy cảm (TOKEN, SECRET, KEY...)
 *   IOC-2: node.exe tạo outbound HTTP connection bất thường trong lúc npm install
 *   IOC-3: Build artifacts bị thay đổi sau CI step (hash mismatch)
 *
 * Cách chạy:
 *   node detector/detect-supply-chain.js [--watch] [--scan-artifacts <dir>]
 */

"use strict";

const { exec, execSync, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const os = require("os");

// ─── Config ────────────────────────────────────────────────────────────────
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

const ALERT_LOG = path.join(__dirname, "detector-alerts.log");
const ARTIFACT_HASHES_FILE = path.join(__dirname, "artifact-hashes.json");

// Files to exclude from artifact integrity checks (not build outputs)
const ARTIFACT_IGNORE = [
  "av-bypass-report.txt",
  "detector-alerts.log",
  ".gitkeep",
];
// ───────────────────────────────────────────────────────────────────────────

let alertCount = 0;

function timestamp() {
  return new Date().toISOString();
}

function log(level, message) {
  const line = `[${timestamp()}] [${level}] ${message}`;
  if (level === "ALERT") {
    alertCount++;
    console.log(`\x1b[31m${line}\x1b[0m`); // red
  } else if (level === "WARN") {
    console.log(`\x1b[33m${line}\x1b[0m`); // yellow
  } else {
    console.log(line);
  }
  fs.appendFileSync(ALERT_LOG, line + "\n", "utf8");
}

// ═══════════════════════════════════════════════════════════════════════════
// IOC-1: Kiểm tra postinstall scripts trong package.json
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Quét tất cả package.json trong node_modules để tìm postinstall scripts đáng ngờ.
 * Alert nếu postinstall script:
 *   - Chứa keywords: env, process.env, TOKEN, SECRET, http, net, socket, exec, spawn
 *   - Truy cập file system ngoài package folder
 */
function scanPostinstallScripts(nodeModulesDir) {
  log("INFO", `[IOC-1] Scanning postinstall scripts in: ${nodeModulesDir}`);
  
  if (!fs.existsSync(nodeModulesDir)) {
    log("WARN", `[IOC-1] node_modules not found: ${nodeModulesDir}`);
    return;
  }

  const SUSPICIOUS_PATTERNS = [
    /process\.env/gi,
    /\b(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)\b/gi,
    /require\s*\(\s*['"](?:http|https|net|dgram|child_process)['"]\s*\)/gi,
    /\bexec\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\beval\s*\(/gi,
    /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)/gi,
    /\.connect\s*\(/gi,
    /XMLHttpRequest|fetch\s*\(/gi,
  ];

  const results = [];
  
  function walkPackages(dir, depth = 0) {
    if (depth > 3) return; // không đi quá sâu
    
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;

      const pkgJsonPath = path.join(dir, entry.name, "package.json");
      
      // Handle scoped packages (@scope/name)
      if (entry.name.startsWith("@")) {
        walkPackages(path.join(dir, entry.name), depth + 1);
        continue;
      }

      if (!fs.existsSync(pkgJsonPath)) continue;

      try {
        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
        const scripts = pkgJson.scripts || {};
        
        // Check lifecycle scripts
        const LIFECYCLE_HOOKS = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"];
        
        for (const hook of LIFECYCLE_HOOKS) {
          if (!scripts[hook]) continue;
          
          log("INFO", `[IOC-1] Found ${hook} script in ${pkgJson.name}: "${scripts[hook]}"`);
          
          // Nếu script chạy file JS, đọc và scan nội dung
          const scriptMatch = scripts[hook].match(/node\s+(.+\.js)/);
          if (scriptMatch) {
            const scriptPath = path.join(dir, entry.name, scriptMatch[1]);
            if (fs.existsSync(scriptPath)) {
              const content = fs.readFileSync(scriptPath, "utf8");
              
              for (const pattern of SUSPICIOUS_PATTERNS) {
                const matches = content.match(pattern);
                if (matches) {
                  log(
                    "ALERT",
                    `[IOC-1] SUSPICIOUS: ${pkgJson.name} → ${hook} script contains: ${matches.join(", ")}`
                  );
                  results.push({
                    package: pkgJson.name,
                    hook,
                    script: scripts[hook],
                    file: scriptPath,
                    matches: matches,
                  });
                }
              }
            }
          }
        }
      } catch {
        // skip invalid package.json
      }
    }
  }

  walkPackages(nodeModulesDir);
  
  if (results.length === 0) {
    log("INFO", "[IOC-1] No suspicious postinstall scripts found.");
  } else {
    log("ALERT", `[IOC-1] Found ${results.length} suspicious lifecycle script(s)!`);
  }
  
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════
// IOC-2: Monitor network connections từ node.exe (Windows)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Lấy tất cả TCP connections từ node.exe và kiểm tra xem có kết nối
 * đến host lạ không (không nằm trong KNOWN_SAFE_HOSTS).
 */
function checkNodeNetworkConnections() {
  log("INFO", "[IOC-2] Checking outbound connections from node.exe...");
  
  if (os.platform() !== "win32") {
    log("WARN", "[IOC-2] Network monitoring chỉ hỗ trợ Windows (dùng netstat).");
    return [];
  }

  const alerts = [];
  
  try {
    // Thử netstat -nob trước (cần Admin)
    const output = execSync("netstat -nob 2>nul", { encoding: "utf8", timeout: 10000 });
    const lines = output.split("\n");
    
    let currentProcess = "";
    for (const line of lines) {
      // Dòng process name: [node.exe]
      const procMatch = line.match(/^\s*\[(.+)\]\s*$/);
      if (procMatch) {
        currentProcess = procMatch[1].toLowerCase();
        continue;
      }
      
      // Dòng connection: TCP    192.168.x.x:port    remote:port    ESTABLISHED
      if (currentProcess === "node.exe") {
        const connMatch = line.match(/TCP\s+\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)/);
        if (connMatch) {
          const remoteIP = connMatch[1];
          const remotePort = connMatch[2];
          const state = connMatch[3];
          
          if (state === "ESTABLISHED" && remoteIP !== "127.0.0.1") {
            // Kiểm tra có phải known safe host không
            // (Trong production cần reverse DNS, PoC dùng IP check)
            const isLocal = remoteIP.startsWith("127.") || remoteIP === "::1";
            const isVerdaccio = remoteIP === "127.0.0.1" || remotePort === "4873";
            
            if (!isLocal && !isVerdaccio) {
              log(
                "ALERT",
                `[IOC-2] node.exe has outbound connection to ${remoteIP}:${remotePort} (${state})`
              );
              alerts.push({ process: "node.exe", remote: `${remoteIP}:${remotePort}`, state });
            }
          }
        }
      }
    }
  } catch (err) {
    log("WARN", `[IOC-2] netstat -nob failed (need Admin): ${err.message}`);
    log("INFO", "[IOC-2] Falling back to PowerShell Get-NetTCPConnection (no Admin required)...");
    
    try {
      // Fallback: Get-NetTCPConnection không cần Admin, lọc theo OwningProcess name
      const psCmd = `powershell -NoProfile -Command "` +
        `Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ` +
        `ForEach-Object { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; ` +
        `if ($proc -eq 'node') { Write-Output (\\\"$($_.RemoteAddress):$($_.RemotePort)\\\") } }"`;
      
      const psOutput = execSync(psCmd, { encoding: "utf8", timeout: 15000 });
      const connections = psOutput.trim().split("\n").filter(Boolean);
      
      for (const conn of connections) {
        const [remoteIP, remotePort] = conn.trim().split(":");
        if (!remoteIP) continue;
        
        const isLocal = remoteIP.startsWith("127.") || remoteIP === "::1" || remoteIP === "0.0.0.0";
        const isVerdaccio = remotePort === "4873";
        
        if (!isLocal && !isVerdaccio) {
          log(
            "ALERT",
            `[IOC-2] node.exe has outbound connection to ${remoteIP}:${remotePort} (ESTABLISHED)`
          );
          alerts.push({ process: "node.exe", remote: `${remoteIP}:${remotePort}`, state: "ESTABLISHED" });
        }
      }
      
      if (connections.length > 0) {
        log("INFO", `[IOC-2] Found ${connections.length} node.exe connection(s) via Get-NetTCPConnection.`);
      }
    } catch (psErr) {
      log("WARN", `[IOC-2] PowerShell fallback also failed: ${psErr.message}`);
    }
  }
  
  if (alerts.length === 0) {
    log("INFO", "[IOC-2] No suspicious outbound connections from node.exe.");
  }
  
  return alerts;
}

// ═══════════════════════════════════════════════════════════════════════════
// IOC-3: Build artifact integrity check (hash comparison)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Tính SHA-256 hash của file.
 */
function sha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

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
      hash: sha256(fullPath),
      size: fs.statSync(fullPath).size,
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
  const alerts = [];

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
        issue: "hash_mismatch",
        baseline_hash: info.hash,
        current_hash: currentHash,
        size_diff: currentSize - info.size,
      });
    } else {
      log("INFO", `[IOC-3] OK: "${file}" integrity verified.`);
    }
  }

  // Kiểm tra file mới bất thường
  const currentFiles = fs.readdirSync(artifactDir).filter((f) =>
    fs.statSync(path.join(artifactDir, f)).isFile() && !ARTIFACT_IGNORE.includes(f)
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

// ═══════════════════════════════════════════════════════════════════════════
// IOC-4: npm install wrapper — chạy npm install trong monitored mode
// ═══════════════════════════════════════════════════════════════════════════

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
      cwd: projectDir,
      encoding: "utf8",
      stdio: "pipe",
    });
  } catch (err) {
    log("WARN", `[SAFE-INSTALL] npm install failed: ${err.message}`);
    return;
  }

  // Step 2: Scan postinstall scripts
  log("INFO", "[SAFE-INSTALL] Step 2: Scanning lifecycle scripts...");
  const nodeModulesDir = path.join(projectDir, "node_modules");
  const suspiciousPackages = scanPostinstallScripts(nodeModulesDir);

  if (suspiciousPackages && suspiciousPackages.length > 0) {
    log(
      "ALERT",
      `[SAFE-INSTALL] ⚠ Found ${suspiciousPackages.length} suspicious package(s)!`
    );
    log("ALERT", "[SAFE-INSTALL] Lifecycle scripts were NOT executed.");
    log("ALERT", "[SAFE-INSTALL] Review the alerts above before running: npm rebuild");
    return suspiciousPackages;
  }

  // Step 3: Nếu sạch, chạy lifecycle scripts
  log("INFO", "[SAFE-INSTALL] Step 3: All clean. Running lifecycle scripts...");
  try {
    execSync("npm rebuild", {
      cwd: projectDir,
      encoding: "utf8",
      stdio: "inherit",
    });
  } catch (err) {
    log("WARN", `[SAFE-INSTALL] npm rebuild failed: ${err.message}`);
  }

  log("INFO", "[SAFE-INSTALL] Done.");
  return [];
}

// ═══════════════════════════════════════════════════════════════════════════
// Watch mode — continuous monitoring
// ═══════════════════════════════════════════════════════════════════════════

function watchMode(artifactDir, intervalMs = 5000) {
  log("INFO", `[WATCH] Continuous monitoring started (interval: ${intervalMs}ms)`);
  log("INFO", `[WATCH] Monitoring: network (IOC-2), artifacts (IOC-3)`);
  log("INFO", "[WATCH] Press Ctrl+C to stop.\n");

  setInterval(() => {
    console.log("─".repeat(50));
    checkNodeNetworkConnections();
    if (artifactDir) verifyArtifactHashes(artifactDir);
  }, intervalMs);
}

// ═══════════════════════════════════════════════════════════════════════════
// Main CLI
// ═══════════════════════════════════════════════════════════════════════════

function printUsage() {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  NT230 Supply Chain Detector — npm/CI Attack Detection      ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Usage:                                                      ║
║    node detect-supply-chain.js <command> [options]            ║
║                                                              ║
║  Commands:                                                   ║
║    scan <node_modules_dir>     Scan postinstall scripts      ║
║    network                     Check node.exe connections    ║
║    baseline <artifacts_dir>    Save artifact hashes          ║
║    verify <artifacts_dir>      Verify artifact integrity     ║
║    safe-install <project_dir>  Safe npm install + scan       ║
║    watch <artifacts_dir>       Continuous monitoring          ║
║    full <project_dir> <artifacts_dir>  Run all checks        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    return;
  }

  console.log("═".repeat(60));
  console.log(`[NT230] Supply Chain Detector started at ${timestamp()}`);
  console.log("═".repeat(60));

  switch (command) {
    case "scan": {
      const dir = args[1] || path.join(process.cwd(), "node_modules");
      scanPostinstallScripts(dir);
      break;
    }
    case "network": {
      checkNodeNetworkConnections();
      break;
    }
    case "baseline": {
      const dir = args[1];
      if (!dir) { console.error("Usage: baseline <artifacts_dir>"); return; }
      baselineArtifactHashes(dir);
      break;
    }
    case "verify": {
      const dir = args[1];
      if (!dir) { console.error("Usage: verify <artifacts_dir>"); return; }
      verifyArtifactHashes(dir);
      break;
    }
    case "safe-install": {
      const dir = args[1] || process.cwd();
      safeNpmInstall(dir);
      break;
    }
    case "watch": {
      const dir = args[1];
      watchMode(dir);
      return; // don't print summary (infinite loop)
    }
    case "full": {
      const projectDir = args[1] || process.cwd();
      const artifactDir = args[2];
      
      console.log("\n[1/3] IOC-1: Scanning postinstall scripts...");
      scanPostinstallScripts(path.join(projectDir, "node_modules"));
      
      console.log("\n[2/3] IOC-2: Checking network connections...");
      checkNodeNetworkConnections();
      
      if (artifactDir) {
        console.log("\n[3/3] IOC-3: Verifying artifact integrity...");
        verifyArtifactHashes(artifactDir);
      } else {
        console.log("\n[3/3] IOC-3: Skipped (no artifacts_dir provided).");
      }
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      return;
  }

  // Summary
  console.log("\n" + "═".repeat(60));
  if (alertCount > 0) {
    console.log(`\x1b[31m[RESULT] ${alertCount} ALERT(s) detected! Review: ${ALERT_LOG}\x1b[0m`);
  } else {
    console.log(`\x1b[32m[RESULT] No alerts. System appears clean.\x1b[0m`);
  }
  console.log("═".repeat(60));
}

main();
