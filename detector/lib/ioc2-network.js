"use strict";

/**
 * IOC-2: Phát hiện outbound TCP connections từ node.exe trong lúc runtime.
 *
 * Sử dụng netstat -nob (cần Admin) hoặc PowerShell Get-NetTCPConnection (không cần Admin).
 * Chỉ hỗ trợ Windows.
 */

const { execSync } = require("child_process");
const os = require("os");
const { log } = require("./utils");

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
          const remoteIP   = connMatch[1];
          const remotePort = connMatch[2];
          const state      = connMatch[3];

          if (state === "ESTABLISHED" && remoteIP !== "127.0.0.1") {
            const isLocal     = remoteIP.startsWith("127.") || remoteIP === "::1";
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
      const psCmd =
        `powershell -NoProfile -Command "` +
        `Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ` +
        `ForEach-Object { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; ` +
        `if ($proc -eq 'node') { Write-Output (\\\"$($_.RemoteAddress):$($_.RemotePort)\\\") } }"`;

      const psOutput    = execSync(psCmd, { encoding: "utf8", timeout: 15000 });
      const connections = psOutput.trim().split("\n").filter(Boolean);

      for (const conn of connections) {
        const [remoteIP, remotePort] = conn.trim().split(":");
        if (!remoteIP) continue;

        const isLocal     = remoteIP.startsWith("127.") || remoteIP === "::1" || remoteIP === "0.0.0.0";
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

module.exports = { checkNodeNetworkConnections };
