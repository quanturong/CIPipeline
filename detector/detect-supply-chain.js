"use strict";

const path = require("path");
const { log, getAlertCount, ALERT_LOG }              = require("./lib/utils");
const { scanPostinstallScripts }                     = require("./lib/ioc1-postinstall");
const { checkNodeNetworkConnections }                = require("./lib/ioc2-network");
const { baselineArtifactHashes, verifyArtifactHashes } = require("./lib/ioc3-artifacts");
const { safeNpmInstall, monitorInstall }             = require("./lib/install-agent");

// ===========================================================================
// Watch mode -- continuous monitoring
// ===========================================================================

function watchMode(artifactDir, intervalMs = 5000) {
  log("INFO", `[WATCH] Continuous monitoring started (interval: ${intervalMs}ms)`);
  log("INFO", "[WATCH] Monitoring: network (IOC-2), artifacts (IOC-3)");
  log("INFO", "[WATCH] Press Ctrl+C to stop.\n");

  setInterval(() => {
    console.log("-".repeat(50));
    checkNodeNetworkConnections();
    if (artifactDir) verifyArtifactHashes(artifactDir);
  }, intervalMs);
}

// ===========================================================================
// CLI
// ===========================================================================

function printUsage() {
  console.log(`
+--------------------------------------------------------------+
|  NT230 Supply Chain Detector -- npm/CI Attack Detection      |
+--------------------------------------------------------------+
|                                                              |
|  Usage:                                                      |
|    node detect-supply-chain.js <command> [options]           |
|                                                              |
|  Commands:                                                   |
|    scan <node_modules_dir>     IOC-1: scan postinstall       |
|    network                     IOC-2: check connections      |
|    baseline <artifacts_dir>    IOC-3: save artifact hashes   |
|    verify <artifacts_dir>      IOC-3: verify artifact hashes |
|    safe-install <project_dir>  safe npm install + scan       |
|    monitor-install <dir> [reg] live network poll + install   |
|    watch <artifacts_dir>       continuous monitoring         |
|    full <project_dir> <artifacts_dir>  run all checks        |
|                                                              |
|  Modules: lib/utils.js  ioc1-postinstall.js  ioc2-network.js |
|           ioc3-artifacts.js  install-agent.js                |
+--------------------------------------------------------------+
  `);
}

function main() {
  const args    = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    return;
  }

  console.log("=".repeat(60));
  console.log("[NT230] Supply Chain Detector started at " + new Date().toISOString());
  console.log("=".repeat(60));

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
    case "monitor-install": {
      const dir = args[1] || process.cwd();
      const reg = args[2] || null;
      monitorInstall(dir, reg);
      break;
    }
    case "watch": {
      const dir = args[1];
      watchMode(dir);
      return; // infinite loop -- no summary
    }
    case "full": {
      const projectDir  = args[1] || process.cwd();
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
      console.error("Unknown command: " + command);
      printUsage();
      return;
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  const count = getAlertCount();
  if (count > 0) {
    console.log(`\x1b[31m[RESULT] ${count} ALERT(s) detected! Review: ${ALERT_LOG}\x1b[0m`);
  } else {
    console.log("\x1b[32m[RESULT] No alerts. System appears clean.\x1b[0m");
  }
  console.log("=".repeat(60));
}

main();