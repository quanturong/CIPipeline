"use strict";

/**
 * IOC-1: Phát hiện suspicious postinstall scripts trong node_modules.
 *
 * IOC-1 v1 — SUSPICIOUS_PATTERNS: quét file JS mà postinstall trỏ đến.
 * IOC-1 v2 — STEALTH_PATTERNS: quét TẤT CẢ JS/JSON trong package
 *             để bắt multi-stage loader (loader.js, config.json, ...).
 */

const fs   = require("fs");
const path = require("path");
const { log } = require("./utils");

// ─── Patterns ──────────────────────────────────────────────────────────────

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

// IOC-1 v2: Stealth detection patterns — bắt multi-stage loader techniques
const STEALTH_PATTERNS = [
  { pattern: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)/gi,               label: "base64 decode (obfuscation)" },
  { pattern: /require\s*\([^'"]*\+[^)]*\)/gi,                                  label: "dynamic require (computed module path)" },
  { pattern: /fs\.writeFileSync\s*\([^)]+\)[\s\S]{0,100}require\s*\(/gi,       label: "write-then-require (stage loading)" },
  { pattern: /\.on\s*\(\s*['"]end['"]\s*[\s\S]{0,200}(?:require|eval)\s*\(/gi, label: "fetch-then-execute chain" },
  { pattern: /JSON\.parse\s*\(\s*(?:fs\.)?readFileSync/gi,                      label: "config-driven execution" },
  { pattern: /(?:https?|net)['"]?\s*:\s*['"]?\s*require/gi,                    label: "protocol-based dynamic import" },
];

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Lấy tất cả JS/JSON files trong 1 package directory (cho IOC-1 v2 deep scan).
 * Giới hạn depth 3, bỏ qua node_modules lồng nhau.
 */
function getAllFilesInPackage(pkgDir, depth = 0) {
  if (depth > 3) return [];
  const results = [];

  try {
    const entries = fs.readdirSync(pkgDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;

      const fullPath = path.join(pkgDir, entry.name);
      if (entry.isDirectory()) {
        results.push(...getAllFilesInPackage(fullPath, depth + 1));
      } else if (/\.(js|json)$/i.test(entry.name)) {
        results.push(fullPath);
      }
    }
  } catch { /* skip unreadable dirs */ }

  return results;
}

// ─── Main export ──────────────────────────────────────────────────────────

/**
 * Quét tất cả package.json trong node_modules để tìm postinstall scripts đáng ngờ.
 */
function scanPostinstallScripts(nodeModulesDir) {
  log("INFO", `[IOC-1] Scanning postinstall scripts in: ${nodeModulesDir}`);

  if (!fs.existsSync(nodeModulesDir)) {
    log("WARN", `[IOC-1] node_modules not found: ${nodeModulesDir}`);
    return;
  }

  const results = [];

  function walkPackages(dir, depth = 0) {
    if (depth > 3) return;

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

        const LIFECYCLE_HOOKS = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"];

        for (const hook of LIFECYCLE_HOOKS) {
          if (!scripts[hook]) continue;

          log("INFO", `[IOC-1] Found ${hook} script in ${pkgJson.name}: "${scripts[hook]}"`);

          // IOC-1 v1: scan file JS mà postinstall trỏ đến
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
                    matches,
                  });
                }
              }
            }
          }

          // IOC-1 v2: Deep scan — quét TẤT CẢ JS + JSON files trong package
          const pkgRoot = path.join(dir, entry.name);
          const allPkgFiles = getAllFilesInPackage(pkgRoot);

          for (const filePath of allPkgFiles) {
            try {
              const fileContent = fs.readFileSync(filePath, "utf8");
              const relPath = path.relative(pkgRoot, filePath);

              for (const { pattern, label } of STEALTH_PATTERNS) {
                pattern.lastIndex = 0;
                const matches = fileContent.match(pattern);
                if (matches) {
                  log(
                    "ALERT",
                    `[IOC-1v2] STEALTH: ${pkgJson.name} → ${relPath}: ${label}`
                  );
                  results.push({
                    package: pkgJson.name,
                    hook,
                    type: "stealth",
                    file: filePath,
                    technique: label,
                    matches,
                  });
                }
              }
            } catch {
              // skip unreadable files
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

module.exports = { scanPostinstallScripts };
