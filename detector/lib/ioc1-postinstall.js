"use strict";

/**
 * IOC-1: Phát hiện suspicious postinstall scripts trong node_modules.
 *
 * IOC-1 v1 — SUSPICIOUS_PATTERNS: quét file JS mà postinstall trỏ đến.
 * IOC-1 v2 — STEALTH_PATTERNS: quét TẤT CẢ JS/JSON trong package
 *             để bắt multi-stage loader (loader.js, config.json, ...).
 * IOC-1 v3 — HEURISTIC: Shannon entropy, string concat deobfuscation,
 *             hex/unicode decode, IP literal detection, suspicious scoring.
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

// ─── IOC-1 v3: Heuristic analysis ─────────────────────────────────────────

/**
 * Shannon entropy — đo độ ngẫu nhiên của string.
 * base64 encoded data thường có entropy 4.5–5.5
 * English text ~ 3.5–4.5, random binary ~ 7.5–8.0
 * Threshold 4.5 = likely encoded/obfuscated.
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Tìm tất cả string literals (single/double/backtick) có entropy cao.
 * Phát hiện obfuscated data dù không match regex pattern cụ thể.
 */
function findHighEntropyStrings(content, threshold = 4.5, minLength = 20) {
  const results = [];
  // Match string literals >= minLength
  const stringRegex = /(?:"([^"\\]{20,}(?:\\.[^"\\]*)*)"|'([^'\\]{20,}(?:\\.[^'\\]*)*)')/g;
  let m;
  while ((m = stringRegex.exec(content)) !== null) {
    const str = m[1] || m[2];
    if (!str || str.length < minLength) continue;
    const ent = shannonEntropy(str);
    if (ent >= threshold) {
      results.push({ value: str.substring(0, 40) + (str.length > 40 ? "..." : ""), entropy: ent.toFixed(2), length: str.length });
    }
  }
  return results;
}

/**
 * Deobfuscate string concatenation: "pro" + "cess" + ".env" → "process.env"
 * Bắt kỹ thuật split keyword để tránh regex IOC-1 v1.
 */
function deobfuscateStringConcat(content) {
  const rebuilt = [];
  // Match: "str1" + "str2" (+ "str3" ...)
  const concatRegex = /(?:["']([^"']{1,30})["']\s*\+\s*){1,10}["']([^"']{1,30})["']/g;
  let m;
  while ((m = concatRegex.exec(content)) !== null) {
    const fullMatch = m[0];
    // Reassemble: extract all quoted parts
    const parts = [];
    const partRegex = /["']([^"']+)["']/g;
    let p;
    while ((p = partRegex.exec(fullMatch)) !== null) {
      parts.push(p[1]);
    }
    if (parts.length >= 2) {
      rebuilt.push(parts.join(""));
    }
  }
  return rebuilt;
}

/**
 * Decode hex escape sequences (\x68\x74\x74\x70) và unicode (\u0068\u0074\u0074\u0070).
 * Attacker dùng để ẩn keywords như "http", "process", "TOKEN".
 */
function decodeEscapeSequences(content) {
  const results = [];

  // Hex escapes: "\x68\x74\x74\x70" → "http"
  const hexRegex = /(?:\\x[0-9a-fA-F]{2}){3,}/g;
  let m;
  while ((m = hexRegex.exec(content)) !== null) {
    try {
      const decoded = m[0].replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      results.push({ encoded: m[0].substring(0, 30), decoded, type: "hex" });
    } catch { /* skip */ }
  }

  // Unicode escapes: "\u0070\u0072\u006f\u0063\u0065\u0073\u0073" → "process"
  const uniRegex = /(?:\\u[0-9a-fA-F]{4}){3,}/g;
  while ((m = uniRegex.exec(content)) !== null) {
    try {
      const decoded = m[0].replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      results.push({ encoded: m[0].substring(0, 30), decoded, type: "unicode" });
    } catch { /* skip */ }
  }

  return results;
}

/**
 * Tìm IP literal trong strings/JSON — chỉ dấu hiệu nếu nằm trong package scripts.
 * Legitimate packages ít khi hardcode IP.
 */
function findIPLiterals(content) {
  const results = [];
  // IPv4 pattern (không match version numbers like 1.0.0)
  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?\b/g;
  let m;
  while ((m = ipRegex.exec(content)) !== null) {
    const ip = m[1];
    const port = m[2] || null;
    // Skip common false positives: 0.0.0.0, 127.0.0.1, version-like
    const octets = ip.split(".").map(Number);
    if (octets.some(o => o > 255)) continue;
    if (ip === "0.0.0.0" || ip === "127.0.0.1") continue;
    results.push({ ip, port });
  }
  return results;
}

const SENSITIVE_KEYWORDS = ["process.env", "token", "secret", "key", "password", "credential",
  "exec(", "spawn(", "eval(", "child_process", "http.request", "http.get", "https.get", "net.connect"];

/**
 * IOC-1 v3 heuristic scan — chạy trên 1 file content.
 * Trả về array of findings, mỗi finding = { technique, detail }.
 */
function heuristicScan(content, relPath) {
  const findings = [];

  // 1. High-entropy strings (encoded data)
  const highEnt = findHighEntropyStrings(content);
  for (const h of highEnt) {
    findings.push({
      technique: "high-entropy string (likely encoded)",
      detail: `entropy=${h.entropy} len=${h.length}: "${h.value}"`,
    });
  }

  // 2. String concatenation deobfuscation
  const deobfuscated = deobfuscateStringConcat(content);
  for (const str of deobfuscated) {
    const lower = str.toLowerCase();
    if (SENSITIVE_KEYWORDS.some(kw => lower.includes(kw))) {
      findings.push({
        technique: "string-concat obfuscation → keyword hidden",
        detail: `rebuilt: "${str}"`,
      });
    }
  }

  // 3. Hex/Unicode escape decoding
  const decoded = decodeEscapeSequences(content);
  for (const d of decoded) {
    const lower = d.decoded.toLowerCase();
    if (SENSITIVE_KEYWORDS.some(kw => lower.includes(kw)) || /https?:\/\//.test(d.decoded)) {
      findings.push({
        technique: `${d.type}-escape obfuscation → keyword hidden`,
        detail: `${d.encoded}... → "${d.decoded}"`,
      });
    }
  }

  // 4. IP literals in JS/JSON (not in comments)
  if (/\.(js|json)$/i.test(relPath)) {
    const ips = findIPLiterals(content);
    for (const ip of ips) {
      findings.push({
        technique: "hardcoded IP literal",
        detail: ip.port ? `${ip.ip}:${ip.port}` : ip.ip,
      });
    }
  }

  return findings;
}

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

              // IOC-1 v3: Heuristic analysis — entropy, deobfuscation, IP literals
              const hFindings = heuristicScan(fileContent, relPath);
              for (const hf of hFindings) {
                log(
                  "ALERT",
                  `[IOC-1v3] HEURISTIC: ${pkgJson.name} → ${relPath}: ${hf.technique} — ${hf.detail}`
                );
                results.push({
                  package: pkgJson.name,
                  hook,
                  type: "heuristic",
                  file: filePath,
                  technique: hf.technique,
                  detail: hf.detail,
                });
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
