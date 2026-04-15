const fs = require("fs");
const os = require("os");
const path = require("path");

const markerPath = path.join(os.tmpdir(), "safe-marker-postinstall.log");
const line = `[${new Date().toISOString()}] postinstall marker emitted by @demo/safe-marker-package\n`;

try {
  fs.appendFileSync(markerPath, line, "utf8");
  console.log(`[safe-marker-package] postinstall marker written to: ${markerPath}`);
} catch (err) {
  console.warn("[safe-marker-package] Unable to write postinstall marker:", err.message);
}
