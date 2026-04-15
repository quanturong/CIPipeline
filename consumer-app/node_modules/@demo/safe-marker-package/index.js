const fs = require("fs");
const os = require("os");
const path = require("path");

function emitMarker(markerName = "safe-marker-runtime.log") {
  const markerPath = path.join(os.tmpdir(), markerName);
  const line = `[${new Date().toISOString()}] runtime marker emitted by @demo/safe-marker-package\n`;

  fs.appendFileSync(markerPath, line, "utf8");
  console.log(`[safe-marker-package] Marker written to: ${markerPath}`);

  return markerPath;
}

module.exports = {
  emitMarker,
};
