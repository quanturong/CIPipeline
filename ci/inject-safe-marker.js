const fs = require("fs");
const path = require("path");

const artifactDir = path.resolve(__dirname, "..", "artifacts");
const markerFile = path.join(artifactDir, "ci-injected-marker.txt");

if (!fs.existsSync(artifactDir)) {
  fs.mkdirSync(artifactDir, { recursive: true });
}

const content = [
  `timestamp=${new Date().toISOString()}`,
  "source=simulated-ci-injection-step",
  "note=SAFE_DEMO_ONLY_NO_HARMFUL_PAYLOAD",
  "",
].join("\n");

fs.appendFileSync(markerFile, content, "utf8");
console.log(`[ci-demo] Injected safe marker artifact: ${markerFile}`);
