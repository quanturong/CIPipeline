const fs = require("fs");
const path = require("path");

const artifactDir = path.resolve(__dirname, "..", "artifacts");
const outputFile = path.join(artifactDir, "build-output.txt");

if (!fs.existsSync(artifactDir)) {
  fs.mkdirSync(artifactDir, { recursive: true });
}

fs.writeFileSync(
  outputFile,
  `clean build output\ncreated_at=${new Date().toISOString()}\n`,
  "utf8"
);

console.log(`[ci-demo] Clean artifact created: ${outputFile}`);
