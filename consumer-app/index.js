const { emitMarker } = require("@demo/safe-marker-package");

console.log("[consumer-app] Running safe marker simulation...");
const markerPath = emitMarker("safe-marker-consumer-runtime.log");
console.log(`[consumer-app] Done. Marker path: ${markerPath}`);
