# Safe Supply-Chain Simulation PoC (Marker-only)

> ⚠️ Educational defensive demo only. This project does **not** execute harmful payloads.

This workspace demonstrates:
1. A fake npm package with **marker behavior only** (writes marker logs to OS temp and console).
2. A local/private npm registry setup via Verdaccio (simulation of publish & consume).
3. (Optional) A simulated CI pipeline where an extra step is injected, but it only writes a harmless artifact marker.

## Structure

- `packages/safe-marker-package/`: fake package (`@demo/safe-marker-package`)
- `consumer-app/`: app that installs and uses the fake package
- `infra/verdaccio/`: Verdaccio config
- `scripts/`: PowerShell helper scripts for simulation
- `ci/`: scripts for optional CI injection simulation

## A) Fake package marker behavior

The package does only safe actions:
- `postinstall`: append log line to temp file `safe-marker-postinstall.log`
- runtime API `emitMarker()`: append log line to temp file (e.g., `safe-marker-consumer-runtime.log`)

## B) Private registry simulation (Verdaccio)

### Option 1 — Full private registry flow (Verdaccio)

1. Start Verdaccio with Docker Compose (`docker-compose.verdaccio.yml`).
2. In `packages/safe-marker-package`, run `npm adduser --registry http://localhost:4873`.
3. Publish package: run script `scripts/publish-to-verdaccio.ps1`.
4. Consume package from registry:
   - In `consumer-app`, install `@demo/safe-marker-package` from `http://localhost:4873`.
   - Run `npm start`.

### Option 2 — Local tarball flow (no registry runtime needed)

Run:
- `scripts/simulate-publish-consume.ps1`

This will:
1. `npm pack` the fake package into `dist/`
2. install tarball into `consumer-app`
3. run consumer app

## C) Optional CI injection simulation (safe)

### Local simulation

Run:
- `scripts/run-local-ci-simulation.ps1`

Outputs:
- `artifacts/build-output.txt`
- `artifacts/ci-injected-marker.txt` (harmless marker)

### GitLab CI example

See `.gitlab-ci.yml`:
- `build_clean`: normal build
- `build_with_injected_step`: includes simulated injected step

## Safety note

This PoC intentionally avoids exploit code and harmful payloads. It is suitable for defensive demonstrations and classroom/lab discussions about software supply-chain risks.
