# NT230 — Hướng Dẫn Chạy Demo Supply Chain Attack PoC

## Tổng Quan

Demo mô phỏng **Supply Chain Attack qua npm** (MITRE ATT&CK T1195.002) với 3 phần:

| Phần | Yêu cầu | Nội dung |
|------|---------|----------|
| **A** | PoC kỹ thuật tấn công | Malicious npm package → đánh cắp CI secrets + poison build artifact |
| **B** | Bypass Windows Defender | Kiểm chứng Defender không phát hiện JS payload |
| **C** | Công cụ phát hiện | Detector scan postinstall scripts, network, artifact integrity |

---

## Prerequisites

| Tool | Version | Kiểm tra |
|------|---------|----------|
| **Node.js** | >= 18 | `node --version` |
| **npm** | >= 9 | `npm --version` |
| **Docker Desktop** | Running | `docker info` |
| **PowerShell** | >= 5.1 | `$PSVersionTable.PSVersion` |

---

## Cấu Trúc Thư Mục

```
DoAn/
├── packages/safe-marker-package/       # npm package (safe + malicious version)
│   ├── scripts/
│   │   ├── postinstall-marker.js       # Safe: ghi marker file
│   │   ├── postinstall-ci-attack.js    # Attack NOISY: single-file, all logic
│   │   ├── postinstall-stealth.js      # Attack STEALTH: Stage 0 — chỉ require loader
│   │   ├── loader.js                   # Attack STEALTH: Stage 1 — đọc config, fetch stage2
│   │   └── config.json                 # Attack STEALTH: base64-encoded attacker URL
│   └── package.json
├── ci/
│   ├── build-clean.js                  # CI step: tạo build artifact (clean)
│   ├── inject-safe-marker.js           # CI step: inject marker (safe)
│   └── inject-malicious-artifact.js    # PoC A: inject backdoor vào artifact
├── attacker-server/
│   └── receiver.js                     # Attacker server: /exfil/secrets, /stage2, /beacon
├── consumer-app/                       # Downstream consumer (simulated)
├── detector/
│   ├── detect-supply-chain.js          # CLI entry point (watchMode + main)
│   └── lib/
│       ├── utils.js                    # Shared: log(), timestamp(), config
│       ├── ioc1-postinstall.js         # IOC-1: scan lifecycle scripts (noisy + stealth)
│       ├── ioc2-network.js             # IOC-2: check outbound node.exe connections
│       ├── ioc3-artifacts.js           # IOC-3: SHA-256 artifact baseline/verify
│       └── install-agent.js            # safe-install + monitor-install agents
├── scripts/
│   ├── 1-attacker-publish.ps1          # Actor 1: publish noisy|stealth package
│   ├── 2-ci-pipeline-run.ps1           # Actor 2: CI pipeline (không biết về attacker)
│   ├── 3-evidence-collection.ps1       # Actor 3: forensics — thu thập loot + bằng chứng
│   ├── run-malicious-ci-simulation.ps1 # Legacy monolithic script (vẫn hoạt động)
│   ├── test-av-bypass.ps1              # Phần B: test AV bypass + AMSI analysis
│   ├── publish-to-verdaccio.ps1        # Publish package lên registry
│   └── simulate-publish-consume.ps1    # Safe simulation
├── infra/verdaccio/                    # Verdaccio config
├── .gitlab-ci.yml                      # CI pipeline CLEAN (safe steps only)
├── .gitlab-ci.compromised.yml          # CI pipeline COMPROMISED (attack inject)
├── docker-compose.verdaccio.yml        # Docker Compose cho registry + attacker
└── artifacts/                          # Build output (bị poison)
```

---

## PHẦN A — PoC Tấn Công Supply Chain

### Bước 1: Khởi động Verdaccio (Private Registry)

```powershell
cd e:\NT230\DoAn
docker compose -f docker-compose.verdaccio.yml up -d
```

Kiểm tra: mở browser → `http://localhost:4873` → thấy Verdaccio UI.

### Bước 2: Khởi động Attacker Receiver + Verdaccio

Attacker receiver giờ chạy trong **Docker container** (IP `172.30.0.20`) trên bridge network riêng — traffic từ victim đi qua Docker network thay vì loopback `127.0.0.1`.

```powershell
cd e:\NT230\DoAn
docker compose -f docker-compose.verdaccio.yml up -d --build
```

Kiểm tra:
```powershell
# Verdaccio
Invoke-WebRequest -Uri "http://localhost:4873" -UseBasicParsing

# Attacker receiver
docker logs attacker-receiver
```

Output kỳ vọng từ `docker logs attacker-receiver`:
```
═══════════════════════════════════════════════════════════
[NT230 PoC] Attacker receiver listening on port 8080
  POST /exfil/secrets                  — CI secret harvest
  POST /exfil/artifact-poison-confirm  — artifact poison confirm
  GET  /beacon                         — second-stage consumer beacon
═══════════════════════════════════════════════════════════
```

> **Network topology**: Host machine (victim/CI) → `172.30.0.20` (attacker container). Traffic đi qua Docker bridge `poc_network` (subnet `172.30.0.0/24`), không còn là loopback.

### Bước 3: Chạy Attack — 3 Actor Scripts (Khuyến nghị)

Workflow mới chia thành **3 actor riêng biệt** phản ánh thực tế: attacker, CI runner và forensics analyst là 3 vai trò độc lập.

#### Actor 1 — Attacker: Publish malicious package

```powershell
cd e:\NT230\DoAn

# Chế độ NOISY (dễ bị IOC-1 phát hiện — single file, chứa suspicious keywords)
.\scripts\1-attacker-publish.ps1 -Mode noisy

# Chế độ STEALTH (multi-stage loader — vượt qua IOC-1 v1)
.\scripts\1-attacker-publish.ps1 -Mode stealth
```

> **Noisy vs Stealth**: `noisy` dùng `postinstall-ci-attack.js` — một file chứa toàn bộ logic (process.env, http.request...) → IOC-1 dễ phát hiện. `stealth` dùng `postinstall-stealth.js → loader.js → config.json (base64 URL) → fetch /stage2 từ attacker` — entry file không chứa suspicious keyword → vượt qua IOC-1 v1, chỉ bị bắt bởi IOC-1 v2 (deep scan).

#### Actor 2 — CI Runner: Chạy pipeline (không biết về attacker)

```powershell
.\scripts\2-ci-pipeline-run.ps1
```

Script mô phỏng CI pipeline 5 stages:
1. Setup environment (fake CI secrets)
2. `npm install` từ Verdaccio → **postinstall tự động chạy**
3. Build step
4. Post-build inject (artifact poisoning)
5. Cleanup

#### Actor 3 — Forensics: Thu thập bằng chứng

```powershell
.\scripts\3-evidence-collection.ps1
```

Kiểm tra: loot files từ attacker server, artifact tampering, Docker logs → in VERDICT.

---

#### (Alternative) Legacy monolithic script

```powershell
# Vẫn hoạt động, chạy cả 3 roles trong 1 script
.\scripts\run-malicious-ci-simulation.ps1
```

### Bước 4: Kiểm tra kết quả

Xem log attacker receiver:

```powershell
docker logs attacker-receiver
```

Output kỳ vọng:

```
═══════════════════════════════════════════════════════════
[...] ◄◄ CI SECRETS RECEIVED from ::ffff:172.30.0.1
──────────────────────────────────────────────────────────
  [secrets]
    CI_JOB_TOKEN=glpat-FAKE-CI-TOKEN-xxxxxxxxxxxx ◄ HIGH VALUE
    GITHUB_TOKEN=ghp_FAKE_GITHUB_TOKEN_xxx...      ◄ HIGH VALUE
    AWS_SECRET_ACCESS_KEY=FAKE+AWS+SECRET+KEY/...  ◄ HIGH VALUE
    NPM_TOKEN=npm_FAKE_PUBLISH_TOKEN_xxx...        ◄ HIGH VALUE
═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════
[...] ◄◄ ARTIFACT POISONED — confirmed
═══════════════════════════════════════════════════════════
```

> **Chú ý IP**: Source IP hiện là `172.30.0.1` (Docker gateway) thay vì `127.0.0.1` — chứng minh traffic đi qua network boundary.

Stolen data được lưu trong `attacker-server/loot/`.

---

## PHẦN B — Bypass Windows Defender

### Cách chạy

Mở **PowerShell as Administrator**:

```powershell
cd e:\NT230\DoAn
.\scripts\test-av-bypass.ps1
```

Script tự động:
1. Thu thập Defender version, signature date, settings
2. Custom Scan toàn bộ project folder
3. Kiểm tra threat detection log
4. Ghi phân tích lý do bypass ra `artifacts/av-bypass-report.txt`

### Kết quả kỳ vọng

```
[4/5] Checking Defender threat history...
  ✓ No threats detected — payload BYPASSED Defender
```

### Tại sao bypass thành công

| # | Lý do | Chi tiết |
|---|-------|---------|
| 1 | **Trusted Process** | Payload chạy dưới `node.exe` — signed binary, Defender whitelist |
| 2 | **No Binary** | Pure JavaScript — không match PE/shellcode signatures |
| 3 | **No Suspicious APIs** | Chỉ dùng `http.request()`, `process.env`, `os.hostname()` |
| 4 | **Legitimate Traffic** | HTTP POST JSON trông như REST API call bình thường |
| 5 | **Fail-silent** | Lỗi bị nuốt → không trigger behavioral detection |
| 6 | **Base64 in Comments** | Payload trong artifact được encode, nằm trong JS comment |
| 7 | **AMSI không hook Node.js** | V8 engine không tích hợp AMSI provider → Defender không scan JS runtime |

### AMSI Analysis (quan trọng)

AMSI (Antimalware Scan Interface) là cơ chế Windows cho phép AV scan script content tại runtime. **Đây là lý do cốt lõi** tại sao bypass thành công:

| Runtime | AMSI Integration | Defender scan được? |
|---------|-----------------|--------------------|
| PowerShell | Có (built-in) | ✅ CÓ |
| .NET CLR | Có | ✅ CÓ |
| WSH (JScript) | Có | ✅ CÓ |
| Python (CPython) | Không | ❌ Bypass |
| **Node.js (V8)** | **Không** | **❌ Bypass** |

> **Phân biệt quan trọng**: JScript chạy qua WSH (`cscript`/`wscript`) BỊ AMSI scan. JavaScript chạy qua Node.js (V8 engine) KHÔNG bị AMSI scan. V8 parse và execute JS trực tiếp mà không gọi `amsi.dll → AmsiScanBuffer()`.

> **Lưu ý**: Script tự động đợi 30 giây sau `Start-MpScan` để scan hoàn tất (vì `Start-MpScan` trả về async). Report file (`artifacts/av-bypass-report.txt`) ghi đầy đủ Defender version + scan result + AMSI analysis.

---

## PHẦN C — Detector (Công cụ phát hiện)

### Kiến trúc module

```
detector/
  detect-supply-chain.js   ← CLI entry point (126 lines)
  lib/
    utils.js               ← shared config + log() + timestamp()
    ioc1-postinstall.js    ← IOC-1 v1 (noisy) + IOC-1 v2 (stealth deep scan)
    ioc2-network.js        ← IOC-2: netstat / Get-NetTCPConnection
    ioc3-artifacts.js      ← IOC-3: SHA-256 baseline + verify
    install-agent.js       ← safe-install + monitor-install
```

### Các IOC được monitor

| IOC | Mô tả | Phương pháp |
|-----|--------|-------------|
| **IOC-1 v1** | Postinstall script chứa suspicious keywords | Static scan file JS mà postinstall trỏ đến |
| **IOC-1 v2** | Multi-stage loader (stealth) trong package | Deep scan TẤT CẢ .js/.json trong package (base64, dynamic require, write-then-require...) |
| **IOC-2** | node.exe tạo outbound connection bất thường | `netstat -nob` (Admin) hoặc `Get-NetTCPConnection` (fallback) |
| **IOC-2-LIVE** | Outbound connection CÙ LÚC npm install đang chạy | `monitor-install`: poll Get-NetTCPConnection mỗi 500ms trong khi `npm install` |
| **IOC-3** | Build artifact bị tamper | SHA-256 hash compare với baseline |

### Cách 1: Full scan (chạy sau attack)

```powershell
cd e:\NT230\DoAn
node detector\detect-supply-chain.js full . artifacts
```

Output kỳ vọng:
```
[1/3] IOC-1: Scanning postinstall scripts...
[ALERT] [IOC-1] SUSPICIOUS: @demo/safe-marker-package → postinstall script contains: process.env, TOKEN, SECRET, KEY, require("http")

[2/3] IOC-2: Checking network connections...
[WARN] [IOC-2] netstat -nob failed (need Admin): ...
[INFO] [IOC-2] Falling back to PowerShell Get-NetTCPConnection (no Admin required)...
[ALERT] [IOC-2] node.exe has outbound connection to 192.168.157.134:8080 (ESTABLISHED)

[3/3] IOC-3: Verifying artifact integrity...
[ALERT] [IOC-3] TAMPERED: "build-output.txt" hash changed!
(av-bypass-report.txt được tự động loại — không phải build artifact)

═══════════════════════════════════════════════════════════
[RESULT] 3 ALERT(s) detected! Review: detector\detector-alerts.log
═══════════════════════════════════════════════════════════
```

### Cách 2: Monitor-install — IOC-2 live trong khi cài (Anti-stealth)

Vấn đề của IOC-2 thông thường: one-shot HTTP POST hoàn thành trong <100ms — detector chạy SAU khi install xong → không bao giờ thấy connection. `monitor-install` giải quyết bằng cách poll network **đồng thời** với `npm install`:

```powershell
# Cài từ Verdaccio, poll network mỗi 500ms
node detector\detect-supply-chain.js monitor-install .\consumer-app http://localhost:4873

# Hoặc không chỉ định registry (dùng mặc định)
node detector\detect-supply-chain.js monitor-install .\consumer-app
```

Flow:
1. Xóa `node_modules` + `package-lock.json` (clean install)
2. Start `setInterval` poll `Get-NetTCPConnection` mỗi 500ms
3. Chạy `npm install` (blocking)
4. Bắt mọi outbound connection của `node.exe` trong quá trình install
5. Đợi thêm 2 giây cho lingering connections
6. Chạy IOC-1 scan trên packages đã cài
7. Report: số polls, số alerts, IP:port bị bắt

Output kỳ vọng (stealth attack):
```
[IOC-2-LIVE] OUTBOUND: node.exe → 172.30.0.20:8080 (Established) [poll #3]
[MONITOR-INSTALL] Detected 1 suspicious outbound connection(s) during install!
[IOC-1v2] STEALTH: @demo/safe-marker-package → scripts/loader.js: config-driven execution
```

### Cách 3: Safe npm install (phòng ngừa)

Thay vì `npm install` bình thường, dùng detector:

```powershell
node detector\detect-supply-chain.js safe-install .\consumer-app
```

Flow:
1. `npm install --ignore-scripts` (tải về nhưng KHÔNG chạy postinstall)
2. Scan tất cả lifecycle scripts → phát hiện suspicious patterns
3. Nếu clean → tự động chạy `npm rebuild`
4. Nếu suspicious → DỪNG, báo alert, chờ user review

### Cách 4: Continuous monitoring

```powershell
node detector\detect-supply-chain.js watch artifacts
```

Mỗi 5 giây kiểm tra network connections + artifact integrity.

### Cách 5: Chỉ scan postinstall

```powershell
# Scan noisy attack
node detector\detect-supply-chain.js scan .\consumer-app\node_modules

# IOC-1 v2 stealth patterns tự động chạy kèm — cần không cần flag thêm
```

### Cách 6: Artifact integrity

```powershell
# Trước attack — lưu baseline
node detector\detect-supply-chain.js baseline artifacts

# Sau attack — kiểm tra thay đổi
node detector\detect-supply-chain.js verify artifacts
```

### Tất cả commands

```
node detect-supply-chain.js scan            <node_modules_dir>   — IOC-1 scan
node detect-supply-chain.js network                              — IOC-2 one-shot
node detect-supply-chain.js monitor-install <dir> [registry]     — IOC-2 live + IOC-1
node detect-supply-chain.js safe-install    <dir>                — phòng ngừa
node detect-supply-chain.js baseline        <artifacts_dir>      — IOC-3 baseline
node detect-supply-chain.js verify          <artifacts_dir>      — IOC-3 verify
node detect-supply-chain.js watch           <artifacts_dir>      — continuous
node detect-supply-chain.js full            <dir> <artifacts>    — tất cả IOC
```

---

## Demo Workflow Hoàn Chỉnh (A → B → C)

### Thứ tự chạy demo cho reviewer/giảng viên:

**Kịch bản đầy đủ (3-actor + stealth — khuyến nghị):**

```
Terminal 1 (Attacker):    .\scripts\1-attacker-publish.ps1 -Mode stealth
                          → Docker start, publish stealth package lên Verdaccio

Terminal 2 (CI Runner):   .\scripts\2-ci-pipeline-run.ps1
                          → Pipeline chạy, stage2 fetch từ attacker, secrets stolen

Terminal 1 (Forensics):   .\scripts\3-evidence-collection.ps1
                          → Thu thập loot, kiểm tra artifact, in VERDICT

Terminal 2 (AV Test):     .\scripts\test-av-bypass.ps1   [Run as Admin]
                          → Defender không phát hiện (Phần B ✓)

Terminal 1 (Detector):    node detector\detect-supply-chain.js monitor-install .\consumer-app http://localhost:4873
                          → Bắt live IOC-2 + IOC-1 v2 (Phần C ✓)
```

**Kịch bản nhanh (legacy):**

```
Terminal 1 (Attack):      .\scripts\run-malicious-ci-simulation.ps1
                          → Chạy toàn bộ A trong 1 script

Terminal 2 (AV Test):     .\scripts\test-av-bypass.ps1   [Run as Admin]

Terminal 1 (Detector):    node detector\detect-supply-chain.js full . artifacts
```

### Timeline (3-actor, stealth mode):

```
[T=0]   Docker start: Verdaccio + Attacker receiver      │ 1-attacker-publish.ps1
[T=1]   Stealth package publish: postinstall-stealth.js  │ Actor 1
[T=2]   CI pipeline start, set fake secrets               │ Actor 2
[T=3]   npm install → loader.js → fetch /stage2           │ Actor 2 → 172.30.0.20
[T=4]   Stage2 execute → secrets POST /exfil/secrets      │ 172.30.0.20 (attacker)
[T=5]   Artifact poisoning → POST confirm                 │ Actor 2 → 172.30.0.20
[T=6]   3-evidence-collection.ps1 → VERDICT               │ Actor 3
[T=7]   Defender scan → bypass confirmed                  │ AV test
[T=8]   monitor-install → IOC-2-LIVE + IOC-1v2 alerts     │ Detector
```

---

## Cleanup Sau Demo

```powershell
# Tắt Verdaccio + Attacker receiver
cd e:\NT230\DoAn
docker compose -f docker-compose.verdaccio.yml down

# Khôi phục package.json gốc
$pkgDir = "packages\safe-marker-package"
if (Test-Path "$pkgDir\package.json.bak") {
    Copy-Item "$pkgDir\package.json.bak" "$pkgDir\package.json" -Force
    Remove-Item "$pkgDir\package.json.bak"
}

# Xoá loot
Remove-Item -Recurse -Force attacker-server\loot -ErrorAction SilentlyContinue

# Xoá detector logs
Remove-Item detector\detector-alerts.log -ErrorAction SilentlyContinue
Remove-Item detector\artifact-hashes.json -ErrorAction SilentlyContinue

# Xoá consumer node_modules
Remove-Item -Recurse -Force consumer-app\node_modules -ErrorAction SilentlyContinue
Remove-Item consumer-app\package-lock.json -ErrorAction SilentlyContinue
```

---

## So Sánh CI Pipeline: Clean vs Compromised

| File | Mô tả | Stages |
|------|--------|--------|
| `.gitlab-ci.yml` | Pipeline **CLEAN** gốc | build → (safe marker) |
| `.gitlab-ci.compromised.yml` | Pipeline **BỊ INJECT** bởi attacker | install (secret theft) → build → inject_backdoor |

So sánh 2 file để thấy attacker đã thêm:
- Stage `install`: `npm install` từ Verdaccio → postinstall-ci-attack.js tự động exfiltrate secrets
- Stage `inject`: chạy `inject-malicious-artifact.js` → append backdoor vào build artifact
- Tên job vô hại ("Post-build processing...") để tránh nghi ngờ

---

## Troubleshooting

| Vấn đề | Giải pháp |
|--------|----------|
| Docker không chạy | Mở Docker Desktop, chờ "Docker is running" |
| Verdaccio 401 Unauthorized | `npm adduser --registry http://localhost:4873` (user: demo, pass: demo, email: demo@test.com) |
| receiver.js port 8080 bị chiếm | `docker compose -f docker-compose.verdaccio.yml down` rồi `up -d --build` lại |
| Defender scan cần Admin | Chạy PowerShell "Run as Administrator" (khuyến nghị cho scan đáng tin cậy) |
| `monitor-install` không bắt được connection | HTTP POST stealth xảy ra trong <500ms — giảm `POLL_INTERVAL` trong `lib/install-agent.js` xuống 200ms |
| `1-attacker-publish.ps1` lỗi publish | Verdaccio chưa start — chạy `docker compose -f docker-compose.verdaccio.yml up -d` trước |
| Stage2 không được fetch | Kiểm tra `config.json` trong package: base64 decode `cdn` field phải ra `http://172.30.0.20:8080/` |
| `3-evidence-collection.ps1` không thấy loot | Actor 2 chưa chạy hoặc `npm install` xong trước khi stage2 execute — kiểm tra `docker logs attacker-receiver` |
| IOC-1 v2 không báo stealth patterns | Deep scan chạy khi package CÓ lifecycle hook — đảm bảo `postinstall` field trong package.json tồn tại |
| `netstat -nob` cần Admin | IOC-2 **tự động fallback** sang `Get-NetTCPConnection` (không cần Admin) |
| npm install lỗi tarball | Chạy `npm pack` lại trong `packages/safe-marker-package/` |
| Package 409 Already Published | Bump version trong package.json trước khi publish |
| IOC-3 false positive av-bypass-report.txt | File này đã được loại tự động khỏi artifact check |

---

## MITRE ATT&CK Mapping

| Technique | ID | Thể hiện trong PoC |
|-----------|-----|-------------------|
| Supply Chain Compromise: Software | T1195.002 | Malicious npm package qua Verdaccio |
| Credential Access: Unsecured Credentials | T1552.007 | Đọc CI env vars (GITHUB_TOKEN, AWS_SECRET...) |
| Exfiltration Over C2 Channel | T1041 | HTTP POST secrets về attacker server |
| Masquerading | T1036.005 | User-Agent giả mạo npm client, job name vô hại |
| Supply Chain: Compromise Software Supply Chain | T1195.002 | Artifact poisoning (inject backdoor vào build output) |

---

## Hạn Chế Của PoC (tự nhận)

| Hạn chế | Giải thích |
|---------|------------|
| Single-host demo | Attacker chạy trong Docker container (172.30.0.20), traffic qua bridge network — **không còn loopback** |
| Không chạy CI thật | Dùng PowerShell script thay vì GitLab Runner. `.gitlab-ci.compromised.yml` là mô phỏng |
| Static regex detection | IOC-1 dùng regex → dễ bị bypass bằng string concatenation/obfuscation |
| Chỉ test Windows Defender | Chưa test multi-AV (VirusTotal) hoặc EDR khác |
| Defense Evasion: Trusted Process | T1036.005 | Chạy dưới node.exe (signed binary) |
