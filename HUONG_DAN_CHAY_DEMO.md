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
├── packages/safe-marker-package/     # npm package (safe + malicious version)
│   ├── scripts/
│   │   ├── postinstall-marker.js     # Safe: ghi marker file
│   │   └── postinstall-ci-attack.js  # PoC A: đánh cắp CI env vars
│   └── package.json
├── ci/
│   ├── build-clean.js                # CI step: tạo build artifact (clean)
│   ├── inject-safe-marker.js         # CI step: inject marker (safe)
│   └── inject-malicious-artifact.js  # PoC A: inject backdoor vào artifact
├── attacker-server/
│   └── receiver.js                   # PoC A: server nhận stolen data
├── consumer-app/                     # Downstream consumer (simulated)
├── detector/
│   └── detect-supply-chain.js        # Phần C: công cụ phát hiện
├── scripts/
│   ├── run-malicious-ci-simulation.ps1   # Script chạy full attack
│   ├── test-av-bypass.ps1                # Phần B: test AV bypass + AMSI analysis
│   ├── publish-to-verdaccio.ps1          # Publish package lên registry
│   └── simulate-publish-consume.ps1      # Safe simulation
├── infra/verdaccio/                  # Verdaccio config
├── .gitlab-ci.yml                    # CI pipeline CLEAN (safe steps only)
├── .gitlab-ci.compromised.yml        # CI pipeline COMPROMISED (attack inject)
├── docker-compose.verdaccio.yml      # Docker Compose cho registry
└── artifacts/                        # Build output (bị poison)
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

### Bước 3: Chạy Full Attack Simulation

Mở **Terminal 2**:

```powershell
cd e:\NT230\DoAn
.\scripts\run-malicious-ci-simulation.ps1
```

Script này tự động:
1. ✅ Start Verdaccio + Attacker receiver (Docker containers)
2. ✅ Đổi package.json → malicious postinstall
3. ✅ **Xóa env vars nhạy cảm thật** (API_KEY, SECRET, TOKEN...) rồi set fake CI secrets
4. ✅ Tạo baseline artifact hash
5. ✅ `npm install` từ Verdaccio → **postinstall đánh cắp secrets** → gửi về receiver (172.30.0.20)
6. ✅ Chạy artifact poisoning step

> **Lưu ý bảo mật**: Bước 3 tự động xóa credentials thật từ máy developer trước khi set fake secrets. Điều này tránh leak API key thật (như RUNPOD_API_KEY, SALAD_API_KEY) khi postinstall exfiltrate toàn bộ env vars.

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

### Các IOC được monitor

| IOC | Mô tả | Phương pháp |
|-----|--------|-------------|
| **IOC-1** | Postinstall script truy cập env vars nhạy cảm | Static analysis: scan node_modules |
| **IOC-2** | node.exe tạo outbound connection bất thường | `netstat -nob` (Admin) hoặc `Get-NetTCPConnection` (fallback, không cần Admin) |
| **IOC-3** | Build artifact bị tamper | Integrity check: SHA-256 hash (tự loại file không phải build output) |

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

### Cách 2: Safe npm install (phòng ngừa)

Thay vì `npm install` bình thường, dùng detector:

```powershell
node detector\detect-supply-chain.js safe-install .\consumer-app
```

Flow:
1. `npm install --ignore-scripts` (tải về nhưng KHÔNG chạy postinstall)
2. Scan tất cả lifecycle scripts → phát hiện suspicious patterns
3. Nếu clean → tự động chạy `npm rebuild`
4. Nếu suspicious → DỪNG, báo alert, chờ user review

### Cách 3: Continuous monitoring

```powershell
node detector\detect-supply-chain.js watch artifacts
```

Mỗi 5 giây kiểm tra network connections + artifact integrity.

### Cách 4: Chỉ scan postinstall

```powershell
node detector\detect-supply-chain.js scan .\consumer-app\node_modules
```

### Cách 5: Artifact integrity

```powershell
# Trước attack — lưu baseline
node detector\detect-supply-chain.js baseline artifacts

# Sau attack — kiểm tra thay đổi
node detector\detect-supply-chain.js verify artifacts
```

---

## Demo Workflow Hoàn Chỉnh (A → B → C)

### Thứ tự chạy demo cho reviewer/giảng viên:

```
Terminal 1 (Attack):      .\scripts\run-malicious-ci-simulation.ps1
                          → Verdaccio + Attacker receiver tự start (Docker)
                          → Receiver nhận secrets (Phần A ✓)
                          → Xem log: docker logs attacker-receiver

Terminal 2 (AV Test):     .\scripts\test-av-bypass.ps1   [Run as Admin]
                          → Defender không phát hiện (Phần B ✓)

Terminal 1 (Detector):    node detector\detect-supply-chain.js full . artifacts
                          → Detector phát hiện 3 IOCs (Phần C ✓)
```

### Timeline:

```
[T=0]   Docker start: Verdaccio + Attacker receiver  │ docker compose up
[T=1]   Malicious package publish lên Verdaccio       │ Terminal 1
[T=2]   CI env vars cleanup + set fake secrets         │ Terminal 1
[T=3]   npm install → secrets gửi qua Docker network   │ Host → 172.30.0.20
[T=4]   Artifact bị poison, confirm qua Docker network │ Host → 172.30.0.20
[T=5]   Defender scan → bypass confirmed               │ Terminal 2
[T=6]   Detector scan → 3 ALERTs                       │ Terminal 1
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
