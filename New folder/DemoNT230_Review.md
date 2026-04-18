# ĐÁNH GIÁ KHẮT KHE: demont230.docx — Demo Re-run Sau Khi Sửa Code

**Ngày đánh giá:** 2026-04-17  
**Tài liệu:** demont230.docx (25 ảnh, ~2084 ký tự text)  
**Ngữ cảnh:** Đây là lần chạy demo lại sau khi đã sửa 6 lỗi từ bài review CI.docx trước đó.

---

## I. TỔNG QUAN

Tài liệu trình bày lại demo PoC Supply Chain Attack gồm 3 phần:
- **Phần A**: PoC tấn công supply chain qua npm
- **Phần B**: Bypass Windows Defender
- **Phần C**: Detector (IOC detection) — nhiều chế độ

**Định dạng:** Vẫn là screenshot walkthrough với caption ngắn, không có phân tích kỹ thuật dạng văn bản.

---

## II. KIỂM TRA CÁC LỖI ĐÃ SỬA (từ review trước)

### ✅ Lỗi 1: Credential Leak — ĐÃ SỬA
- **Ảnh 8**: Hiển thị rõ `Removed: GIT_ASKPASS, RUNPOD_API_KEY, SALAD_API_KEY, VSCODE_GIT_ASKPASS_*`
- Script đã xoá biến thật trước khi set biến giả
- **Verdict: PASS**

### ✅ Lỗi 2: IOC-2 Fallback — ĐÃ SỬA
- **Ảnh 20, 25**: `[WARN] netstat -nob failed (need Admin)` → `Falling back to PowerShell Get-NetTCPConnection (no Admin required)...`
- Không còn crash khi chạy non-Admin
- **Verdict: PASS**

### ✅ Lỗi 3: AV Scan Timing — ĐÃ SỬA
- **Ảnh 15**: `Scan completed in 30.7s (incl. 30s wait)` — không còn 0.8s giả tạo
- **Ảnh 18**: Report file xác nhận Duration: 30.7s
- 2 Defender events after scan start — có bằng chứng Defender thực sự quét
- **Verdict: PASS**

### ✅ Lỗi 4: AMSI Analysis — ĐÃ SỬA
- **Ảnh 16**: Phân tích bypass đầy đủ 6 yếu tố + mục 7 "AMSI — LÝ DO CỐT LỖI"
- **Ảnh 17**: Bảng so sánh AMSI integration giữa 5 runtime (PowerShell/CLR/WSH/Python/Node.js)
- Kết luận rõ ràng: V8 không gọi AmsiScanBuffer → bypass tự nhiên
- **Verdict: PASS**

### ✅ Lỗi 5: IOC-3 False Positive — ĐÃ SỬA
- **Ảnh 20**: IOC-3 chỉ check `build-output.txt` và `ci-injected-marker.txt`, không còn flag `av-bypass-report.txt`
- **Verdict: PASS**

### ⚠️ Lỗi 6: Compromised CI Pipeline — KHÔNG THẤY DEMO
- Không có ảnh nào chạy `.gitlab-ci.compromised.yml` hoặc so sánh clean vs compromised pipeline
- File `.gitlab-ci.compromised.yml` đã tạo nhưng **không xuất hiện trong demo**
- **Verdict: PARTIAL — file tồn tại nhưng thiếu minh chứng trong demo**

### ✅ Network Separation — ĐÃ SỬA
- **Ảnh 7**: `Network: Victim (host) → Attacker (172.30.0.20, Docker bridge)` — hiển thị rõ
- **Ảnh 10**: Beacon từ IP `172.30.0.1` (Docker gateway) — KHÔNG phải 127.0.0.1
- **Ảnh 11**: File loot tên `beacon_..._172.30.0.1.json` — xác nhận traffic qua Docker bridge
- **Verdict: PASS**

---

## III. VẤN ĐỀ MỚI PHÁT HIỆN

### 🔴 Vấn đề 1: npm publish thất bại (NGHIÊM TRỌNG)
- **Ảnh 8**: `npm error: cannot publish over previously published versions: 1.0.1`
- Script vẫn in `Malicious package published to Verdaccio!` — **output sai lệch**
- Package 1.0.1 đã tồn tại từ lần chạy trước → lần này KHÔNG publish lại
- **Hệ quả:** npm install dùng package cũ từ cache/registry, không phải package vừa build. Demo vẫn chạy vì package cũ vẫn có malicious postinstall, nhưng đây là bằng chứng thiếu idempotency
- **Fix:** Tăng version tự động (semver patch++) hoặc `npm unpublish` trước khi publish

### 🟡 Vấn đề 2: Docker logs chỉ có BEACON, thiếu CI SECRETS + ARTIFACT
- **Ảnh 10**: Chỉ thấy `SECOND-STAGE BEACON from 172.30.0.1`
- **KHÔNG thấy** `CI SECRETS RECEIVED` và `ARTIFACT POISONED` 
- **Ảnh 11**: Chỉ có 1 file loot (beacon, 177 bytes) — không có secrets hay artifact loot
- **Khả năng:** Beacon gửi thành công nhưng secrets exfiltration + artifact confirm có thể đã fail
- Đây là điểm yếu lớn: demo chỉ chứng minh beacon về được Docker, nhưng **dữ liệu bị đánh cắp ở đâu?**

### 🟡 Vấn đề 3: IOC-3 không phát hiện artifact tampering
- **Ảnh 8 Step 4**: Tạo baseline (hash artifacts)
- **Ảnh 8 Step 6**: Artifact poisoning done
- **Ảnh 20**: IOC-3 check → "All artifacts pass integrity check" — **KO phát hiện thay đổi**
- **Ảnh 12**: `build-output.txt` chỉ chứa "clean build output" + timestamp — **không có dấu hiệu bị inject**
- **Kết luận:** Artifact poisoning có thể đã KHÔNG thực sự modify file, hoặc baseline bị tạo SAU khi poisoning
- Đây phá vỡ narrative "attack → detect" — detector nói sạch khi lẽ ra phải có alert

### 🟡 Vấn đề 4: IOC-1 chạy full scan nhưng không tìm thấy node_modules
- **Ảnh 20**: `[WARN] [IOC-1] node_modules not found: node_modules`
- Chạy `detect-supply-chain.js full . artifacts` từ project root → không có `node_modules` ở root
- `consumer-app/node_modules` mới là đúng → ảnh 23-24 scan riêng mới phát hiện 4-7 alerts
- Demo flow không mạch lạc: chạy full scan → 0 alerts → rồi chạy riêng → có alerts. Giám khảo sẽ hỏi **tại sao full scan không phát hiện?**

### 🟢 Điểm tích cực mới: Detector nhiều chế độ
- **Ảnh 23**: `scan .\consumer-app\node_modules` → 4 ALERTS (process.env, credentials keywords, require("http"))
- **Ảnh 24**: `safe-install .\consumer-app` → 7 ALERTS + "Lifecycle scripts were NOT executed"
- **Ảnh 25**: `watch artifacts` → continuous monitoring IOC-2 + IOC-3
- **Ảnh 21-22**: `baseline artifacts` + `verify artifacts` — workflow rõ ràng
- Đây là cải thiện đáng kể so với bản cũ

---

## IV. VẤN ĐỀ HÌNH THỨC & NỘI DUNG

### 🔴 Text vẫn quá ít (~2084 ký tự)
- Toàn bộ nội dung chỉ là caption ngắn kiểu "Giải thích: dựng container nền..."
- **Không có:**
  - Phân tích kỹ thuật về cách tấn công hoạt động
  - Giải thích tại sao Defender bypass (text, không phải ảnh)
  - So sánh trước/sau khi fix
  - Bảng tóm tắt kết quả
  - Kết luận / lessons learned
- Nếu đây là báo cáo nộp, nó giống **lab notebook** hơn là **technical report**

### 🟡 Thứ tự demo thiếu logic
1. Chạy attack (Part A) → docker logs chỉ có beacon
2. xem artifact → không thấy bị thay đổi
3. Chạy AV bypass test (Part B) — xong phần B xong mới sang C
4. Full scan IOC → "no alerts" (vì node_modules sai đường dẫn)
5. Rồi mới scan đúng consumer-app → có alerts

Thứ tự hợp lý hơn: A (attack) → C (detect ngay sau attack, thấy alerts) → B (AV bypass giải thích tại sao AV miss)

### 🟡 Thiếu ảnh so sánh trước/sau
- Không có ảnh chạy detector TRƯỚC attack (baseline clean scan)
- Không có ảnh artifact bị modified vs artifact gốc
- Không có ảnh `.gitlab-ci.compromised.yml` so với `.gitlab-ci.yml`

---

## V. CHẤM ĐIỂM

| Tiêu chí | Điểm trước (CI.docx) | Điểm hiện tại | Ghi chú |
|---|---|---|---|
| **A. PoC Attack** | 6/10 | 7/10 | Network separation tốt, nhưng npm publish fail + thiếu secrets exfil evidence |
| **B. AV Bypass** | 5/10 | 8.5/10 | Cải thiện lớn nhất: 30s scan, AMSI table, Defender events |
| **C. Detector** | 6/10 | 7.5/10 | Nhiều mode tốt (scan/safe-install/watch/verify), nhưng full scan fail logic |
| **Hình thức** | 4/10 | 4.5/10 | Vẫn chỉ là screenshot dump, text quá ít |
| **Tính chặt chẽ** | 5/10 | 6/10 | npm publish error output sai, artifact poisoning evidence thiếu |

### **TỔNG ĐIỂM: 6.7/10** (trước: 6.0/10)

---

## VI. DANH SÁCH FIX CẦN LÀM (ưu tiên cao → thấp)

### Ưu tiên 1 — Fix ngay trước khi nộp
1. **Fix npm publish idempotency**: Thêm logic bump version hoặc unpublish trước publish
2. **Chạy lại demo với version mới** → lần này phải có CI SECRETS + ARTIFACT POISON trong docker logs
3. **Fix full scan path**: Chạy `detect-supply-chain.js full ./consumer-app artifacts` thay vì `full . artifacts`

### Ưu tiên 2 — Cải thiện nội dung
4. **Thêm ảnh artifact bị modify**: `Get-Content build-output.txt` sau step 6 → phải thấy payload injected
5. **Thêm ảnh detector phát hiện artifact tampering**: Verify hash mismatch
6. **Chạy detector TRƯỚC attack**: Chứng minh baseline sạch → sau attack → có alert

### Ưu tiên 3 — Nâng hình thức
7. **Viết phân tích text** giữa các ảnh (tối thiểu 1-2 đoạn mỗi phần A/B/C)
8. **Thêm bảng tóm tắt kết quả** đầu hoặc cuối mỗi phần
9. **Thêm phần kết luận** tổng hợp 3 phần

---

## VII. KẾT LUẬN

**Cải thiện đáng kể** so với bản CI.docx — đặc biệt AV bypass (AMSI analysis, 30s scan) và detector (multiple modes, fallback). Network separation qua Docker bridge là bước tiến quan trọng.

**Tuy nhiên**, demo vẫn có lỗ hổng logic nghiêm trọng:
- npm publish fail nhưng script vẫn báo thành công
- Không có bằng chứng secrets bị exfiltrate (chỉ có beacon)
- Artifact poisoning không có bằng chứng thực sự xảy ra
- Full scan detector nói "clean" vì quét sai thư mục

**Nếu giám khảo hỏi:** "Dữ liệu bị đánh cắp thực sự ở đâu?" hoặc "Full scan nói sạch, vậy detector có hoạt động không?" — sẽ khó trả lời với evidence hiện có.

**Khuyến nghị:** Chạy lại demo MỘT LẦN NỮA sau khi fix npm publish + full scan path, bổ sung ảnh evidence cho secrets exfil + artifact tampering. Viết thêm text phân tích. Có thể nâng lên 8.0+ với effort không nhiều.
