# ĐÁNH GIÁ KHẮT KHE: demovippro.docx — Demo Hoàn Chỉnh

**Ngày đánh giá:** 2026-04-17  
**Tài liệu:** demovippro.docx (27 ảnh, ~2934 ký tự text)  
**Ngữ cảnh:** Đây là phiên bản demo thứ 3, sau khi đã sửa toàn bộ lỗi từ CI.docx (6.0/10) và demont230.docx (6.7/10).

---

## I. TỔNG QUAN

Tài liệu trình bày demo PoC Supply Chain Attack theo 3 phần:
- **Phần A** (Ảnh 1–10): PoC tấn công supply chain qua npm — exfiltrate secrets + poison artifact
- **Phần B** (Ảnh 11–17): Bypass Windows Defender + phân tích AMSI
- **Phần C** (Ảnh 18–27): Detector validation — full scan, baseline, verify, scan, safe-install, watch, log collection

**Cải thiện lớn so với demont230.docx:** Tất cả 4 vấn đề nghiêm trọng đã được sửa. Evidence chain giờ hoàn chỉnh từ attack → loot → detection.

---

## II. KIỂM TRA CÁC LỖI TỪ REVIEW TRƯỚC

### ✅ Lỗi cũ 1: npm publish conflict — ĐÃ SỬA (XUẤT SẮC)
- **Ảnh 3**: Publish `@demo/safe-marker-package@1.0.1776449936` — **version có timestamp**
- Không còn lỗi `cannot publish over previously published versions`
- Giải pháp đúng: epoch-based versioning đảm bảo idempotency
- **Verdict: PASS — đây là fix tốt nhất trong toàn bộ bản cập nhật**

### ✅ Lỗi cũ 2: Docker logs thiếu secrets + artifact — ĐÃ SỬA
- **Ảnh 10**: Docker logs hiển thị RÕ RÀNG cả hai:
  - `═══ CI SECRETS RECEIVED from 172.30.0.1 ═══` với 5 secrets đánh dấu `◄ HIGH VALUE`
  - `═══ ARTIFACT POISONED — confirmed from 172.30.0.1 ═══`
- **Ảnh 6**: 2 file loot: `secrets_*.json` (807 bytes) + `poison_confirm_*.json` (283 bytes)
- Trước đó chỉ có 1 file beacon → giờ có đủ 2 evidence file
- **Verdict: PASS — evidence chain hoàn chỉnh**

### ✅ Lỗi cũ 3: Artifact poisoning không có bằng chứng — ĐÃ SỬA
- **Ảnh 9**: `Select-String` tìm thấy `INJECTED BY SUPPLY CHAIN` + `artifact_poisoning_confirmed` trong build-output.txt
- **Ảnh 9**: `Get-Content build-output.txt -Tail 20` hiển thị payload inject: `eval(Buffer.from(arguments[0],'base64').toString())`
- **Ảnh 8**: Poison confirm JSON: `{"event":"artifact_poisoned","status":"poisoned","file":"build-output.txt"}`
- **Verdict: PASS — bằng chứng trực quan mạnh**

### ✅ Lỗi cũ 4: Full scan quét sai đường dẫn — ĐÃ SỬA
- **Ảnh 18**: `node .\detector\detect-supply-chain.js full . artifacts`
- IOC-1 log: `Scanning postinstall scripts in: consumer-app\node_modules` — **tự resolve đúng thư mục**
- Không còn `[WARN] node_modules not found: node_modules`
- RESULT: 5 ALERTS detected — gồm cả IOC-1 (3 alerts) + IOC-3 (2 alerts: TAMPERED + NEW FILE)
- **Verdict: PASS — full scan giờ hoạt động đúng từ project root**

### ✅ Các fix trước vẫn giữ nguyên:
- **Credential cleanup**: Ảnh 4 — `Removed: GIT_ASKPASS, RUNPOD_API_KEY, SALAD_API_KEY, VSCODE_GIT_ASKPASS_*`
- **IOC-2 fallback**: Ảnh 18, 23 — `netstat -nob failed → Falling back to PowerShell Get-NetTCPConnection`
- **AV scan 30s**: Ảnh 11 — `30.6s (incl. 30s wait)`
- **AMSI analysis**: Ảnh 15–16 — bảng 5 runtime, V8 = KHÔNG có AMSI
- **Network separation**: Ảnh 3 — `172.30.0.20, Docker bridge`, Ảnh 10 — traffic từ `172.30.0.1`

---

## III. PHÂN TÍCH CHI TIẾT TỪNG PHẦN

### A. PoC Supply Chain Attack (Ảnh 1–10) — 9.0/10

**Điểm mạnh:**
- **Flow hoàn chỉnh 7 bước**: Docker check → publish → credential cleanup → baseline → npm install → artifact poison → evidence summary
- **Evidence summary tự động** (Ảnh 4): `secrets exfil files = 1, artifact poison confirmations = 1, build-output poisoned marker = True` — 3/3 confidence indicators
- **Loot verification** (Ảnh 6–8): Cả secrets JSON (807 bytes) và poison confirm JSON (283 bytes) đều hiện rõ nội dung
- **Secrets JSON chi tiết** (Ảnh 7): Context đầy đủ (hostname, CI project, CI job) + 5 fake secrets (AWS, CI_JOB_TOKEN, DEPLOY_KEY, GITHUB_TOKEN, NPM_TOKEN)
- **Artifact payload rõ ràng** (Ảnh 9): Base64 payload + eval injection trong build-output.txt — giám khảo thấy ngay payload thực tế
- **Docker logs đẹp** (Ảnh 10): Output format professional với borders, color-coded, HIGH VALUE markers

**Điểm yếu nhỏ:**
- Vẫn không demo `.gitlab-ci.compromised.yml` — nhưng đây là phụ, không ảnh hưởng core narrative
- Ảnh 5 (screen DONE) có phần thừa — thông tin đã có ở ảnh 4

### B. Windows Defender Bypass (Ảnh 11–17) — 9.0/10

**Điểm mạnh:**
- **Defender status đầy đủ** (Ảnh 11): Real-time, Behavior, IOAV, On Access all True, signature ver 1.449.152.0
- **Scan duration chính xác**: 30.6s — Defender thực sự quét
- **Phân tích bypass 7 lý do** (Ảnh 15): Trusted Process, No Binary, No Suspicious API, Legitimate Traffic, Fail-silent, File Append, AMSI
- **AMSI table xuất sắc** (Ảnh 16): So sánh 5 runtime (PowerShell/CLR/WSH/Python/Node.js V8) — dễ hiểu, dễ trình bày
- **Kết luận rõ ràng**: "Bypass nhờ ĐẶC ĐIỂM TỰ NHIÊN của Node.js ecosystem (V8 không AMSI), KHÔNG phải anti-AV chủ động"
- **AV report file** (Ảnh 14): Structured report với SHA256 hashes, scan timing, system info
- **Get-MpThreatDetection** (Ảnh 17): Bảng trống → xác nhận ở cấp hệ thống Defender không phát hiện gì

**Điểm yếu nhỏ:**
- Ảnh 12 (bypass [5/5]) và ảnh 15 (bypass [1-6]) có overlap content — có thể gộp
- Ảnh 13 và ảnh 16 cũng hơi trùng (AMSI table xuất hiện 2 lần)

### C. Detector Validation (Ảnh 18–27) — 8.5/10

**Điểm mạnh:**
- **Full scan hoạt động đúng** (Ảnh 18): 
  - IOC-1: Tìm `@demo/safe-marker-package` trong `consumer-app\node_modules` → 3 SUSPICIOUS (process.env, TOKEN/SECRET/KEY, require("http"))
  - IOC-2: Fallback to PowerShell → "No suspicious outbound" (expected — attack đã kết thúc)
  - IOC-3: **TAMPERED: "build-output.txt" hash changed!** (Baseline: 8b5437... 55 bytes → Current: f1053c... 336 bytes) + **NEW FILE: "ci-injected-marker.txt" appeared**
  - 5 ALERTS total — impressive
- **Baseline workflow** (Ảnh 19): Clean baseline creation + hash saved
- **Verify phát hiện tampering** (Ảnh 20): TAMPERED alert + NEW FILE warning → 1 ALERT
- **Standalone IOC-1 scan** (Ảnh 21): 4 alerts from `consumer-app\node_modules`
- **Safe-install chặn script** (Ảnh 22): `npm install --ignore-scripts` → scan → **"Lifecycle scripts were NOT executed"** → 7 ALERTS. Đây là demo phòng ngừa tốt nhất
- **Watch mode** (Ảnh 23): Continuous monitoring 5000ms interval, IOC-2 + IOC-3
- **Full detector log** (Ảnh 24–27): `Get-Content detector-alerts.log` — toàn bộ timeline từ baseline → full scan → verify → scan → safe-install → watch. Bằng chứng text cho phụ lục báo cáo

**Điểm yếu:**

1. **IOC-2 không bao giờ phát hiện gì** — Mọi lần check đều "No suspicious outbound connections from node.exe." Đây là hạn chế thiết kế: attacker dùng one-shot HTTP POST trong postinstall, không có persistent connection. IOC-2 chỉ hữu ích nếu có reverse shell hoặc beacon liên tục. Demo nên ghi chú giới hạn này.

2. **Watch mode chỉ thấy clean** — Ảnh 23: Mọi cycle đều "All artifacts pass integrity check." Vì baseline đã re-create sau attack, watch monitor state sạch. Lý tưởng hơn: chạy watch TRƯỚC attack → thấy nó catch realtime. Nhưng architecture hiện tại không hỗ trợ attack-during-watch dễ dàng.

3. **Hash baseline không nhất quán giữa các ảnh** — Ảnh 18 (full scan) baseline = `8b5437...`, Ảnh 19 (re-baseline) = `f1053c...`, Ảnh 20 (verify) baseline = `22786e...`. Ba hash khác nhau cho cùng file ban đầu. Cho thấy demo chạy nhiều lần với state khác nhau và ảnh ghép từ nhiều session. Không ảnh hưởng tính đúng đắn nhưng giám khảo tinh ý sẽ nhận ra.

4. **Verify nên chạy SAU full scan, không sau re-baseline** — Flow logic hơn: baseline (clean) → attack → full scan (thấy TAMPERED) → verify (confirm TAMPERED). Hiện tại demo chạy: attack → full scan → re-baseline → verify → thấy TAMPERED. Chuỗi này hơi confusing vì re-baseline ở giữa.

---

## IV. VẤN ĐỀ HÌNH THỨC & NỘI DUNG

### 🟡 Text tốt hơn nhưng vẫn chưa đủ (2934 ký tự)
- Có cải thiện: mỗi bước đều có "Giải thích:" với nội dung giải thích
- Structured theo A/B/C rõ ràng
- **Tuy nhiên vẫn thiếu:**
  - Đoạn mở đầu tổng quan về supply chain attack
  - Phân tích kỹ thuật dạng văn bản (không chỉ caption)
  - Bảng tóm tắt kết quả cuối mỗi phần
  - Phần kết luận tổng hợp
  - So sánh trước/sau sửa
  - References (MITRE ATT&CK, CWE, CVE tương tự)

### 🟢 Trình tự demo hợp lý
- A (attack) → chứng minh attack chạy thành công
- B (AV bypass) → giải thích tại sao AV không bắt
- C (detector) → demo tool phát hiện + phòng ngừa
- Thứ tự này có logic narrative tốt hơn bản trước

### 🟢 Ảnh chụp chất lượng cao hơn
- Output rõ ràng, font size đọc được
- Mỗi ảnh tập trung vào 1 mục đích
- Tuy nhiên 27 ảnh hơi nhiều — ảnh 24-27 (detector log) có thể gộp thành 1-2 ảnh

---

## V. SO SÁNH VỚI CÁC BẢN TRƯỚC

| Vấn đề | CI.docx (6.0) | demont230.docx (6.7) | demovippro.docx |
|---|---|---|---|
| npm publish | N/A | ❌ Version conflict | ✅ Timestamp version |
| Secrets exfil evidence | ❌ Không có | ❌ Chỉ beacon | ✅ Full secrets JSON + docker logs |
| Artifact poison evidence | ❌ Không có | ❌ Không thấy modify | ✅ Base64 payload + poison confirm |
| Full scan path | N/A | ❌ node_modules not found | ✅ Auto-resolve consumer-app |
| Credential leak | ❌ Leak thật | ✅ Cleanup | ✅ Cleanup |
| IOC-2 crash | ❌ Crash | ✅ Fallback | ✅ Fallback |
| AV scan timing | ❌ 0.8s giả | ✅ 30.7s | ✅ 30.6s |
| AMSI analysis | ❌ Không có | ✅ Full table | ✅ Full table |
| IOC-3 false positive | ❌ Flag report.txt | ✅ Fixed | ✅ Fixed |
| Detector artifact detect | N/A | ❌ "All pass" | ✅ TAMPERED + NEW FILE |
| Network separation | ❌ localhost | ✅ Docker bridge | ✅ Docker bridge |

---

## VI. CHẤM ĐIỂM (CHỈ KỸ THUẬT — bỏ qua hình thức/text vì đây là bản khái quát)

| Tiêu chí | Trọng số | CI.docx | demont230.docx | demovippro.docx | Ghi chú |
|---|---|---|---|---|---|
| **A. PoC Attack** | 35% | 6/10 | 7/10 | **9.0/10** | Publish idempotent, full evidence chain, docker logs complete |
| **B. AV Bypass** | 25% | 5/10 | 8.5/10 | **9.0/10** | 30s scan, AMSI table, Get-MpThreatDetection, 7-point analysis |
| **C. Detector** | 30% | 6/10 | 7.5/10 | **8.5/10** | Full scan resolve đúng, verify TAMPERED, safe-install blocks. IOC-2 hạn chế |
| **Tính chặt chẽ kỹ thuật** | 10% | 5/10 | 6/10 | **8.5/10** | Evidence chain liền mạch, không output sai lệch, hash verify đúng |

### Chi tiết điểm trừ kỹ thuật:

**A. PoC Attack — 9.0/10** (-1.0)
- -0.3: Không demo `.gitlab-ci.compromised.yml` (có file nhưng không chạy)
- -0.3: Ảnh 5 (DONE screen) thông tin trùng ảnh 4 — không thêm value kỹ thuật
- -0.4: Không show attack execution realtime (npm install → postinstall trigger → HTTP POST) — chỉ thấy kết quả, không thấy quá trình

**B. AV Bypass — 9.0/10** (-1.0)
- -0.3: Ảnh 12+15 và ảnh 13+16 overlap content (bypass analysis + AMSI table xuất hiện 2 lần)
- -0.3: Không so sánh với scenario Defender CÓ phát hiện (ví dụ: chạy EICAR test → Defender bắt → chứng minh Defender đang hoạt động, không chỉ enable)
- -0.4: Chưa thử kịch bản "nếu payload dùng exec()/spawn() thì Defender có bắt không?" — thiếu control experiment

**C. Detector — 8.5/10** (-1.5)
- -0.5: IOC-2 **không bao giờ phát hiện gì** trong toàn bộ demo (7 lần check = 7 lần "No suspicious"). One-shot HTTP POST không tạo persistent connection → IOC-2 về mặt kỹ thuật vô dụng với attack vector này. Không ghi chú limitation
- -0.3: Watch mode chỉ monitor state sạch (baseline đã re-create). Không demo watch bắt tamper realtime
- -0.3: Hash baseline không nhất quán giữa ảnh 18/19/20 (8b5437 vs f1053c vs 22786e) — ảnh từ nhiều session
- -0.4: Thiếu **clean scan trước attack** → full scan sau attack. Contrast before/after sẽ chứng minh detector hoạt động mạnh hơn

**Tính chặt chẽ — 8.5/10** (-1.5)
- -0.5: Hash inconsistency cho thấy ảnh ghép từ ≥2 session khác nhau
- -0.5: Verify (ảnh 20) chạy sau re-baseline (ảnh 19) nhưng vẫn thấy TAMPERED — logic sequence hơi confusing
- -0.5: IOC-2 chiếm ~30% output nhưng 0% detection value — inflates perceived coverage

### **TỔNG ĐIỂM KỸ THUẬT: 8.8/10**

Tính: (9.0×0.35) + (9.0×0.25) + (8.5×0.30) + (8.5×0.10) = 3.15 + 2.25 + 2.55 + 0.85 = **8.80/10**

*(Trước: demont230.docx ~7.2 kỹ thuật, CI.docx ~5.7 kỹ thuật)*

---

## VII. NHỮNG GÌ CÒN THIẾU ĐỂ ĐẠT 9.0+

### Ưu tiên 1 — Nội dung text (dễ làm, impact cao)
1. **Thêm đoạn mở đầu** (200-300 từ): Giải thích supply chain attack là gì, attack vector nào được demo, threat model
2. **Thêm bảng tóm tắt** đầu mỗi phần: "Part A: 7 steps, 3 evidence types, attack time ~10s"
3. **Thêm phần kết luận** (200 từ): Lessons learned, mitigation recommendations, limitations
4. **Thêm references**: MITRE ATT&CK T1195.002, CWE-829, npm advisory examples

### Ưu tiên 2 — Demo flow nhỏ
5. **Ghi chú IOC-2 limitation**: Thêm 1 dòng giải thích tại sao IOC-2 không phát hiện (one-shot attack, no persistent connection)
6. **Gộp ảnh detector log**: Ảnh 24-27 có thể cắt thành 1-2 ảnh highlight chỉ phần quan trọng
7. **Demo watch mode DURING attack**: Nếu kỹ thuật cho phép (chạy watch → trigger install → watch bắt tamper realtime)

### Ưu tiên 3 — Nếu muốn perfect
8. **Demo .gitlab-ci.compromised.yml**: So sánh clean vs compromised pipeline output
9. **Thêm 1 ảnh clean scan TRƯỚC attack**: Chạy full scan khi chưa attack → 0 alerts → rồi attack → 5 alerts. Contrast mạnh hơn
10. **Consistent baseline hashes**: Đảm bảo tất cả ảnh Part C từ cùng 1 session

---

## VIII. KẾT LUẬN

**Bản demo này là bước nhảy vọt** so với 2 bản trước. Mọi vấn đề nghiêm trọng đã được sửa:
- npm publish idempotent qua timestamp versioning
- Evidence chain hoàn chỉnh: secrets exfil → artifact poison → docker logs → loot files → build-output payload
- Full scan detector resolve đúng path và phát hiện cả IOC-1 + IOC-3
- AV bypass analysis professional-grade với AMSI table và Get-MpThreatDetection

**Narrative giờ mạch lạc:** Chạy attack → thấy secrets bị đánh cắp + artifact bị inject → AV không bắt vì V8 không có AMSI → detector bắt được qua static analysis + hash integrity.

**Điểm yếu còn lại** chủ yếu ở hình thức (text ít, thiếu kết luận) và một số chi tiết nhỏ (IOC-2 always empty, watch mode shows clean, hash inconsistency giữa sessions). Không có lỗi logic nghiêm trọng nào.

**Nếu giám khảo hỏi** "Dữ liệu bị đánh cắp ở đâu?" → Trả lời được ngay: Ảnh 6-7-8 (loot files) + Ảnh 10 (docker logs). Đây là cải thiện quan trọng nhất so với bản trước.

**Khuyến nghị cuối:** Dành 30-60 phút viết thêm text phân tích (mở đầu + kết luận + bảng tóm tắt) và gộp 4 ảnh log thành 1-2 ảnh. Có thể đạt 8.5-9.0 dễ dàng mà không cần chạy lại demo.
