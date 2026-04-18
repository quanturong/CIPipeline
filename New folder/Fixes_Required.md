# ĐIỂM YẾU & CÁCH KHẮC PHỤC — demovippro.docx

> Sắp xếp theo mức độ ảnh hưởng đến điểm kỹ thuật (cao → thấp)

---

## 🔴 MỨC ĐỘ CAO — Fix trước khi demo

---

### [FIX-1] IOC-2 không bao giờ phát hiện gì
**Vấn đề:**  
IOC-2 dùng `netstat` / `Get-NetTCPConnection` để tìm connection từ `node.exe`. Nhưng postinstall script chỉ gửi 1 HTTP POST duy nhất (~100ms) rồi thoát — khi IOC-2 chạy thì `node.exe` đã chết từ lâu. 7/7 lần check đều "No suspicious". IOC-2 hiện tại vô dụng với attack vector này.

**Khắc phục — Thêm `monitor-install` mode vào detector:**  
Spawn `npm install` như child process, poll `Get-NetTCPConnection` mỗi 200ms TRONG KHI npm đang chạy.

```js
// Thêm vào detect-supply-chain.js, mode: 'monitor-install'
const { spawn } = require('child_process');

async function monitorInstall(appDir) {
  console.log('[IOC-2-LIVE] Spawning npm install with network monitoring...');
  
  const child = spawn('npm', ['install'], {
    cwd: path.resolve(appDir),
    shell: true,
    stdio: 'pipe'
  });

  const pollInterval = setInterval(async () => {
    const conns = await checkNodeConnections(); // hàm IOC-2 hiện tại
    if (conns.suspicious.length > 0) {
      console.log(`[ALERT] [IOC-2-LIVE] OUTBOUND detected: ${JSON.stringify(conns.suspicious)}`);
    }
  }, 200);

  return new Promise((resolve) => {
    child.on('close', (code) => {
      clearInterval(pollInterval);
      console.log(`[IOC-2-LIVE] npm install exited (code ${code}). Monitoring stopped.`);
      resolve();
    });
  });
}
```

**Dùng trong demo:**
```powershell
node .\detector\detect-supply-chain.js monitor-install .\consumer-app
```

**Kết quả kỳ vọng:**  
`[ALERT] [IOC-2-LIVE] OUTBOUND detected: [{"localPort":xxxxx,"remoteAddress":"172.30.0.20","remotePort":8080,"process":"node.exe"}]`

**Effort:** ~1-2 giờ | **Impact:** +0.5 điểm C

---

### [FIX-2] Hash baseline không nhất quán (ảnh từ nhiều session)
**Vấn đề:**  
- Ảnh 18 (full scan): baseline = `8b5437...` (55 bytes)
- Ảnh 19 (re-baseline): `f1053c...`
- Ảnh 20 (verify): baseline = `22786e...`  

3 hash khác nhau cho cùng `build-output.txt` ban đầu → giám khảo tinh ý nhận ra ảnh ghép từ nhiều lần chạy.

**Khắc phục:**  
Chạy lại toàn bộ Part C trong **1 session duy nhất** theo đúng thứ tự:
```
1. Reset state: xóa node_modules, artifacts về state sạch
2. node detector full . artifacts           → 0 alerts (clean)   [ảnh trước attack]
3. npm install                              → attack xảy ra
4. node detector full . artifacts           → 5 alerts TAMPERED  [ảnh sau attack]  
5. node detector baseline artifacts         → re-baseline (poisoned state)
6. node detector verify artifacts           → confirm TAMPERED
7. node detector scan .\consumer-app\node_modules
8. node detector safe-install .\consumer-app
9. node detector watch artifacts            → (vài cycle)
```

Tất cả hash trong cùng session → nhất quán.

**Effort:** ~30 phút chạy lại | **Impact:** +0.3 điểm chặt chẽ

---

### [FIX-3] Thiếu clean scan TRƯỚC attack (contrast before/after)
**Vấn đề:**  
Demo hiện tại chỉ thấy sau attack có alerts. Không có ảnh "trước attack = 0 alerts" để contrast. Giám khảo không thấy rõ detector BẮT được attack, chỉ thấy nó scan sau khi đã biết có attack.

**Khắc phục:**  
Thêm 1 bước vào đầu Part C (thực hiện trong fix FIX-2 luôn):
```powershell
# Trước khi chạy npm install
node .\detector\detect-supply-chain.js full . artifacts
# → Kết quả: [RESULT] No alerts. System appears clean.
```
Chụp ảnh output này → đây là "state sạch".  
Sau đó chạy attack → chụp lại full scan → 5 ALERTS.  
Hai ảnh đặt cạnh nhau = contrast mạnh nhất trong toàn bộ demo.

**Effort:** 10 phút | **Impact:** +0.4 điểm C

---

## 🟡 MỨC ĐỘ TRUNG BÌNH — Nên làm nếu còn thời gian

---

### [FIX-4] Verify chạy sau re-baseline → logic confusing
**Vấn đề:**  
Thứ tự hiện tại: attack → full scan (TAMPERED) → **re-baseline** → verify (TAMPERED).  
Re-baseline ở giữa làm người xem mất hướng: đang baseline trạng thái bị poison, rồi verify cũng thấy TAMPERED từ baseline poisoned đó — logic vòng vòng.

**Khắc phục:**  
Đổi thứ tự theo FIX-2: baseline (clean) → attack → full scan → verify → [rồi mới] re-baseline.  
`verify` so với baseline sạch → thấy TAMPERED rõ ràng.  
Re-baseline chỉ chạy **sau** khi đã verify xong để "chấp nhận" trạng thái mới.

**Effort:** 0 phút code, chỉ thay đổi thứ tự demo | **Impact:** +0.3 điểm chặt chẽ

---

### [FIX-5] Watch mode không bắt tamper realtime
**Vấn đề:**  
Watch chạy sau khi re-baseline → mọi cycle đều "All artifacts pass". Demo watch mode mà không có event gì xảy ra thì không ấn tượng.

**Khắc phục (chọn 1 trong 2):**

*Option A — Dễ:* Chạy watch TRONG KHI artifact vẫn là trạng thái bị poison (trước re-baseline). Watch sẽ liên tục báo TAMPERED mỗi 5 giây.

*Option B — Ấn tượng hơn:* Chạy watch, rồi trong terminal khác chạy `node .\inject-malicious-artifact.js` để inject thêm lần nữa → watch bắt realtime trong vài giây.

**Effort:** 5-10 phút | **Impact:** +0.2 điểm C

---

### [FIX-6] Ảnh duplicate trong Part B (bypass analysis + AMSI table xuất hiện 2 lần)
**Vấn đề:**  
- Ảnh 12 ([5/5]) và Ảnh 15 ([1-6]): cùng nội dung bypass analysis  
- Ảnh 13 và Ảnh 16: cùng AMSI table  

4 ảnh → 2 ảnh, tiết kiệm không gian, tránh cảm giác padding.

**Khắc phục:**  
Xóa ảnh 12 và 13 khỏi docx (giữ 15 và 16 vì đầy đủ hơn).

**Effort:** 2 phút | **Impact:** cleaner presentation

---

## 🟢 MỨC ĐỘ THẤP — Nice to have

---

### [FIX-7] Không demo `.gitlab-ci.compromised.yml`
**Vấn đề:** File đã tạo sẵn nhưng không chạy trong demo.

**Khắc phục:**  
Thêm 2 ảnh vào cuối Part A:
```powershell
# So sánh clean vs compromised pipeline
Get-Content .\.gitlab-ci.yml           # normal pipeline
Get-Content .\.gitlab-ci.compromised.yml  # có bước inject thêm
```
Highlight diff để thấy poisoned pipeline khác clean pipeline ở điểm nào.

**Effort:** 5 phút | **Impact:** +0.3 điểm A

---

### [FIX-8] Không có control experiment cho AV bypass
**Vấn đề:**  
Chỉ chứng minh "node.exe bypass được" nhưng không chứng minh "Defender đang thực sự hoạt động". Có thể bị hỏi: "Defender đang bật nhưng biết đâu nó không quét gì cả?"

**Khắc phục:**  
Thêm 1 ảnh chạy EICAR test string để chứng minh Defender hoạt động:
```powershell
# Tạo EICAR test file → Defender phải xóa ngay
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content eicar-test.txt $eicar
Start-Sleep -Milliseconds 500
Test-Path eicar-test.txt  # → False = Defender đã xóa = Defender đang hoạt động
```
Sau đó chạy payload Node.js → không bị xóa → contrast rõ ràng.

**Effort:** 10 phút | **Impact:** +0.3 điểm B

---

## TỔNG KẾT

| Fix | Effort | Impact điểm | Ưu tiên |
|---|---|---|---|
| FIX-1: IOC-2 monitor-install mode | 1-2h | +0.5 C | 🔴 Cao |
| FIX-2: Chạy lại Part C 1 session | 30 phút | +0.3 chặt chẽ | 🔴 Cao |
| FIX-3: Clean scan trước attack | 10 phút | +0.4 C | 🔴 Cao |
| FIX-4: Đổi thứ tự verify | 0 phút | +0.3 chặt chẽ | 🟡 Trung bình |
| FIX-5: Watch mode có event | 10 phút | +0.2 C | 🟡 Trung bình |
| FIX-6: Xóa ảnh duplicate | 2 phút | presentation | 🟡 Trung bình |
| FIX-7: Demo compromised CI | 5 phút | +0.3 A | 🟢 Thấp |
| FIX-8: EICAR control test | 10 phút | +0.3 B | 🟢 Thấp |

**Nếu chỉ làm FIX-1 + FIX-2 + FIX-3 + FIX-4:** Điểm kỹ thuật tăng từ **8.8 → ~9.3/10**  
**Nếu làm tất cả:** ~9.5/10
