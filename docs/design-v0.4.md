# RouterTop 0.4 設計與可及性記錄

本版依使用者指定，將深色管理介面改為受 macOS「系統設定」啟發的淺色介面。RouterTop 保留自己的名稱與 RT 標誌，沒有使用 Apple 圖像、商標、外部字型、CDN 或前端框架。

## 設計依據與實作

本次已讀 `design-skills-router`、`visual-design-foundations` 與 `web-accessibility-design` 技能；依序處理資訊群組、視覺層級、色彩與可操作性。

- **相關設定分組、導覽位置固定**：左側依功能排列，右側為白色分組面板；目前分頁有文字、選取背景與 `aria-current`，頁面標題也同步更新。參考 [Apple HIG Settings](https://developer.apple.com/design/human-interface-guidelines/settings)。
- **顏色有明確用途**：淺灰背景與側欄承載結構，白色面板承載欄位，藍色表示主要操作與選取。錯誤、未套用與停用都保留文字，避免只靠顏色辨識。參考 [Apple HIG Color](https://developer.apple.com/design/human-interface-guidelines/color)。
- **一致排版**：單一系統字型堆疊 `-apple-system, BlinkMacSystemFont, Segoe UI, Microsoft JhengHei, sans-serif`；主體 14px、群組標題 18px、頁面標題 28px（手機 24px），輔助文字最低 12px；間距以 8/16/24/32px 為主。刪除原有英文裝飾標語與網路裝飾圖。
- **控制目標與焦點**：主要按鈕與輸入高度 40px；次要操作最低 32px；核取方塊 24×24px；焦點使用 3px 藍色外框。`dialog` 搭配明確首尾 Tab／Shift+Tab 循環與原生 Escape；排序提供上移／下移按鈕。登入與主介面皆有跳到主要內容連結。參考 [WCAG 2.5.8](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)。
- **響應式**：桌面為側欄與內容區；850px 以下導覽轉為上方網格，560px 以下欄位單欄，操作按鈕自動換列。沒有固定浮動儲存列遮住鍵盤焦點。
- **狀態與安全語意**：明確區分草稿、持久儲存與待重啟。WireGuard 僅顯示公鑰。IPv6 說明靜態 WAN 與不支援 DHCPv6-PD；主控台驗證必要且與 Web 共用 admin 密碼，沒有關閉驗證的控制。

這是網頁設定介面的設計轉譯，不宣稱完全符合 macOS 原生介面規範，也沒有仿造視窗關閉等無實際作用的控制。

## 對比實測

2026-10-24，以實際 CSS 色票和 WCAG sRGB 相對亮度公式計算，非目測估計。公式為 `(較亮相對亮度 + 0.05) / (較暗相對亮度 + 0.05)`；比值於通過判斷後才四捨五入。依據 [WCAG 1.4.3](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html)。

| 用途 | 前景／背景 | 比值 | 結果 |
|---|---|---:|---|
| 主要文字／白色面板 | `#1d1d1f` / `#ffffff` | 16.83:1 | PASS ≥4.5 |
| 輔助文字／白色面板 | `#606064` / `#ffffff` | 6.26:1 | PASS ≥4.5 |
| 輔助文字／側欄 | `#606064` / `#ededf0` | 5.36:1 | PASS ≥4.5 |
| 主要按鈕及選取文字 | `#ffffff` / `#0064d9` | 5.49:1 | PASS ≥4.5 |
| 資訊狀態 | `#174d8f` / `#edf4ff` | 7.61:1 | PASS ≥4.5 |
| 待重啟提示 | `#714400` / `#fff4d6` | 7.58:1 | PASS ≥4.5 |
| 錯誤提示 | `#9f242d` / `#fff0f0` | 6.86:1 | PASS ≥4.5 |
| 欄位提示文字 | `#68686e` / `#ffffff` | 5.54:1 | PASS ≥4.5 |
| 輸入邊界 | `#85858b` / `#ffffff` | 3.67:1 | PASS ≥3，非文字 |
| 焦點外框／內容背景 | `#005fcc` / `#f5f5f7` | 5.50:1 | PASS ≥3，非文字 |

細分隔線為群組裝飾，不作為唯一可操作邊界；可操作輸入與次要按鈕另有較深邊界。停用控制保留原生 disabled 語意，其外觀不列為文字對比驗收的啟用控制。

## 驗證分層

- **PASS**：CSS 色票計算、JavaScript 語法與欄位結構檢查。
- **PASS（整合驗收）**：真實 Chrome 與最終 0.4 ISO 的 12 組操作、18 個樣式檢查通過，含鍵盤對話框、對比／目標、390px 版面、IPv6／全通道保存、重啟與 UEFI 冷開。見 [實際報告](../evidence/v04/browser/browser-v04-report.json)。
- **NOT_RUN**：完整螢幕閱讀器測試；不以這些檢查宣稱整站 WCAG 認證。網路封包結果獨立記錄於 [驗收紀錄](acceptance-v0.4.md)。

靜態設計檢查不能證明 IPv6 轉送、WireGuard 握手或斷線防洩漏；這些由獨立網路驗收處理。
