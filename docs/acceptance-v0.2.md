# RouterTop 0.2.0 驗收紀錄

日期：2026-10-24（Asia/Taipei）。範圍為設定持久化、管理員登入與 Web 管理。這是 x86_64 開發映像，並非 RouterOS 全功能完成或正式發布。舊版證據保留於 [0.1 驗收](acceptance.md)。

## 程式與協作

- PASS：Windows `cargo test --locked`，8 unit + 2 CLI + 14 Web integration tests；fmt 與 Clippy 無警告。
- PASS：Alpine Linux `cargo test --locked`，8 unit + 2 CLI + 14 Web integration tests，含 Unix 權限檢查；`evidence/v02/linux-final.log`。
- PASS：設定跨執行緒／跨程序 revision 競爭只允許一筆提交；損壞／遺失已初始化資料不會重設管理員；寫入失敗不回報成功。
- PASS：Argon2id、一次性註冊、登入節流、CSRF／Origin／HTTPS、cookie flags、登出與密碼變更撤銷 session。密碼持久更新後即使 runtime 檔案取代失敗，auth_epoch 仍使舊 session 失效。
- PASS（靜態範圍）：[獨立審查及三項修復回驗](review-v0.2.md)。作者使用分開 worktree；Odin 真實 Rust LSP 查詢確認本 workspace 的持久狀態結構，未以靜態分析冒充執行測試。

## 映像與實際操作

| 成品 | 實際大小 |
|---|---:|
| `dist/v0.2/routertop-x86_64.iso` | 65,943,552 bytes / **62.89 MiB** |
| kernel + initramfs | 52,822,623 bytes / **50.38 MiB** |
| Linux Rust binary | 819,840 bytes / **800.63 KiB** |
| Web HTML + CSS + JS | 45,137 bytes / **44.08 KiB** |
| 空白資料磁碟 | 34,603,008 bytes / **33 MiB**（含 32 MiB ext4） |

ISO 比 0.1 增加 1,921,024 bytes / 1.83 MiB；資料卷單獨計算，不含在 ISO。ISO SHA256：`a3201620579b35b4d2b01447db1c78a15e3428644cbc0f08db5a05694b570ace`。Linux binary SHA256：`22d931733aac6f7bfd6cbca830a838ee9b40f6a771835d02a6d576c9cfc79e7e`。

Alpine v3.24，58 個套件，Linux 6.18.58-0-virt、lighttpd 1.4.85、OpenSSL 3.5.9；Alpine Rust 1.96.1 / x86_64-alpine-linux-musl。使用可信 apk keys，版本鎖定記錄於 packages.txt；未宣稱可位元重現或已簽署整個映像。

| 檢查 | 狀態與實際證據 |
|---|---|
| Linux release／映像建置 | PASS；`evidence/v02/linux-final.log`，chroot 執行 binary 成功 |
| 下載完整性 | PASS；host 重算全部原始 SHA256SUMS，與 builder 一致；來源檔雜湊見 artifact-source.log |
| BIOS ISO，256 MiB | PASS；`iso-bios-boot.log` |
| UEFI ISO，256 MiB | PASS；`iso-uefi-boot.log`、`uefi-runtime.log` |
| 真實 Chrome 瀏覽器 | PASS；12 組檢查，`browser-report.json`，含桌面及 390px 手機截圖 |
| 註冊／登入／密碼 | PASS；一次性註冊、錯誤密碼 401、新密碼登入、登出／改密碼撤銷舊 cookie |
| 儲存設定 | PASS；hostname 寫入，revision 1→2，其餘欄位完整保留；重開前仍顯示舊 active hostname |
| Web 觸發實際重開 | PASS；觀察 HTTPS 中斷與恢復，約 25.47 秒（含重新登入）；帳號、設定、revision、憑證保留，pending=false、舊 cookie 401 |
| 完整關機後 UEFI 再啟動 | PASS；帳號沒有重新註冊、憑證指紋一致、已保存 hostname 生效；`uefi-probe.json` |
| 服務及權限 | PASS；實際 lighttpd 以 routertop 使用者執行，只監聽 LAN 443；UID 1000 可讀 active config；資料目錄 0700、state 0600、TLS root-only；`appliance-runtime.log` |
| HTTP 拒絕行為 | PASS；未登入讀取 401、缺少 CSRF／錯誤 Origin 403、舊 revision 409、無效設定 400；拒絕後資料未改變；40,000 bytes 請求 413；`browser-report.json`、`http-probe.json` |
| WAN HTTPS 與 TLS | PASS；實際 WAN host-forward 連線逾時，LAN 正常；TLS 1.2 可交握；`http-probe.json` |
| 設定損壞後開機 | PASS；測試卷故意寫入無效 JSON，開機拒絕、forwarding=0、無 listener、未重設管理員；驗證後還原原檔；`corrupt-boot.log`、`corrupt-runtime.log` |
| 網路回歸 | PASS；Linux namespace 中 DHCP、DNS、NAT、LAN 管理 TCP 接受／WAN default-drop、重複 nft 套用保留無關 table；`linux-final.log` |
| 資料磁碟建立 | PASS；產生新的一般映像檔，拒絕覆寫既有路徑；`linux-build.log`、`artifact-source.log` |
| 無資料磁碟開機 | PASS；基本路由 ready、forwarding=1，無 persistence/web-enabled marker，沒有 HTTPS listener；`diskless-boot.log`、`diskless-runtime.log` |

256 MiB BIOS VM 閒置取樣：MemTotal 220724 kB，MemAvailable 130848 kB。Chrome 測得一次有效登入 0.732 秒。這些是 QEMU TCG 單次取樣，不是最低 RAM 或效能承諾。瀏覽器僅在隔離測試 context 接受自簽憑證，未變更主機信任設定；未保存密碼、註冊權杖、cookies 或 HAR。

本次 0.2 網路回歸使用實際 Linux namespace 封包；完整二台 VM 的 DHCP／DNS／NAT 證據屬 0.1，本次未重跑，不將舊結果冒充新版測試。新版本實際 appliance 的 HTTPS／登入／重開機則已直接測試。

## 執行紀錄備註

序列測試工具初次遇到 BusyBox askfirst 會吞掉第一行，背景命令結尾 `&` 也曾與原先分號拼接衝突。已改成先確認 shell 回覆，再以換行分隔命令與退出碼；受影響的 UEFI／損壞檢查重跑，以上 PASS 均有實際標記及 API 證據。早期工具失敗保留在原始 log，不代表 appliance 失敗。

lighttpd 有兩個已解釋的啟動警告：未載入 mod_dirlisting，所以 `dir-listing.activate` 被忽略（目錄列表模組本就未啟用）；其 OpenSSL EOL 警告是上游 1.4.85 將 `OPENSSL_VERSION_NUMBER` 與 **3.5.0 的完整數值**比較，錯誤地警告 3.5.9。實際 appliance 的程式及 library 均回報 OpenSSL 3.5.9。已核對[官方 lighttpd release source](https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.85.tar.xz)第 4456–4461 行、[Alpine 配方](https://raw.githubusercontent.com/alpinelinux/aports/3.24-stable/main/lighttpd/APKBUILD)及[OpenSSL 版本定義](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.9/include/openssl/opensslv.h.in)，未以關閉 TLS 檢查掩蓋警告。

建置 manifest 的 boot_test 保留建立當下的 NOT_RUN；本文件與 acceptance-manifest.json 是後續驗收證據，沒有回寫建置證據造成雜湊失效。

## 邊界

- 設定先保存，重開機才套用；沒有即時網路交易／確認逾時回復。
- Web 使用唯一管理員 admin。本機 recovery console 仍為免密碼 root，必須是受控的實體／VM console。
- HTTPS 使用本機自簽憑證；沒有公開 CA 信任、憑證管理 UI 或 Secure Boot。
- NOT_RUN：實體網卡／硬體、ARM、掉電注入及檔案系統故障壓力、效能壓力、遠端 CI、apk 簽章發行、公開部署。
- 完整 RouterOS 功能、IPv6、VLAN、VPN、動態路由、多 WAN、QoS、安裝器與 A/B 更新仍列於功能對照表；本次未將其標為完成。
