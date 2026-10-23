# RouterTop 0.3.0 驗收紀錄

日期：2026-10-24（Asia/Taipei）。範圍：VLAN、WireGuard、規則管理、Web 整合、設定持久化與公開來源碼。x86_64 開發映像；不是完整 RouterOS 功能相當性或正式生產版本。歷史證據見 [0.2](acceptance-v0.2.md)。

## 程式與協作

- PASS：Windows、Alpine Linux 各 43 項測試：8 library、2 CLI、16 network、14 Web、3 Web network。Windows fmt 與 Clippy 通過。Linux 最新候選完整結果：本機 `evidence/v03/linux-verified.log`。
- PASS：新增設定嚴格驗證、注入／網段衝突／界限拒絕；0.2 帳號及 revision 升級；公開設定不含私鑰；保存／重啟保留 VPN 身分；缺失私鑰不默默重生；錯誤及競爭提交不改原資料。
- PASS（限定靜態範圍）：[一次獨立審查](review-v0.3.md)。修復 endpoint 被 WG connected route 攔截問題。其後以隔離 Linux 實驗證實 WAN connected route 可被 peer route 覆蓋，補上 live-WAN 檢查及 DHCP 更新保護。
- PASS：agent-team 分開工作樹；核心、Web、封包腳本由不同實作者交付，主代理整合與驗收。契約見 [network-v0.3-contract.md](network-v0.3-contract.md)。
- Odin 明確綁定 `E:\routertop`，用於結構、符號、呼叫與診斷。重新整理後 network.rs 診斷無問題；web.rs 只有停用 proc-macro 展開及平台條件的提示。Odin 結果不替代編譯、測試或 runtime 證據。

## 實測與產物

| 產物 | 實際大小 |
|---|---:|
| ISO | **66,062,336 bytes / 63.00 MiB** |
| kernel + initramfs | **52,941,351 bytes / 50.49 MiB** |
| Linux Rust binary | **1,032,832 bytes / 0.985 MiB** |
| Web HTML + CSS + JS | **74,400 bytes / 72.66 KiB** |
| 空白資料磁碟 | 34,603,008 bytes / 33 MiB |

ISO 比 0.2 增加 118,784 bytes（116 KiB）。壓縮 kernel + root 低於 64 MiB 目標；資料卷、ISO 開機開銷與 runtime RAM 分開計量。Alpine v3.24、60 個套件、Linux 6.18.58-0-virt、Alpine Rust 1.96.1 / x86_64-alpine-linux-musl。只增加 `wireguard-tools-wg` 與其 ifupdown 整合套件；不加入 wg-quick、bash 或前端框架。

ISO SHA256：`c0ef84e2f3aa84f95a9d34473b46a9272173be19bf3776af0555818078e97394`。Linux binary SHA256：`ba3cd824a761c8edf10cdb17205c75eef49571cdbd6cecfeed36e7864543e947`。全部下載產物與 builder 的 SHA256SUMS 相符，appliance 內實際 binary 雜湊也相同。

| 檢查 | 狀態與證據 |
|---|---|
| Linux release／ISO 建置 | PASS；`linux-verified.log`，chroot 執行新版 binary 成功 |
| 真實網路封包 | PASS，15 項；[network-results.jsonl](../evidence/v03/network-results.jsonl) |
| VLAN | PASS；802.1Q DHCP 位址／mask／gateway／DNS、同 VLAN HTTP／ICMP、跨 VLAN／未標籤 LAN 隔離、選配 NAT |
| WireGuard | PASS；核心實際握手及加密 ICMP、VPN 到 VLAN 預設拒絕／明確放行後 HTTP 與 ICMP 成功、陌生金鑰不能握手或轉送 |
| 防火牆排序 | PASS；drop 在 accept 前拒絕、調換後放行、停用／刪除後恢復隔離。每次用不同 TCP source port 避免既有 conntrack 造成假通過 |
| WAN 衝突保護 | PASS；live preflight 拒絕 peer／WG 網段衝突並保留原 WAN route。另在實際 appliance 加入衝突 WAN 位址並執行安裝的 DHCP renew hook，forwarding 降為 0；移除衝突、冷開後恢復 1 |
| 既有網路回歸 | PASS；DHCP、DNS、NAT、LAN 管理放行、WAN default-drop、重複 nft 套用保留無關 table；`linux-verified.log` |
| BIOS／UEFI ISO | PASS；各以 256 MiB QEMU TCG 開機，`iso-bios-boot.log`、`iso-uefi-boot.log` |
| 真實 Chrome Web | PASS，8 組；[browser-network-report.json](../evidence/v03/browser/browser-network-report.json)，VLAN／WG／peer／規則 CRUD、排序、啟停、公鑰穩定、完整欄位保留及重讀 |
| Web 重開機 | PASS；真實 HTTPS 中斷／恢復；原 admin 登入、revision 21、設定、公鑰與憑證保留；pending=false，舊 cookie 回覆 401 |
| 完整關機後 UEFI 啟動 | PASS；設定及公鑰 digest 不變，帳號與 TLS 保留，VLAN／WG 介面實際存在；[uefi-probe.json](../evidence/v03/uefi-probe.json) |
| 權限／保密 | PASS；durable 0700/0600、root WG 0700/0600；一般 API 無私鑰欄位，未保存密碼／token／cookie／HAR |
| 未登入與 WAN HTTPS | PASS；status/config/WG 公鑰 API 401，WAN HTTPS 不可連；[http-probe.json](../evidence/v03/http-probe.json) |
| 桌面／手機 | PASS；實際截圖檢查，390px 無水平溢出；[桌面](../evidence/v03/browser/firewall-desktop.png)、[手機](../evidence/v03/browser/firewall-mobile.png) |

256 MiB BIOS VM 閒置取樣：MemTotal 220724 kB、MemAvailable 129960 kB。不是最低 RAM 或吞吐效能承諾。WireGuard／VLAN 封包測試在真正 Linux network namespaces 執行；最終 ISO 另驗證核心介面、配置套用、Web 與重啟，沒有把 namespace 握手宣稱為實體設備驗收。

公開來源碼位置：[stevenke1981/routertop](https://github.com/stevenke1981/routertop)。本地驗收與 hosted CI 分層；公開推送後的精確 commit／CI 結果見 [Actions](https://github.com/stevenke1981/routertop/actions)。本文件不將尚未執行的遠端作業推定為 PASS。

## 交付邊界

- 設定先保存，重開機套用；沒有即時網路交易或確認逾時 rollback。
- VLAN 是實體 WAN／LAN 上的 802.1Q 子介面；沒有 bridge/PVID/access-port 管理或硬體 offload。
- WireGuard 限 IPv4 split tunnel，endpoint 是 IPv4:port。沒有 `/0` 全通道、DNS endpoint、IPv6 或鑰匙輪替 UI。刪除／改名介面會更換身分；一般 Config 匯出不包含私鑰。
- 系統保留 LAN 管理／DHCP／DNS／VPN transport 規則與 established／related。自訂規則排序不會強制中斷已建立連線。跨內部網段需要明確 forward 放行。
- WG 啟用需要已取得 WAN IPv4 租約；開機先檢查動態 WAN 網段衝突。後續 DHCP bound/renew 衝突停止 forwarding，修正設定後需重開。
- 單一 admin、自簽 TLS、可信本機 console 仍免密碼 root；不是正式安全啟動或多使用者設備。
- NOT_RUN：ARM、實體網卡／板型、效能／吞吐壓力、掉電故障注入、簽章 apk 發行與生產部署。aarch64 僅預留；沒有宣稱這些通過。

## 建置證據說明

初次傳送 source tar 的固定舊時間戳導致 Cargo 沿用較早候選，整合者從測試數量不符辨識後中止該輪，刷新來源時間戳並重新編譯。`linux-final.log` 是中止的早期紀錄；只有 `linux-verified.log` 的最新 43 項測試與其後產物列入驗收。

建置 manifest 的 `boot_test` 保留建置當下的 NOT_RUN；後續 acceptance manifest 才記錄實際啟動結果，不修改原始 build hash。

lighttpd 1.4.85 的 OpenSSL 版本警告仍是 [0.2 紀錄](acceptance-v0.2.md) 已核對的上游完整版本數值比較問題；映像實際使用 OpenSSL 3.5.9。移除了未載入目錄列表模組對應的無效設定指令，沒有停用 TLS 驗證來隱藏警告。

## 交接

- Owner：主代理整合、映像、驗收與公開推送；核心／UI／封包實作者各自使用獨立工作樹；審查者只做一次限定審查。
- Input：baseline `227c672`、本次 0.3 契約與原有 0.2 資料格式。
- Output：Rust／Web／開機整合、可重跑的兩個驗收腳本、`dist/v0.3` 產物及本文件。
- Acceptance：上列本地已執行項目 PASS；未執行範圍如上，不含正式部署。
- Next owner：後續 ARM、硬體、即時套用／rollback、IPv6／全通道與升級工程仍需獨立工作及驗收。
