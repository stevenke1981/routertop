# RouterTop 0.4.0 驗收紀錄

日期：2026-10-24（Asia/Taipei）。範圍：IPv6、WireGuard 全通道、console 登入、Web 設定與持久化、淺色系統設定介面。x86_64 開發映像；沒有完整 RouterOS 相容或正式生產版本宣稱。

## 實作與協作

Agent-team 依 [契約](network-v0.4-contract.md) 分成網路核心、console／封包驗證、Web 設計三個隔離 worktree，整合者負責實際 Linux／QEMU／Chrome 驗收；另完成 [一次獨立範圍審查](review-v0.4.md)。Odin 明確綁定 `E:\routertop`，實際 project analysis 與 IPv6 LSP symbols 成功；trace `f8ecbc99-5adc-4eac-9547-64155405d0d4`。程式導航與靜態審查不替代 runtime 證據。

新增功能使用現有 Rust 依賴與 Linux 核心能力，沒有新增前端框架、CDN 或 runtime 套件。介面為淺灰側欄、白色群組與藍色控制，設計依據及色彩記錄見 [設計說明](design-v0.4.md)。

## 實際驗收

| 檢查 | 結果與範圍 |
|---|---|
| Windows | PASS：最終 65 tests、fmt、Clippy、JavaScript 與 Python 語法 |
| Alpine Linux | PASS：66 tests；密碼規則修復後定點重測，RA 修復後 31 項 IPv6／network tests 通過；最終 release 與 ISO 建置成功 |
| IPv6／全通道實包 | PASS，17 項；[完整結果](../evidence/v04/network-v04-results.jsonl)。真實 LAN／tagged VLAN SLAAC、RA default policy、IPv4 DHCP 正向及拒絕控制、IPv6 轉送／WAN 拒絕、規則排序、真實 PMTU 1280 學習 |
| WireGuard 全通道 | PASS：核心握手、fwmark、LAN 及路由器自身 IPv4／IPv6 HTTP 經 VPN、路由器 DNS 經 VPN、LAN 管理可達；刪除 WG 介面後兩種 IP family 均不能回落到 WAN。IPv4-only VPN 另以強制 client IPv6 default 證明無繞過 |
| 既有網路 | PASS：[15 項 VLAN／WG／防火牆回歸](../evidence/v04/network-v03-results.jsonl)；另通過基礎 DHCP、DNS、NAT、LAN 管理、WAN 拒絕及保留無關 nft table |
| 真實 PTY | PASS，[6 項](../evidence/v04/console-pty-results.jsonl)：缺失／損壞帳號狀態下，命令輸入、Ctrl-C、EOF 都不授予 shell，也不重建帳號 |
| 最終 ISO console | PASS，[6 組](../evidence/v04/console-report.json)：首次建立帳號、無密碼回顯、錯誤／Ctrl-C／EOF 拒絕、root shell、登出、UID1000／0600、Web 改密碼即時影響新登入、重啟後密碼保留 |
| 最終 ISO 真 Chrome | PASS，[12 組](../evidence/v04/browser/browser-v04-report.json)：token 註冊、鍵盤／對話框循環、IPv6／WG full／family 規則保存、錯誤設定不改持久資料、18 個實際樣式／對比／目標／版面檢查、無 JS runtime error 或私鑰回覆 |
| 重啟與 UEFI 冷開 | PASS：BIOS／UEFI 均以 QEMU TCG 256 MiB 啟動；真實 HTTPS 下線／恢復，帳號、完整 config／revision、公鑰、憑證保留，舊 session 401、pending=false。UEFI 實查 eth1／vlan20／wg0 IPv6 位址、兩種 family 的 table51820 default；最後經認證關機並確認 VM 結束 |
| 產物一致性 | PASS：[8 個 SHA256 與來源快照](../evidence/v04/artifact-verification.json)。UEFI 內實際 `/usr/sbin/routertop` SHA256 與下載 binary／build manifest 相同 |

所有封包案例都在隔離 Linux namespaces 執行；ISO 另驗證開機、實際核心介面／路由、管理介面與持久化。沒有將 namespace 的 VPN 流量宣稱為實體硬體驗收。最終 UEFI 閒置取樣：MemTotal 214612 KiB、MemAvailable 116332 KiB；這不是最低 RAM 或吞吐承諾。

## 體積與產物

| 項目 | 實際大小 |
|---|---:|
| ISO | 66,095,104 bytes／63.03 MiB |
| kernel + initramfs | 52,974,428 bytes／50.52 MiB |
| Linux Rust binary | 1,110,656 bytes／1.06 MiB |
| Web HTML + CSS + JS | 85,610 bytes／83.60 KiB |
| 空白資料磁碟 | 34,603,008 bytes／33 MiB |

ISO 比 0.3 增加 **32 KiB**，kernel + root 仍低於 64 MiB 目標；仍為 60 個 Alpine runtime 套件，沒有新增依賴。Builder：Alpine v3.24、Linux 6.18.58、Rust 1.96.1、x86_64-alpine-linux-musl。ISO SHA256：`b8b1c544fcca8150fc77c167feb35d6b79a3bd46d2d1216c64b4515fb7231744`；binary：`74a21e682feea6021a251f637e488cb2edacb96d83d119f055018e0c2e54c3ce`。

介面實拍：[總覽](../evidence/v04/browser/overview-light.png)、[IPv6](../evidence/v04/browser/ipv6-after-uefi-cold-boot-light.png)、[手機 WireGuard](../evidence/v04/browser/wireguard-mobile-light.png)。本機產物在 `dist/v0.4/`；repo 不包含二進位映像或已註冊磁碟。

## 驗收中修復的問題

- Linux 專用檔案 ownership 呼叫改為 `std::os::unix::fs::chown`，實測保留 CGI 所需 UID/GID 與私密權限。
- Web 新密碼與 console 統一拒絕 ASCII 控制字元，避免接受無法在 TTY 輸入的共用密碼。
- 真實 RS/RA 抓包及單一變因比對證明：目前 dnsmasq 的 `no-dhcpv4-interface` 會阻止 VLAN IPv6 constructor。改為不建立 IPv4 pool／DHCP input 放行並保留 SLAAC；最終實包同時證明 IPv4 DHCP 仍被拒絕。
- Chrome 原生 dialog 可將 Tab 移到瀏覽器工具列；補明確首尾 Tab／Shift+Tab 循環，保留 Escape 與焦點返回，實際 VM 重測通過。
- 測試工具另排除 HTTP fixture 的外部 PTR 依賴、採用足夠的 DHCP lease 探測等待，修正 Windows 子程序輸出管線及序列命令傳送完成前關閉連線的問題。這些是驗收工具修復，不以此放寬產品防火牆或繞過 render。

公開來源碼：[stevenke1981/routertop](https://github.com/stevenke1981/routertop)。CI 已包含 Windows／Linux Rust、Alpine image、實際 IPv6／全通道及 console PTY；遠端結果以對應 commit 的 [Actions](https://github.com/stevenke1981/routertop/actions) 為準，不由本地測試推定通過。

## 交付邊界

- IPv6 WAN 為靜態位址／gateway；LAN、VLAN `/64` 使用 RA／SLAAC。尚無 DHCPv6-PD、動態 ISP 前綴、stateful DHCPv6。HTTPS 管理仍綁定 IPv4 LAN。
- 全通道最多一個介面／一個 peer，必須含 IPv4 default，可選 IPv6 default；外層 endpoint 限 IPv4。NAT66 需明確開啟，否則遠端須有 IPv6 回程路由。未啟用 IPv6 全通道時阻擋 IPv6 轉送。
- 設定儲存後重啟套用；尚無即時交易或連線確認 rollback。防火牆自訂排序不會強制中斷既有 conntrack；全通道 WAN 防洩漏 gate 優先於 established/custom 規則。
- Console 與 Web 共用單一 admin 密碼，成功登入 console 後為 root shell；改密碼影響後續登入，已登入 shell 不會被強制終止。新密碼拒絕 ASCII 控制字元；舊版若曾使用這類密碼，先透過 Web 更換。
- 無有效資料卷時，console 不授予 shell；不提供免驗證救援後門。Secure Boot、磁碟加密、帳號復原產品流程尚未完成。
- NOT_RUN：ARM 開機、實體網卡／板型、吞吐／負載、掉電故障注入、螢幕閱讀器、簽章 apk 發行及生產部署。aarch64 僅保留架構入口。

原始 build manifest 的 `boot_test` 保留建置時的 NOT_RUN；後續測試結果另記錄，不覆寫建置雜湊。秘密、token、cookie、HAR、私鑰、已註冊資料磁碟及原始 console log 不進公開 repo。
