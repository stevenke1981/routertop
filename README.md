# RouterTop

以 Linux、Alpine、apk 與 Rust 製作的小型路由系統。x86_64 優先，aarch64 預留。0.7 加入固定 IP WAN、雙 WAN 主備切換與恢復後自動切回，支援 DHCP／PPPoE，延續 IPv6CP、DHCPv6-PD、WireGuard 全通道、必要的本機 console 登入及受 macOS「系統設定」啟發的淺色介面；這仍是隔離環境用的開發映像，**尚未達成 RouterOS 全功能相當性**，也不包含 WinBox、MikroTik 原始碼或 RouterBOARD 驅動。

## 已實作範圍

- IPv4 固定 IP／DHCP／PPPoE WAN、雙 WAN 主備切換、綁定各線路的健康檢查與自動恢復；固定 LAN、DHCP 伺服器、DNS 轉送、NAT、狀態防火牆與 LAN gateway 靜態路由。
- 實體 WAN／LAN 上的 802.1Q VLAN、選配 DHCP 與對外 NAT，預設跨網段隔離。
- 靜態或自動 IPv6 WAN、DHCPv6-PD `/48`–`/64` 申請、LAN／VLAN 獨立 `/64`、RA／SLAAC、IPv6 DNS 轉送及必要的 ND／PMTU 規則。
- IPv4／IPv6 split-tunnel WireGuard，或一個明確啟用的全通道介面；全通道 IPv4 NAT、可選 NAT66 與防止直接 WAN 回退的規則。
- IPv4／IPv6 input／forward 規則新增、編輯、刪除、排序及啟停，可比對介面、網段、協定與目的埠。
- Rust 嚴格設定驗證、CLI、設定產生器及 CGI 管理 API；繁體中文 Web UI 使用淺灰側欄、白色分組面板與藍色重點，不依賴外部 CDN 或前端框架。
- 可寫 ext4 資料卷保存設定、管理員密碼雜湊與 TLS 憑證；session 留在 RAM，重新開機後重新登入。
- 管理頁面提供首次註冊、登入、系統狀態、設定儲存、修改密碼、登出與重新啟動。設定儲存後於下次開機套用。
- 本機序列／螢幕 console 與 Web 共用 `admin` 密碼；登入成功才提供 root shell，沒有免驗證開關。
- Alpine 簽章套件組成 kernel、initramfs 與 BIOS/UEFI ISO；保留 apk、套件清單與建置 manifest。

預設 WAN 為 `eth0`，LAN 為 `eth1`／`192.168.88.1/24`，DHCP 範圍為 `.100` 至 `.199`。HTTPS 預設僅綁定 LAN 位址的 443 埠；SSH 未安裝或啟用，`ssh_port` 只控制防火牆放行。

實作項目不等於驗收通過。0.7 的實際產物、體積、測試及未執行項目記錄於 [0.7 驗收紀錄](docs/acceptance-v0.7.md)。[0.6](docs/acceptance-v0.6.md)、[0.5](docs/acceptance-v0.5.md)、[0.4](docs/acceptance-v0.4.md)、[0.3](docs/acceptance-v0.3.md)、[0.2](docs/acceptance-v0.2.md) 與 [0.1](docs/acceptance.md) 保留為各版本證據。

## 首次啟動與登入

1. 在 Linux 建立一個全新的資料磁碟檔：`sh scripts/make-data-disk.sh routertop-data.img`。需要 `mkfs.ext4`、`sfdisk` 等工具；輸出為 33 MiB 一般檔案，內含 32 MiB ext4 分割區及 `ROUTERTOP_DATA` 標籤。工具拒絕覆寫既有路徑。
2. 將資料磁碟與 0.7 映像交給 Windows 啟動器：

   ```powershell
   ./scripts/boot-qemu.ps1 -ImageDirectory ./dist/v0.7 -DataDisk ./routertop-data.img -Qemu 'C:/path/to/qemu-system-x86_64.exe'
   ```

3. 首次 console 顯示 `Setup choice [create/token]:`。選 `create` 並輸入、確認 12–128 位元組密碼，即可建立管理員；若想從 Web 註冊，選 `token`，在可信實體終端取得一次性註冊權杖。
4. 開啟 `https://127.0.0.1:19443`。這是啟動器轉送至客體 LAN 的 localhost 連線；直接 LAN 用戶端使用 `https://192.168.88.1`。
5. 檢查本機產生的自簽憑證。若已使用 `create`，以 `admin` 與同一密碼登入；若選擇 `token`，在 Web 輸入權杖與新密碼完成註冊。兩種方式建立的是同一個帳號，註冊成功後權杖失效。

自簽憑證會觸發瀏覽器信任警告；localhost 轉送也不符合憑證的 LAN IP 名稱。可在可信 console 以已建立的管理員密碼登入，再執行 `openssl x509 -in /data/tls/server.pem -noout -sha256 -fingerprint` 核對指紋。它提供加密，並非公開 CA 簽發身分。

序列與螢幕 console 都會要求管理員密碼，成功後才進入 root shell，輸入 `exit` 返回登入。密碼輸入不回顯；Web 修改密碼會影響下一次 console 登入，但不會終止已登入的 shell。資料卷缺失、管理員資料損壞或驗證失敗時，不會退回無保護 shell；必要時使用可信離線維護環境與備份復原。這不代表已提供 Secure Boot、磁碟加密或防止實體離線改寫。

## 固定 IP 與雙 WAN

在「網路設定」選擇固定 IP、DHCP 或 PPPoE；固定 IP 需填寫 IPv4／前綴與同網段閘道。啟用雙 WAN 後，設定備線介面、連線方式及兩條線路各自可回應 ping 的 IPv4 檢查目標。主線連續失敗達門檻後切換備線，恢復達門檻後自動切回；兩線皆無法通過檢查時停止對外路由。Web 顯示使用中線路和各線狀態。兩組 PPPoE 密碼分別保存，讀取不回傳密碼。

這版是主備切換；外部 IP 改變後，既有 TCP／VPN 連線可能需要重連。IPv6／DHCPv6-PD 僅使用主線，備線接手時撤回 IPv6，主線恢復後重新取得前綴。雙 WAN 啟用 IPv6 時需使用自動模式；單 WAN 仍支援靜態 IPv6。詳細欄位與限制見 [0.7 WAN 契約](docs/network-v0.7-contract.md)。

## 設定與持久化

系統 root 仍從 RAM 執行。開機只掛載明確指定的 `routertop.datadev=/dev/vda1`，或唯一具有 `ROUTERTOP_DATA` 標籤的 ext4 分割區；不會在開機時格式化磁碟。啟動器預設透過標籤尋找附加資料檔。

沒有資料卷時仍可啟動基本路由，但不啟用 HTTPS 管理、可寫設定持久化或無驗證 console shell。已有資料損壞或遺失時不會自動清空管理員重新註冊。

Web 儲存會寫入資料卷並顯示是否待重啟；不會立即改動運作中的網路。確認重新啟動後才載入新設定。若修改 LAN 位址或 HTTPS 埠，下次需使用新網址；Windows 啟動器內建轉送仍指向預設 `192.168.88.1:443`，需要相應調整測試連線。資料卷不會讓 RAM root 裡手動執行的所有 `apk add` 或檔案修改自動持久化。

VLAN 與 split-tunnel VPN 的網際網路存取需要明確啟用；跨 VLAN、VPN 到 LAN／VLAN 的連線需要 forward 放行規則。一般自訂規則在 established／related 之後依畫面順序匹配；input 系統保留 LAN 管理、DHCP／DNS、VPN listener 與必要 IPv6 控制訊息。全通道的直接 WAN 阻擋則放在 established／related 之前，不讓既有直接連線繞過。啟用 VPN 時須先取得 WAN IPv4 位址；開機與 DHCP 更新檢查網段衝突，衝突時停止轉送。

IPv6 WAN 可選靜態或自動取得。自動模式使用 dhcpcd 處理 RA、SLAAC 與 DHCPv6；啟用 PD 時向 ISP 申請 `/48`–`/64` 前綴，再以唯一子網編號配置 LAN／VLAN 的 `/64`。例如 `/56` 可用編號 0–255；實際上游授予的前綴仍需容納全部編號，否則拒絕配置。PD 與手動 LAN／VLAN IPv6 位址互斥。Web 顯示目前位址、委派子網、DNS 與等待／異常狀態。

自動模式需要資料卷保存 root 專用的 DHCPv6 客戶端身分；租約和運作狀態留在 RAM，重開機重新向上游取得。上游更新時同步核心位址、有限時效的防火牆集合及 RA；Web 儲存的模式和子網編號不隨租約改寫。自動學習 DNS 可關閉；WireGuard 全通道不採用上游自動 DNS，應設定 VPN 可達的 DNS。靜態模式與 IPv4 外層承載的雙協定全通道仍保留。管理 HTTPS 仍限 LAN IPv4。

全通道最多一個介面，使用單一 peer、必填 `0.0.0.0/0`，可加 `::/0`；endpoint 暫限 IPv4 位址與埠。與原有 `internet`（讓遠端 peer 對外）模式互斥。IPv4 LAN 流量經 VPN NAT；IPv6 可選 NAT66，不選時 VPN 端必須具備回到 LAN／VLAN 前綴的路由。其他分流 WG 可共存。隧道失效時應維持 WAN 阻擋，DNS 也須使用可經隧道到達的伺服器；實際防洩漏證據見 0.4 驗收紀錄。只設定 IPv4 全通道時，IPv6 轉送會停用於防火牆，LAN 的 ND／RA 仍保留但不宣告可用的 IPv6 預設出口。

WireGuard 私鑰不會出現在 Web、公開設定或一般 export；備份完整資料卷才會保存 VPN 身分。刪除介面會移除其私鑰，改名或重新建立介面會產生新身分。舊資料卷載入時正規化新增欄位的預設值，保留原有帳號及 revision；損壞或缺少既有 VPN 私鑰時拒絕啟動管理，不會默默換鑰。

0.4 的 Web 與 console 建立／修改密碼共用驗證，排除 ASCII 控制字元。若 0.3 帳號曾使用包含控制字元的密碼，升級後仍可從 Web 登入，但須先在 Web 改為可輸入的密碼才能使用 console；既有雜湊無法判斷原密碼內容。一般密碼不受影響。

## 開發與建置

```text
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo run -- check configs/routertop.toml
cargo run -- render configs/routertop.toml --output dist/rendered
cargo run -- export configs/routertop.toml
```

`status` 讀取 Linux 網卡、路由與 nft table。`apply CONFIG --boot` 僅供 appliance 初次開機配置，已配置的系統拒絕再次套用。`storage-init`、`stored-config`、`wg-configs DATA OUTPUT` 與 `bootstrap-token` 是 Linux root console 管理指令。`wg-configs` 產生含私鑰的 0600 檔案，僅供開機服務使用。

完整步驟見 [映像建置說明](image/README.md)。0.6 apk recipe 只打包 Rust CLI、預設設定與授權；Web 靜態資源、TLS 服務、儲存掛載及 console／開機整合由 OS 映像建置加入，不能把安裝 CLI apk 當成完整 OS 安裝。

壓縮 kernel + root 的初始目標為 64 MiB；ISO、資料磁碟與 RAM 需求分開計量。實際值見驗收紀錄。ARM 只預留 profile，建置入口會拒絕尚未驗證的 ARM 映像。

後續範圍見 [功能對照表](docs/feature-matrix.md) 與 [架構](docs/architecture.md)。本機測試、VM、瀏覽器、封包、實體硬體、ARM、CI 與發布各自提供證據，不互相替代。

介面設計見 [0.4 設計記錄](docs/design-v0.4.md)：使用系統字型、分組設定、鍵盤焦點與響應式布局，保留 RouterTop 品牌，沒有使用 Apple 素材，也不宣稱 Apple 官方產品或完整符合 macOS 原生規範。

## 上游與授權

RouterTop 自有程式採 MIT；Linux 與 Alpine 套件保留各自授權。此 repository 公開自有來源碼與建置流程；正式散布 OS 映像前仍需準備對應套件授權及來源交付。

參考：[Alpine](https://alpinelinux.org/releases/)、[RouterOS 功能](https://manual.mikrotik.com/docs/getting-started/software-specifications/)、[nft 原子更新](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)、[dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)。

## PPPoE WAN (0.6)

Web 的 WAN 設定可選 DHCP 或 PPPoE，提供唯寫 ISP 密碼與 MTU。PPPoE 使用邏輯介面 `ppp0`，支援自動重撥、IPv6CP 及 DHCPv6-PD 的 LAN／VLAN 前綴分配；儲存後重新啟動套用，憑證私密保存。介面維持淺色設計，不引入前端框架。[設定契約](docs/network-v0.6-contract.md) 與 [驗收紀錄](docs/acceptance-v0.6.md) 列明實際結果與限制。
