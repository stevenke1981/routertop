# 架構決策：RouterTop 0.5

## 基礎系統與資料平面

採 Alpine v3.24 的 linux-virt、musl、BusyBox 與 apk。自訂 initramfs 作為 RAM root；Rust release 使用 size optimization、LTO、strip 與 panic abort。編譯器及開發工具留在 builder，不進入成品。

Linux kernel、nftables、iproute2、dnsmasq 負責封包、路由、DHCP 與 DNS；802.1Q 與 WireGuard 使用核心資料平面，僅增加小型 `wg` 設定工具。Rust 負責嚴格解析、跨欄位驗證、配置產生與管理 API，不另造 TCP/IP 協定棧。動態路由、無線與 QoS 尚需獨立模型和驗收。

VLAN、VPN 與防火牆使用有界、拒絕未知欄位的型別模型。所有介面名稱、IPv4／IPv6 網段、埠、公鑰與註解先驗證再產生 nft／ip／wg 配置，Web 不接收原始 shell 或 nft 表達式。VLAN 預設隔離；WireGuard 的解密流量需自訂規則放行至其他內部網段。一般自訂 forward 規則位於 established／related 之後、預設對外放行之前；input 系統保留規則優先。全通道的防洩漏阻擋具有更高順序，不能由 established 或自訂 accept 繞過。

## IPv6 與全通道路由

`Config.ipv6` 預設為空。靜態模式使用 WAN 位址／gateway、LAN `/64` 及對應既有 VLAN 的 `/64`。gateway 可為同網段 global／ULA 或由 WAN 介面限定的 link-local 位址；不接收任意 zone／shell 字串。前綴須正規化且互不重疊。`wan_mode` 預設 static，相容既有資料；auto 模式省略 WAN 位址與 gateway，由 dhcpcd 取得。`pd` 可指定 /48–/64 申請長度和 LAN／VLAN 唯一子網編號，與手動內網 IPv6 位址互斥。雙協定全通道也允許省略靜態 WAN IPv6 位址與 gateway。

dnsmasq 在指定 LAN／VLAN 供應 RA-only SLAAC 與 RDNSS，不提供此版未實作的 stateful DHCPv6。IPv4 DHCP 停用但需提供 SLAAC 的 VLAN 不建立 IPv4 位址池，也不產生 DHCPv4 input 放行；省略會在目前 dnsmasq 2.92 套件連帶阻止 IPv6 constructor 的 `no-dhcpv4-interface`。沒有 IPv6 的停用 VLAN 仍使用 `no-dhcp-interface`。IPv6 firewall 預設拒絕，保留 ND、錯誤訊息、PMTU 與各網段限定的 DNS；HTTPS 管理仍綁 LAN IPv4。自訂規則明確帶 `family`，拒絕混用網段及 ICMP 家族。

WireGuard 可增加 IPv6 介面位址與 IPv6 peer 路由。分流路由不得攔截本機網段、其他 peer 或 endpoint；自身 WG 網段的單一 `/32`／`/128` peer host 為明確例外。Live WAN IPv4 檢查另防止 DHCP 租約網段被 VPN 或靜態路由覆蓋。

全通道最多一個介面，該介面僅一個 peer，需 IPv4 default，可選 IPv6 default，外層 endpoint 暫限 literal IPv4。`full_tunnel` 與遠端 peer 對外功能 `internet` 互斥。所有 WG socket 在 full mode 使用保留 mark `0x5254`；default routes 放入 table `51820`，priority 100 查 main 並 suppress default，priority 110 讓未標記封包查 VPN table。如此保留本地管理、非預設路由及已標記的 WireGuard 加密 transport。

nft forward 在 established／related 前拒絕直接 WAN；output 對 WAN 僅保留已標記且來源埠符合已配置 WG 的 UDP、DHCPv4、動態模式限定的 DHCPv6／RS 與必要 IPv6 ND，其他封包拒絕。這些規則不隨 WG link 刪除，所以政策路由消失不等於允許明文回退。IPv4-only 全通道拒絕 IPv6 轉送，但保留 LAN ND／RA，RA router lifetime 設為零。此設計的實際握手、轉送及斷線結果需由封包驗收確認。

IPv4 內網經全通道使用 masquerade；IPv6 NAT66 為明確選項，關閉時需要 VPN 端的回程路由。VLAN 的 internet 開關仍控制是否能使用對外出口；full mode 時其出口改為 VPN。沒有任意使用者自訂政策路由或自動 failover 的宣稱。

## 儲存與開機順序

系統程式從 RAM 執行，只有明確提供的 ext4 資料分割區可寫入持久狀態。可用 kernel 參數 `routertop.datadev` 選擇，或接受唯一的 `ROUTERTOP_DATA` 標籤；重複標籤視為歧義。掛載使用 `rw,nosuid,nodev,noexec`，開機不格式化磁碟。

開機流程：取得初始 TOML → 載入或首次建立持久 bundle → 驗證設定 → 設定 hostname → 產生服務配置與 root-only VPN 檔案 → nft/dnsmasq 原生檢查 → 原子更新 RouterTop 自有 nft table → 啟用實體介面並檢查 live WAN → 設定 VLAN／VPN、IPv6 及政策路由 → 啟用 forwarding → 啟動 DHCP/DNS／RA → 準備 LAN HTTPS → ready marker。防火牆先於網路啟用，DHCP 更新會再檢查 WAN 衝突。

無資料卷時，預設基本路由可繼續，HTTPS 管理停用，console 也不開放無驗證 shell。既有持久資料損壞時停止該次開機配置、關閉 forwarding 並保持驗證拒絕；不自動清空帳號重新註冊。必要時透過可信離線維護環境及備份復原。0.1 唯讀設定卷仍可提供初始化輸入，但不是可寫管理儲存。

## 管理程序與權限

lighttpd 在 LAN IPv4 位址提供 HTTPS，CGI 執行同一個 Rust binary 的 `routertop.cgi` 入口。Web 靜態資源隨映像內建，不依賴外部服務。CGI 以 UID 1000 執行；持久狀態 `/data/routertop` 及 volatile `/run/routertop/web` 為該帳號所有，目錄 0700、秘密檔案 0600。

TLS 私鑰與自簽憑證位於 root-only `/data/tls`，沿用同一資料卷即可保留。Web 只綁 LAN IP；防火牆只放行 LAN 來源到指定 HTTPS 埠。`ssh_port` 不會啟動 SSH daemon。

CGI 不執行任意 shell 指令。重啟 API 只在固定 runtime 路徑寫入 `reboot.request`；root supervisor 只處理這個固定動作。CLI 的持久資料初始化、讀取及 bootstrap token 指令由 Linux root console 執行。

ttyS0 與 tty1 由 console gate 接管，不再直接 respawn shell。首次可選 `create` 建立並確認密碼，或 `token` 顯示 Web 註冊權杖。完成註冊後，每次登入都比對相同持久 admin Argon2id 雜湊，成功才啟動 root shell，`exit` 返回登入。密碼輸入前關閉 echo，錯誤、EOF、interrupt 或資料無效不得授予 shell。Web 密碼變更作用於後續 console 登入；已登入 shell 不會因此強制終止。

console 節流狀態由 root 持有並跨 TTY 共用，與 unprivileged Web runtime 分開；root 更新持久狀態時保留 UID/GID，避免破壞 Web 寫入權限。沒有關閉驗證的選項。這不是 Secure Boot、加密磁碟或實體離線防竄改機制。

## 帳號、session 與變更一致性

首次啟動產生 256-bit 註冊權杖，由可信 console 的 `token` 選項取得；也可直接用 console `create` 建立帳號。任一途徑成功設定唯一 `admin` 密碼後，權杖失效。密碼只存 Argon2id 雜湊；JSON 請求限制 32 KiB，密碼 12–128 位元組。

Web 與 console 的新密碼驗證共用相同規則，拒絕 ASCII 控制字元。升級時不重設既有雜湊，也無法由雜湊識別原密碼是否包含控制字元；這類 0.3 密碼仍可 Web 登入，須先在 Web 修改為可輸入密碼，才能使用 console。一般密碼不受影響。

Cookie 設定 `HttpOnly; Secure; SameSite=Strict; Path=/`；session 最長 30 分鐘，存於 RAM。登出、密碼變更及重新開機使相關 session 失效。所有 POST 驗證 HTTPS Origin；已登入 POST 額外檢查 CSRF token。全域失敗次數保存在共享 runtime 狀態，五分鐘內五次失敗後暫時限制認證嘗試。

跨 CGI 程序以檔案鎖序列化狀態操作。持久 bundle 同時包含 canonical 設定、revision、管理員雜湊及認證 epoch；以暫存檔、file fsync、rename、parent fsync 取代。設定儲存須帶目前 revision，競爭更新回覆 409。初始化 marker 防止遺失 bundle 時靜默重設帳號。

自 0.3 起，相同原子 bundle 包含獨立 `wireguard_keys` map。私鑰由 OS 隨機來源產生，以 x25519 導出公鑰；公開 Config 結構完全沒有私鑰欄位。新增介面與生成身分同筆提交；相同名稱保留私鑰、刪除介面移除其私鑰。開機 root 把必要私鑰寫入 RAM 中的 0700 目錄、0600 wg 檔案；CLI/API 一般設定匯出只包含 peer 公鑰。舊 bundle 讀取後 canonical 化補新增欄位的預設值，不改管理員、epoch 或 revision；現有 VPN 缺失／損壞私鑰時 fail closed。

密碼與新認證 epoch 同筆持久更新；session 必須符合目前 epoch。即使更新密碼後 volatile session 檔案清除失敗，舊 session 仍不能通過驗證。系統狀態從 `/proc` 讀取，不以示範數據代替運作狀態。

## 儲存與套用的區別

Web 儲存只更新持久 bundle。作用中配置仍在 `/etc/routertop/routertop.toml`；將解析後的 canonical 設定比較，決定是否顯示待重啟，不因空白或註解誤判。

重啟才載入已儲存配置。`apply --boot` 僅供首次開機，拒絕運作中的任意重套。此版尚未提供即時網路交易、確認逾時 rollback 或 A/B 系統升級。

## 動態 IPv6 生命週期

套件 dhcpcd 處理 DHCPv6 IA_NA／IA_PD 與 RA；Rust 不實作 DHCP 客戶端。上游事件經固定 hook 交給嚴格解析器，不 eval 環境內容。Rust 對實際委派大小、網段衝突與有效期限再次驗證，將目前有效的 LAN／VLAN 前綴放入有限 timeout 的 nft 集合；集合更新失敗或 monitor 停止時不永久保留通行權。動態來源 gate 先於 established／自訂規則；原有 WG 直接 WAN 阻擋仍保留。

DHCPv6 identity 位於 root-only `/data/routertop-dhcpcd/duid`，以持久資料卷保留；租約、DNS、狀態與產生配置留在 `/run/routertop/pd`。前綴變更不改寫使用者設定或 revision。dnsmasq constructor 依介面位址時效宣告子網，失去上游時撤回預設出口。動態 DNS 只使用仍有效資料，WG full mode 不採用上游學習 DNS。Web 的公開 runtime status 不包含 DUID、私鑰或 hook 環境。

## 平台、建置與證據

0.4 Web 介面將資訊整理為淺灰側欄、白色分組面板及藍色主要操作，使用系統字型、可見鍵盤焦點與響應式排列。設計借鑑 macOS「系統設定」，保留 RouterTop 名稱與圖示，不使用 Apple 素材；[設計記錄](design-v0.4.md) 與實際瀏覽器驗收分開。

設定與驗證不依賴 CPU；image profile 分離 apk architecture、Rust ABI 與 kernel。x86_64 為實作入口，aarch64 profile 不代表已完成 ARM 開機。

Cargo.lock 固定 Rust dependency resolution；apk 驗證 Alpine 簽章。產物附套件版本、repository、binary hash、kernel/root bytes 與 artifact hashes。精確重建仍需保存 APK snapshot 及工具鏈。

開發依 agent-team workflow 分工與獨立 worktree，Odin 作為程式導航及分析輔助；實際編譯、服務、VM、瀏覽器、console 與封包證據分開記錄。0.5 的實測與體積記錄於 [驗收紀錄](acceptance-v0.5.md)，目前不得推定尚未完成的項目通過；[0.3](acceptance-v0.3.md)、[0.2](acceptance-v0.2.md) 與 [0.1](acceptance.md) 紀錄保留。
