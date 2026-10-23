# 架構決策：RouterTop 0.3

## 基礎系統與資料平面

採 Alpine v3.24 的 linux-virt、musl、BusyBox 與 apk。自訂 initramfs 作為 RAM root；Rust release 使用 size optimization、LTO、strip 與 panic abort。編譯器及開發工具留在 builder，不進入成品。

Linux kernel、nftables、iproute2、dnsmasq 負責封包、路由、DHCP 與 DNS；802.1Q 與 WireGuard 使用核心資料平面，僅增加小型 `wg` 設定工具。Rust 負責嚴格解析、跨欄位驗證、配置產生與管理 API，不另造 TCP/IP 協定棧。動態路由、無線與 QoS 尚需獨立模型和驗收。

VLAN、VPN 與防火牆使用有界、拒絕未知欄位的型別模型。所有介面名稱、IPv4 網段、埠、公鑰與註解先驗證再產生 nft／ip／wg 配置，Web 不接收原始 shell 或 nft 表達式。VLAN 預設隔離；WireGuard 的解密流量需自訂規則放行至其他內部網段。啟用 internet 僅加入往 WAN 的來源網段放行及 masquerade。自訂 forward 規則位於 established／related 之後、預設對外放行之前；input 系統保留規則優先。

## 儲存與開機順序

系統程式從 RAM 執行，只有明確提供的 ext4 資料分割區可寫入持久狀態。可用 kernel 參數 `routertop.datadev` 選擇，或接受唯一的 `ROUTERTOP_DATA` 標籤；重複標籤視為歧義。掛載使用 `rw,nosuid,nodev,noexec`，開機不格式化磁碟。

開機流程：取得初始 TOML → 載入或首次建立持久 bundle → 驗證設定 → 設定 hostname → 產生服務配置與 root-only VPN 檔案 → nft/dnsmasq 原生檢查 → 原子更新 RouterTop 自有 nft table → 啟用實體介面、VLAN／VPN 與 forwarding → 啟動 DHCP/DNS → 準備 LAN HTTPS → ready marker。

無資料卷時，預設基本路由可繼續，HTTPS 管理停用。既有持久資料損壞時停止該次開機配置、關閉 forwarding 並保留本機 recovery；不自動清空帳號重新註冊。0.1 唯讀設定卷仍可提供初始化輸入，但不是 0.2 的持久寫入介面。

## 管理程序與權限

lighttpd 在 LAN 位址提供 HTTPS，CGI 執行同一個 Rust binary 的 `routertop.cgi` 入口。Web 靜態資源隨映像內建，不依賴外部服務。CGI 以 UID 1000 執行；持久狀態 `/data/routertop` 及 volatile `/run/routertop/web` 為該帳號所有，目錄 0700、秘密檔案 0600。

TLS 私鑰與自簽憑證位於 root-only `/data/tls`，沿用同一資料卷即可保留。Web 只綁 LAN IP；防火牆只放行 LAN 來源到指定 HTTPS 埠。`ssh_port` 不會啟動 SSH daemon。

CGI 不執行任意 shell 指令。重啟 API 只在固定 runtime 路徑寫入 `reboot.request`；root supervisor 只處理這個固定動作。CLI 的持久資料初始化、讀取及 bootstrap token 指令由 Linux root console 執行。

本機序列／螢幕 recovery console 仍是免密碼 root。Web 管理員驗證沒有改變實體 console 的信任邊界，這不是正式多使用者路由產品。

## 帳號、session 與變更一致性

首次啟動產生 256-bit 註冊權杖，由可信 console 取得。成功設定唯一 `admin` 的密碼後，註冊權杖失效。密碼只存 Argon2id 雜湊；JSON 請求限制 32 KiB，密碼 12–128 位元組。

Cookie 設定 `HttpOnly; Secure; SameSite=Strict; Path=/`；session 最長 30 分鐘，存於 RAM。登出、密碼變更及重新開機使相關 session 失效。所有 POST 驗證 HTTPS Origin；已登入 POST 額外檢查 CSRF token。全域失敗次數保存在共享 runtime 狀態，五分鐘內五次失敗後暫時限制認證嘗試。

跨 CGI 程序以檔案鎖序列化狀態操作。持久 bundle 同時包含 canonical 設定、revision、管理員雜湊及認證 epoch；以暫存檔、file fsync、rename、parent fsync 取代。設定儲存須帶目前 revision，競爭更新回覆 409。初始化 marker 防止遺失 bundle 時靜默重設帳號。

0.3 在相同原子 bundle 中加入獨立 `wireguard_keys` map。私鑰由 OS 隨機來源產生，以 x25519 導出公鑰；公開 Config 結構完全沒有私鑰欄位。新增介面與生成身分同筆提交；相同名稱保留私鑰、刪除介面移除其私鑰。開機 root 把必要私鑰寫入 RAM 中的 0700 目錄、0600 wg 檔案；CLI/API 一般設定匯出只包含 peer 公鑰。舊 0.2 bundle 讀取後 canonical 化補空集合，不改管理員、epoch 或 revision；現有 VPN 缺失／損壞私鑰時 fail closed。

密碼與新認證 epoch 同筆持久更新；session 必須符合目前 epoch。即使更新密碼後 volatile session 檔案清除失敗，舊 session 仍不能通過驗證。系統狀態從 `/proc` 讀取，不以示範數據代替運作狀態。

## 儲存與套用的區別

Web 儲存只更新持久 bundle。作用中配置仍在 `/etc/routertop/routertop.toml`；將解析後的 canonical 設定比較，決定是否顯示待重啟，不因空白或註解誤判。

重啟才載入已儲存配置。`apply --boot` 僅供首次開機，拒絕運作中的任意重套。此版尚未提供即時網路交易、確認逾時 rollback 或 A/B 系統升級。

## 平台、建置與證據

設定與驗證不依賴 CPU；image profile 分離 apk architecture、Rust ABI 與 kernel。x86_64 為實作入口，aarch64 profile 不代表已完成 ARM 開機。

Cargo.lock 固定 Rust dependency resolution；apk 驗證 Alpine 簽章。產物附套件版本、repository、binary hash、kernel/root bytes 與 artifact hashes。精確重建仍需保存 APK snapshot 及工具鏈。

開發依 agent-team workflow 分工與獨立 worktree，Odin 作為程式導航及分析輔助；實際編譯、服務、VM、瀏覽器與封包證據分開記錄。0.3 結果以 [驗收紀錄](acceptance-v0.3.md) 為準，[0.2 紀錄](acceptance-v0.2.md) 保留。文件描述已實作設計，不自行推定任何尚未執行的測試通過。
