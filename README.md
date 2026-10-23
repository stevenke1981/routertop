# RouterTop

以 Linux、Alpine、apk 與 Rust 製作的小型路由系統。x86_64 優先，aarch64 預留。0.2 加入持久設定、首次管理員註冊及 LAN HTTPS 管理；這仍是隔離環境用的開發映像，**尚未達成 RouterOS 全功能相當性**，也不包含 WinBox、MikroTik 原始碼或 RouterBOARD 驅動。

## 已實作範圍

- IPv4 DHCP WAN、固定 LAN、DHCP 伺服器、DNS 轉送、NAT、狀態防火牆與 LAN gateway 靜態路由。
- Rust 嚴格設定驗證、CLI、設定產生器及 CGI 管理 API；繁體中文 Web UI 不依賴外部 CDN 或前端框架。
- 可寫 ext4 資料卷保存設定、管理員密碼雜湊與 TLS 憑證；session 留在 RAM，重新開機後重新登入。
- 管理頁面提供首次註冊、登入、系統狀態、設定儲存、修改密碼、登出與重新啟動。設定儲存後於下次開機套用。
- Alpine 簽章套件組成 kernel、initramfs 與 BIOS/UEFI ISO；保留 apk、套件清單與建置 manifest。

預設 WAN 為 `eth0`，LAN 為 `eth1`／`192.168.88.1/24`，DHCP 範圍為 `.100` 至 `.199`。HTTPS 預設僅綁定 LAN 位址的 443 埠；SSH 未安裝或啟用，`ssh_port` 只控制防火牆放行。

實作項目不等於驗收通過。0.2 的實際產物、體積、測試及未執行項目以 [0.2 驗收紀錄](docs/acceptance-v0.2.md) 為準；[0.1 驗收紀錄](docs/acceptance.md) 保留為舊版本證據。

## 首次啟動與登入

1. 在 Linux 建立一個全新的資料磁碟檔：`sh scripts/make-data-disk.sh routertop-data.img`。需要 `mkfs.ext4`、`sfdisk` 等工具；輸出為 33 MiB 一般檔案，內含 32 MiB ext4 分割區及 `ROUTERTOP_DATA` 標籤。工具拒絕覆寫既有路徑。
2. 將資料磁碟與 0.2 映像交給 Windows 啟動器：

   ```powershell
   ./scripts/boot-qemu.ps1 -ImageDirectory ./dist/v0.2 -DataDisk ./routertop-data.img -Qemu 'C:/path/to/qemu-system-x86_64.exe'
   ```

3. 在 VM 本機 console 執行 `routertop bootstrap-token`，取得一次性註冊權杖。
4. 開啟 `https://127.0.0.1:19443`。這是啟動器轉送至客體 LAN 的 localhost 連線；直接 LAN 用戶端使用 `https://192.168.88.1`。
5. 檢查本機產生的自簽憑證，輸入權杖與 12–128 位元組密碼，建立唯一管理員 `admin`。成功後權杖失效，後續使用密碼登入。

自簽憑證會觸發瀏覽器信任警告；localhost 轉送也不符合憑證的 LAN IP 名稱。可在可信 console 執行 `openssl x509 -in /data/tls/server.pem -noout -sha256 -fingerprint` 核對指紋。它提供加密，並非公開 CA 簽發身分。

本機序列／螢幕 console **仍是免密碼 root**，Web 管理員密碼不會改變此設定。此版的實體 console 信任邊界沒有改成正式產品的登入機制。

## 設定與持久化

系統 root 仍從 RAM 執行。開機只掛載明確指定的 `routertop.datadev=/dev/vda1`，或唯一具有 `ROUTERTOP_DATA` 標籤的 ext4 分割區；不會在開機時格式化磁碟。啟動器預設透過標籤尋找附加資料檔。

沒有資料卷時仍可啟動基本路由，但不啟用 HTTPS 管理，也沒有可寫設定持久化。已有資料損壞或遺失時不會自動清空管理員重新註冊，應使用本機 console 復原。

Web 儲存會寫入資料卷並顯示是否待重啟；不會立即改動運作中的網路。確認重新啟動後才載入新設定。若修改 LAN 位址或 HTTPS 埠，下次需使用新網址；Windows 啟動器內建轉送仍指向預設 `192.168.88.1:443`，需要相應調整測試連線。資料卷不會讓 RAM root 裡手動執行的所有 `apk add` 或檔案修改自動持久化。

## 開發與建置

```text
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo run -- check configs/routertop.toml
cargo run -- render configs/routertop.toml --output dist/rendered
cargo run -- export configs/routertop.toml
```

`status` 讀取 Linux 網卡、路由與 nft table。`apply CONFIG --boot` 僅供 appliance 初次開機配置，已配置的系統拒絕再次套用。`storage-init`、`stored-config` 與 `bootstrap-token` 是 Linux root console 管理指令。

完整步驟見 [映像建置說明](image/README.md)。0.2 apk recipe 只打包 Rust CLI、預設設定與授權；Web 靜態資源、TLS 服務、儲存掛載及開機整合由 OS 映像建置加入，不能把安裝 CLI apk 當成完整 OS 安裝。

壓縮 kernel + root 的初始目標為 64 MiB；ISO、資料磁碟與 RAM 需求分開計量。實際值見驗收紀錄。ARM 只預留 profile，建置入口會拒絕尚未驗證的 ARM 映像。

後續範圍見 [功能對照表](docs/feature-matrix.md) 與 [架構](docs/architecture.md)。本機測試、VM、瀏覽器、封包、實體硬體、ARM、CI 與發布各自提供證據，不互相替代。

## 上游與授權

RouterTop 自有程式採 MIT；Linux 與 Alpine 套件保留各自授權。正式散布映像前仍需準備對應授權及來源交付；本次沒有對外發布。

參考：[Alpine](https://alpinelinux.org/releases/)、[RouterOS 功能](https://manual.mikrotik.com/docs/getting-started/software-specifications/)、[nft 原子更新](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)、[dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)。
