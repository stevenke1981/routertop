# RouterOS 功能目標與 RouterTop 0.2 範圍

這份表區分程式實作與後續工程；安裝某個 Linux 套件不等於完成同名 RouterOS 功能。**0.2 是開發映像，沒有完整 RouterOS 功能相當性或正式生產部署宣稱。**

| 範圍 | 0.2 已實作內容 | 尚未完成／後續驗收範圍 |
|---|---|---|
| x86_64 系統 | Alpine、linux-virt、自訂 initramfs、BIOS/UEFI ISO 建置 | 實體機驅動、最低 RAM、硬體相容與安裝器 |
| IPv4 地址／路由 | DHCP WAN、固定 LAN、LAN gateway 靜態路由 | WAN 固定地址、PPPoE、多 WAN、策略路由、故障切換 |
| NAT／防火牆 | 狀態防火牆、LAN masquerade、LAN HTTPS 放行 | DNAT、自由規則編輯、連線檢視、即時交易與 rollback |
| DHCP／DNS | LAN DHCP 與 DNS 轉送 | 靜態租約、relay、DNSSEC／DoH 選配 |
| IPv6 | forwarding 明確關閉 | DHCPv6-PD、RA、完整 IPv6 firewall |
| Web／API | 繁體中文靜態 UI、LAN HTTPS、狀態及設定 API | 多管理員／角色、遠端管理策略、API 外部整合 |
| 管理員認證 | 一次性 console token、admin、Argon2id、session、CSRF、Origin、全域節流 | MFA、集中認證、審計及帳號復原產品流程 |
| 設定持久化 | 可寫 ext4 資料卷、原子 bundle、revision、儲存後重啟套用 | 完整備份還原 UI、斷電故障注入、儲存遷移與冗餘 |
| TLS | 每資料卷產生並保存自簽憑證；LAN IP 綁定 | 公開 CA、憑證匯入／輪替介面、變更 LAN IP 後憑證管理 |
| Console／CLI | 本機 CLI、TOML、真實 status；physical console 保持免密碼 root | 正式 console 驗證與開機信任鏈 |
| apk／系統更新 | apk 保留；0.2 CLI-only APKBUILD；完整 OS 由 image builder 組裝 | 簽章發行通道、A/B 升級、系統 rollback；安裝 CLI apk 不會安裝整個管理 OS |
| Bridge／VLAN | 未實作 | Linux bridge、802.1Q、RSTP、隔離、硬體 offload |
| VPN | 未實作 | WireGuard 優先，IPsec／OpenVPN 可選模組 |
| BGP／OSPF | 未實作 | FRR 模組、設定生命週期及封包驗收 |
| QoS | 未實作 | tc、CAKE／fq_codel、限速及負載測試 |
| 無線 AP | 未實作 | hostapd、板型驅動／韌體；不宣稱 CAPsMAN 相容 |
| ARM | aarch64 profile／套件架構預留；OS 建置仍拒絕 | QEMU virt 開機、交叉編譯、指定 SoC 與板型驗收 |

沒有資料卷時，HTTPS 管理與可寫設定持久化不啟用；基本路由仍可使用映像內設定。整體壓縮體積目標為 kernel + root ≤64 MiB，實測需分開列出 ISO、資料卷及 RAM。

實際 PASS／FAIL／NOT_RUN、產物 hash 與版本體積比較見 [0.2 驗收紀錄](acceptance-v0.2.md)；[0.1 驗收紀錄](acceptance.md) 保留舊版結果。瀏覽器、VM 重啟、持久化、負向 HTTP、封包、ARM、實體硬體、CI 與發布證據不能相互替代。
