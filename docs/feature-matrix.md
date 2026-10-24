# RouterOS 功能目標與 RouterTop 0.8 範圍

這份表區分程式實作與後續工程；安裝某個 Linux 套件不等於完成同名 RouterOS 功能。**0.8 是開發映像，沒有完整 RouterOS 功能相當性或正式生產部署宣稱。**本表不替代各層的 0.8 驗收證據。

| 範圍 | 0.8 已實作內容 | 尚未完成／後續驗收範圍 |
|---|---|---|
| x86_64 系統 | Alpine、linux-virt、自訂 initramfs、BIOS/UEFI ISO 建置 | 實體機驅動、最低 RAM、硬體相容與安裝器 |
| IPv4 地址／路由 | 固定 IP／DHCP／PPPoE WAN、雙 WAN 主備切換與自動切回、固定 LAN、LAN gateway 靜態路由 | 負載平衡、連線遷移、任意策略路由 |
| NAT／防火牆 | IPv4／IPv6 狀態防火牆、family 明確的 input／forward CRUD、排序與啟停；IPv4 masquerade、全通道選配 NAT66 | DNAT、連接埠範圍、連線檢視、任意政策路由、即時交易與 rollback |
| DHCP／DNS | LAN DHCP 與 DNS 轉送 | 靜態租約、relay、DNSSEC／DoH 選配 |
| IPv6 | 靜態／自動 WAN、DHCPv6 IA_NA／PD（含 PPPoE／IPv6CP）、LAN／VLAN `/64`、可選雙 WAN 前綴／DNS 切換、前綴更新、RA／SLAAC、IPv6 DNS、ND／PMTU 與 IPv6 規則 | 下游 stateful DHCPv6 server、任意 ISP 互通、獨立 IPv6 健康選路及靜態多 ISP 前綴策略；不宣稱完整 IPv6 產品相容 |
| Web／API | macOS 系統設定風格的淺色繁中 UI、分組設定、IPv4 LAN HTTPS、IPv6／全通道控制 | 多管理員／角色、遠端管理策略；完整螢幕閱讀器等可及性驗收另列 |
| 管理員認證 | 一次性 console token、admin、Argon2id、session、CSRF、Origin、全域節流 | MFA、集中認證、審計及帳號復原產品流程 |
| 設定持久化 | 可寫 ext4 資料卷、原子 bundle、revision、儲存後重啟套用 | 完整備份還原 UI、斷電故障注入、儲存遷移與冗餘 |
| TLS | 每資料卷產生並保存自簽憑證；LAN IP 綁定 | 公開 CA、憑證匯入／輪替介面、變更 LAN IP 後憑證管理 |
| Console／CLI | 序列／螢幕必要登入、共用 Web admin 密碼、首次 create／token、登出及跨 TTY 節流；無資料不開放 shell | Secure Boot、磁碟加密、離線復原產品流程；已登入 shell 不隨 Web 改密碼終止 |
| apk／系統更新 | apk 保留；0.8 CLI-only APKBUILD；完整 OS 由 image builder 組裝 | 簽章發行通道、A/B 升級、系統 rollback；安裝 CLI apk 不會安裝整個管理 OS |
| Bridge／VLAN | 實體 WAN／LAN 上 802.1Q、IPv4、選配 DHCP／NAT、IPv6 `/64`／SLAAC、預設隔離及 Web CRUD | Linux bridge 管理、RSTP、access port／PVID、硬體 offload |
| VPN | 核心 WG、IPv4／IPv6 分流、單一全通道介面、fwmark／獨立路由表、WAN 防洩漏 gate、可選 NAT66、私鑰持久化 | IPv6／DNS 外層 endpoint、雙全通道或故障切換、鑰匙輪替 UI、IPsec／OpenVPN |
| BGP／OSPF | 未實作 | FRR 模組、設定生命週期及封包驗收 |
| QoS | 未實作 | tc、CAKE／fq_codel、限速及負載測試 |
| 無線 AP | 未實作 | hostapd、板型驅動／韌體；不宣稱 CAPsMAN 相容 |
| ARM | aarch64 profile／套件架構預留；OS 建置仍拒絕 | QEMU virt 開機、交叉編譯、指定 SoC 與板型驗收 |

沒有資料卷時，HTTPS 管理與可寫設定持久化不啟用，console 也不提供免驗證 shell；基本靜態路由仍可使用映像內設定；自動 IPv6 需要資料卷保存客戶端身分；PPPoE 需要資料卷保存唯寫 ISP 憑證。全通道必須有 IPv4 default，IPv6 default 可選；未提供後者時阻擋 IPv6 轉送。外層 WG endpoint 暫限 IPv4，沒有 NAT66 時需配置遠端 IPv6 回程路由。管理 HTTPS 仍在 IPv4 LAN。

整體壓縮體積目標仍為 kernel + root ≤64 MiB；實際大小見 0.8 驗收紀錄，ISO、資料卷及 RAM 分開計量。x86_64 是本次建置／測試目標，aarch64 仍只預留，不宣稱 ARM 或實體 RouterBOARD 可用。

實際 PASS／FAIL／NOT_RUN、產物 hash 與版本體積比較記錄於 [0.8 驗收紀錄](acceptance-v0.8.md)；[0.7](acceptance-v0.7.md)、[0.6](acceptance-v0.6.md)、[0.5](acceptance-v0.5.md)、[0.4](acceptance-v0.4.md)、[0.3](acceptance-v0.3.md)、[0.2](acceptance-v0.2.md)、[0.1](acceptance.md) 保留舊版結果。瀏覽器、console、VM 重啟、持久化、負向 HTTP、封包、ARM、實體硬體、CI 與發布證據不能相互替代。

後續體積優化必須先處理 [SquashFS（zstd／xz）與可寫層／設定分割區](image-size-roadmap.md)，再依文件順序進行其他精簡。
