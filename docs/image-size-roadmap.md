# 體積優化順序：SquashFS 優先

本文件固定 RouterTop 後續體積優化的先後順序。已實作、量測結果及後續設計分開記錄；列入第一優先不代表本版已遷移檔案系統。

| 優先序 | 工作 | 驗收重點 |
|---|---|---|
| **1** | **SquashFS（zstd／xz）唯讀系統，搭配 overlay 或獨立設定分割區** | 以相同套件與程式產生兩種壓縮候選；比較大小、開機時間、尖峰／閒置 RAM，驗證所有網路與持久化功能 |
| 2 | 核心裁剪 | 在明確 x86_64／未來 ARM 板型範圍內精簡驅動與模組，保留開機、儲存、雙 WAN、IPv6、PPP、VLAN、WireGuard 與防火牆必要能力 |
| 3 | Alpine 套件清理 | 依實際依賴、檔案占用及功能驗收移除可選內容；保留 apk 與已承諾的管理／網路功能 |
| 4 | qcow2／sparse 壓縮 | 測量離線虛擬磁碟的實際配置空間與傳輸大小；區分邏輯容量與主機占用，不宣稱這會縮小 kernel／root 或降低 RAM |
| 5 | 進階 initramfs 精簡 | 在唯讀根系統路徑穩定後，再縮減早期啟動內容、重複工具與額外模組，保留救援及設定載入能力 |

## 第一優先的兩條候選路徑

SquashFS 是壓縮唯讀檔案系統，支援 zstd 與 xz 等演算法；本計畫會在同一份根目錄內容上比較兩者，不預先承諾壓縮率或選定勝者。[Linux SquashFS 文件](https://docs.kernel.org/filesystems/squashfs.html)

候選 A 使用 SquashFS 作為唯讀 lower，RAM 或另行設計的可寫 upper 作為 overlay；使用可寫 upper 時，workdir 必須與 upper 位於相同檔案系統，並確認其支援所需的延伸屬性及目錄型別。必須另定升級時 upper 內容的相容與回復規則。[Linux OverlayFS 文件](https://docs.kernel.org/filesystems/overlayfs.html)

候選 B 使用唯讀 SquashFS 系統，保留獨立設定分割區，只持久保存設定 bundle、管理員、TLS、PPP／WireGuard 身分及兩條 WAN 的 DUID；日誌、租約、世代標記與暫存狀態依既有 RAM 生命週期處理。現有 ext4 設定卷可作為相容性設計基礎，但不能直接把現行 RAM root 宣稱為 SquashFS 成果。

兩條候選都要驗證 kernel 的 SquashFS／zstd／xz／overlay 支援與早期載入、唯讀根掛載、必要可寫路徑、檔案擁有者／權限、BIOS／UEFI 啟動，以及未來指定 ARM 板型的驅動。不得為縮小檔案而遺失登入保護或讓設定、憑證與身分於重啟後消失。

## 量測及放行條件

每個候選固定 source／binary hash、套件清單、核心及壓縮工具版本，分別記錄 kernel、early initramfs、SquashFS、ISO、設定磁碟邏輯容量、主機實際占用，以及開機與執行期 RAM。大小差異必須來自實際產物，不把 ZIP／qcow2 壓縮當成作業系統本體的縮減。

第一優先的放行至少包括：冷啟動、Web／console 登入、設定與雙身分保存、四種 DHCP／PPPoE 組合、雙 WAN IPv6／PD 前綴切換及恢復、舊來源阻擋、DNS 更新、VLAN 與 WireGuard 防洩漏回歸。先完成這些，再依表中順序進行後續優化。

qcow2／sparse 處理只對已停止使用的磁碟進行，使用新輸出並比較 guest 可見資料；不可對正在執行的 VM 磁碟做原地轉換。[QEMU qemu-img 文件](https://www.qemu.org/docs/master/tools/qemu-img.html)

## 本版狀態

本次要求完成此優先排序文件；SquashFS zstd／xz 建置、overlay 遷移、裁剪核心、套件移除、虛擬磁碟轉換及進階 initramfs 精簡均為 **NOT_RUN／後續工作**。本版實際映像與新增功能的體積，列在對應版本驗收紀錄。
