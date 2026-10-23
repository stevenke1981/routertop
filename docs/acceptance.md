# RouterTop 0.1.0 驗收紀錄

日期：2026-10-23～24（Asia/Taipei）。這是 x86_64 開發映像驗收，不是 RouterOS 全功能驗收或正式發布。

## 成品

| 產物 | 實際大小 |
|---|---:|
| `dist/x86_64/routertop-x86_64.iso` | 64,022,528 bytes / **61.06 MiB** |
| kernel + initramfs | 50,901,546 bytes / **48.54 MiB** |
| Rust 管理程式 | 647,712 bytes / **632.53 KiB** |

ISO SHA256：`07b139231a20d6c85cfa880a9dc9aed1c136173dca2dadcfe4fc3bf00bd6f696`。

基礎為 Alpine v3.24 signed repositories，49 個套件，Linux `6.18.58-0-virt`，apk `3.0.8-r0`。建置 toolchain 為 Alpine Rust `1.96.1`、`x86_64-alpine-linux-musl`；Windows 測試 toolchain 為 Rust `1.99.0`。Rust binary 是 Alpine musl native build，映像包含實際需要的 libgcc；不宣稱完全 static。

## 已執行結果

| 項目 | 狀態 | 證據 |
|---|---|---|
| Windows cargo test | PASS | 7 core + 2 CLI tests；exit 0 |
| Linux cargo test --locked | PASS | 同樣 9 tests；`evidence/linux-final.log` |
| Windows fmt / Clippy | PASS | `cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`；exit 0 |
| Linux release build | PASS | `cargo build --locked --release`，4m42s TCG；`evidence/linux-final.log` |
| Alpine image build | PASS | chroot 中執行 binary、建立 ISO；`evidence/image-build2.log` |
| 產物下載雜湊 | PASS | 所有 builder SHA256SUMS 在 Windows 重新計算相符 |
| BIOS ISO 開機 | PASS | QEMU q35/TCG，512 MiB；`evidence/iso-bios-boot.log` |
| UEFI ISO 開機 | PASS | 同一 ISO，EDK2，256 MiB；`evidence/iso-uefi-boot.log` |
| 實際 appliance 狀態 | PASS | WAN `10.0.2.15/24`、LAN `192.168.88.1/24`、預設 route、nft table、apk 可執行；`evidence/appliance-status.log` |
| 第二台 VM 經成品路由 | PASS | DHCP 得 `192.168.88.158/24`，gateway/DNS `192.168.88.1`，外部 DNS A 查詢與 NAT HTTP 下載成功；`evidence/two-vm-routing.log` |
| 隔離 namespace 防火牆／網路 | PASS | DHCP、DNS、HTTP NAT、WAN TCP default-drop、保留其他 nft table、IPv6 forwarding 關閉；`evidence/image-build.log` 前段 |
| 重複 apply 防護 | PASS | 開機後 `apply --boot` 明確拒絕；`evidence/uefi-runtime.log` |
| Odin | PASS | 正確 workspace live analysis + 真實 Rust LSP symbols；`evidence/odin-structure.json` 與工具回傳 |
| 獨立審查 | PASS（限靜態範圍） | reviewer 找到 hostname 與開機 markers 缺陷，修復後回驗；不代替上述 runtime 證據 |

256 MiB VM 開機後 `/proc/meminfo`：MemTotal 215436 kB、MemAvailable 135648 kB。這是單次閒置取樣，並非最低記憶體承諾、壓力測試或效能基準。

## 重現

Linux builder 按 `image/README.md` 操作。網路測試需 root 及 iproute2、nftables、dnsmasq、busybox（含 udhcpc/nslookup）、busybox-extras（httpd）、curl：

```sh
cargo test --locked
cargo build --locked --release
sh scripts/netns-smoke.sh "$PWD/target/release/routertop"
ROUTERTOP_BINARY="$PWD/target/release/routertop" sh scripts/build-image.sh
```

BIOS/UEFI 使用同一 ISO。實際雙 VM 拓樸：router eth0 -> QEMU user WAN；router eth1 -> localhost QEMU socket LAN；第二台 Alpine client 只有該 LAN 網卡。Client 執行 udhcpc、向 `192.168.88.1` 查 DNS，再下載 WAN 側 HTTP 測試檔。未橋接主機實體 LAN，也沒有格式化或掛載實體磁碟。

## 保留的失敗與修正

1. Alpine distro Rust 不含 `x86_64-unknown-linux-musl` target，第一次 explicit-target build 失敗；改用實際 native `x86_64-alpine-linux-musl`，原始結果留在 `evidence/linux-build.log`。
2. IPv4 fixture 的 BusyBox nslookup 同時問 AAAA 而收到 REFUSED；測試改用 `-type=A`，保留失敗 `evidence/linux-final.log`。此版 IPv6 並未因此被宣稱支援。
3. 首次 image chroot 缺 `libgcc_s.so.1`；補入 libgcc 套件並重建，`image-build.log` 保留原始錯誤，`image-build2.log` 為成功結果。

## 尚未完成

**NOT_RUN：** ARM/aarch64 建置及開機、實體 x64 硬體、長時間負載／吞吐、設定分割區讀取、靜態路由實際封包、正式 CLI APK 建置與簽署、Secure Boot、遠端 CI。

**尚未實作：** 安裝器、可寫設定服務、即時配置 rollback、認證 Web/API、VPN、VLAN/bridge、IPv6 routing、BGP/OSPF、QoS 管理、無線管理、A/B 更新。詳見 feature-matrix.md。

**發布 N/A：** 沒有外部發布或推送。Git 初始 commit 因沒有 author identity 未建立；沒有擅自設定全域身分。產物是免密碼本機 console 的 RAM 開發版，不是正式網路設備映像。

Builder manifest 保留建立當下的 `boot_test: NOT_RUN`；後續 boot 結果記於 `evidence/handoff.json`，以成品 SHA256 綁定，沒有修改原始 build metadata 冒充建置時已驗證。
