[CmdletBinding()]
param(
    [string]$ImageDirectory = (Join-Path $PSScriptRoot '../dist/v0.8'),
    [string]$Qemu = 'qemu-system-x86_64',
    [int]$MemoryMiB = 512,
    [string]$DataDisk,
    [int]$ManagementPort = 19443,
    [switch]$Iso,
    [switch]$ShowWindow
)
$ErrorActionPreference = 'Stop'
$imagePath = (Resolve-Path -LiteralPath $ImageDirectory).Path
$qemuPath = (Get-Command $Qemu -ErrorAction Stop).Source
$qemuArgs = @('-name', 'RouterTop development', '-machine', 'q35', '-accel', 'tcg',
    '-m', "$MemoryMiB", '-smp', '2',
    '-netdev', 'user,id=wan', '-device', 'virtio-net-pci,netdev=wan,mac=52:54:00:88:00:01',
    '-netdev', "user,id=lan,net=192.168.88.0/24,dhcpstart=192.168.88.200,restrict=on,hostfwd=tcp:127.0.0.1:$ManagementPort-192.168.88.1:443",
    '-device', 'virtio-net-pci,netdev=lan,mac=52:54:00:88:00:02')
if ($DataDisk) {
    $dataPath = (Resolve-Path -LiteralPath $DataDisk).Path
    if (-not (Test-Path -LiteralPath $dataPath -PathType Leaf)) { throw 'DataDisk must be an existing image file.' }
    $qemuArgs += @('-drive', "file=$dataPath,format=raw,if=virtio")
}
if ($Iso) {
    $isoPath = Join-Path $imagePath 'routertop-x86_64.iso'
    if (-not (Test-Path -LiteralPath $isoPath -PathType Leaf)) { throw "Missing image: $isoPath" }
    $qemuArgs += @('-cdrom', $isoPath, '-boot', 'd')
} else {
    $kernelPath = Join-Path $imagePath 'vmlinuz'
    $initramfsPath = Join-Path $imagePath 'initramfs.gz'
    foreach ($file in @($kernelPath, $initramfsPath)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing image: $file" }
    }
    $qemuArgs += @('-kernel', $kernelPath, '-initrd', $initramfsPath,
        '-append', 'console=tty0 console=ttyS0,115200n8 panic=10')
}
if ($ShowWindow) { $qemuArgs += @('-serial', 'stdio') }
else { $qemuArgs += @('-display', 'none', '-serial', 'mon:stdio') }
Write-Host 'Starting RouterTop. Local consoles require the persistent Web administrator password; first boot offers create/token.'
Write-Host "HTTPS management with a provisioned data disk: https://127.0.0.1:$ManagementPort"
Write-Host 'WAN uses QEMU user networking; LAN management is forwarded only on localhost.'
Write-Host 'This launcher checks boot; use the two-VM topology for DHCP/DNS/NAT acceptance.'
& $qemuPath @qemuArgs
exit $LASTEXITCODE
