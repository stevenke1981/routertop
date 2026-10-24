#!/bin/sh
# Native Alpine root builder. Does not mount or format any physical disk.
set -eu
export LC_ALL=C
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROFILE=${PROFILE:-x86_64}
ALPINE_BRANCH=${ALPINE_BRANCH:-v3.24}
MIRROR=${MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
OUT=${OUT:-"$REPO/dist/$PROFILE"}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1792713600}
MAKE_ISO=${MAKE_ISO:-1}
die() { echo "build-image: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die 'run inside a disposable Alpine VM/container as root'
[ "$(uname -s)" = Linux ] || die 'native Linux required'
case "$PROFILE" in x86_64) ;; aarch64) die 'ARM profile is reserved and not yet boot-tested';; *) die 'unknown profile';; esac
. "$REPO/image/profiles/$PROFILE.env"
[ "$(uname -m)" = "$ARCH" ] || die "native $ARCH builder required"
case "$ALPINE_BRANCH" in v[0-9]*.[0-9]*) ;; *) die 'use a stable Alpine vMAJOR.MINOR branch';; esac
case "$MIRROR" in https://*) ;; *) die 'HTTPS package mirror required';; esac
for cmd in apk cpio gzip find sort sha256sum chroot install touch; do command -v "$cmd" >/dev/null || die "missing builder tool: $cmd"; done
[ -d /etc/apk/keys ] || die 'trusted Alpine apk keys required'
if [ "$MAKE_ISO" = 1 ]; then
    command -v grub-mkrescue >/dev/null || die 'install grub grub-bios grub-efi xorriso mtools, or set MAKE_ISO=0'
fi
BINARY_RUST_TARGET=${ROUTERTOP_BINARY_TARGET:-unknown-prebuilt}
if [ -z "${ROUTERTOP_BINARY:-}" ]; then
    # Alpine's packaged rustc can use x86_64-alpine-linux-musl. Its shipped
    # standard library need not include rustup's x86_64-unknown-linux-musl.
    BINARY_RUST_TARGET=$(rustc -vV | sed -n 's/^host: //p')
    case "$BINARY_RUST_TARGET" in "$ARCH"-*-linux-musl) ;; *) die 'native Alpine musl Rust toolchain required';; esac
    (cd "$REPO" && cargo build --locked --release --target "$BINARY_RUST_TARGET" --target-dir "$REPO/target/image-native")
    ROUTERTOP_BINARY="$REPO/target/image-native/$BINARY_RUST_TARGET/release/routertop"
fi
case "$BINARY_RUST_TARGET" in ''|*[!a-zA-Z0-9_-]*) die 'invalid ROUTERTOP_BINARY_TARGET metadata';; esac
[ -f "$ROUTERTOP_BINARY" ] || die 'ROUTERTOP_BINARY does not exist'
[ -f "$REPO/configs/routertop.toml" ] || die 'default router configuration missing'
# Refuse replacement of an existing artifact set. The caller chooses a new OUT.
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || die 'OUT must be empty (choose a fresh output directory)'
OUT=$(CDPATH= cd -- "$OUT" && pwd)
WORK=$(mktemp -d "$OUT/.build.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM
ROOT="$WORK/root"
mkdir -p "$ROOT/etc/apk/keys" "$ROOT/etc/network" "$ROOT/etc/routertop" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/run" "$ROOT/tmp"
cp /etc/apk/keys/*.pub "$ROOT/etc/apk/keys/"
printf '%s/%s/main\n%s/%s/community\n' "$MIRROR" "$ALPINE_BRANCH" "$MIRROR" "$ALPINE_BRANCH" > "$ROOT/etc/apk/repositories"
# Package installation scripts are deliberately skipped: this avoids mounting
# the host /dev or running kernel initramfs hooks in the image being assembled.
# We initialize the BusyBox links and module index explicitly below.
apk --root "$ROOT" --arch "$ARCH" --initdb --no-cache --no-progress --no-scripts add $(cat "$REPO/image/packages.txt")
chroot "$ROOT" /bin/busybox --install -s
# --no-scripts omits dnsmasq's pre-install account creation. Initialize its
# dedicated unprivileged account explicitly, rather than running DNS as root.
if ! grep -q '^dnsmasq:' "$ROOT/etc/group"; then
    chroot "$ROOT" /usr/sbin/addgroup -S dnsmasq
fi
if ! grep -q '^dnsmasq:' "$ROOT/etc/passwd"; then
    chroot "$ROOT" /usr/sbin/adduser -S -D -H -s /sbin/nologin -G dnsmasq dnsmasq
fi
mkdir -p "$ROOT/var/lib/misc"
chroot "$ROOT" /usr/sbin/addgroup -g 1000 routertop
chroot "$ROOT" /usr/sbin/adduser -D -H -u 1000 -s /sbin/nologin -G routertop routertop
cp -a "$REPO/image/overlay/." "$ROOT/"
install -m 0755 "$ROUTERTOP_BINARY" "$ROOT/usr/sbin/routertop"
install -m 0644 "$REPO/configs/routertop.toml" "$ROOT/etc/routertop/routertop.toml"
chmod 0755 "$ROOT/init" "$ROOT/usr/sbin/routertop-boot" "$ROOT/usr/sbin/routertop-storage" "$ROOT/usr/sbin/routertop-management" "$ROOT/usr/sbin/routertop-web-supervisor"
chmod 0755 "$ROOT/usr/sbin/routertop-wan-check"
chmod 0755 "$ROOT/usr/sbin/routertop-console"
for event in bound renew; do
    mkdir -p "$ROOT/etc/udhcpc/post-$event"
    ln -s /usr/sbin/routertop-wan-check "$ROOT/etc/udhcpc/post-$event/10-routertop"
done
mkdir -p "$ROOT/usr/share/routertop/www/cgi-bin"
cp "$REPO/web/index.html" "$REPO/web/app.js" "$REPO/web/style.css" "$ROOT/usr/share/routertop/www/"
ln -s /usr/sbin/routertop "$ROOT/usr/share/routertop/www/cgi-bin/routertop.cgi"
# Both fully static and Alpine-native dynamically linked musl binaries are
# accepted. This execution must succeed with only the image's own libraries.
chroot "$ROOT" /usr/sbin/routertop check /etc/routertop/routertop.toml
for modules in "$ROOT"/lib/modules/*; do
    [ -d "$modules" ] || continue
    chroot "$ROOT" /sbin/depmod -a "$(basename "$modules")"
done
cp "$ROOT/boot/$KERNEL_FILE" "$OUT/vmlinuz"
apk --root "$ROOT" info -v | sort > "$OUT/packages.txt"
cp "$ROOT/etc/apk/repositories" "$OUT/repositories.txt"
# Preserve runtime libraries, licenses and apk's database; discard duplicate
# boot artifacts and package cache, which are unnecessary in the RAM root.
rm -rf "$ROOT/boot" "$ROOT/var/cache/apk"
mkdir -p "$ROOT/boot" "$ROOT/var/cache/apk"
chown -R 0:0 "$ROOT"
chroot "$ROOT" /bin/chown dnsmasq:dnsmasq /var/lib/misc
find "$ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$ROOT" && find . -print0 | sort -z > "$WORK/root-files.list")
(cd "$ROOT" && cpio --null -o --format=newc < "$WORK/root-files.list" > "$WORK/root.cpio" 2>"$OUT/cpio.log")
gzip -n -9 < "$WORK/root.cpio" > "$OUT/initramfs.gz"
if [ "$MAKE_ISO" = 1 ]; then
    mkdir -p "$WORK/iso/boot/grub"
    cp "$OUT/vmlinuz" "$OUT/initramfs.gz" "$WORK/iso/boot/"
    cp "$REPO/image/grub.cfg" "$WORK/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$OUT/routertop-x86_64.iso" "$WORK/iso"
fi
KERNEL_BYTES=$(wc -c < "$OUT/vmlinuz" | tr -d ' ')
INITRAMFS_BYTES=$(wc -c < "$OUT/initramfs.gz" | tr -d ' ')
BINARY_HASH=$(sha256sum "$ROUTERTOP_BINARY" | cut -d ' ' -f 1)
cat > "$OUT/build-manifest.json" <<EOF
{"product":"RouterTop","architecture":"$ARCH","alpine_branch":"$ALPINE_BRANCH","rust_target":"$BINARY_RUST_TARGET","kernel_bytes":$KERNEL_BYTES,"initramfs_bytes":$INITRAMFS_BYTES,"compressed_boot_bytes":$((KERNEL_BYTES + INITRAMFS_BYTES)),"routertop_sha256":"$BINARY_HASH","source_date_epoch":$SOURCE_DATE_EPOCH,"package_lock":"packages.txt","boot_test":"NOT_RUN","signed":false,"configuration_persistence":"ext4-data-volume-required","management":"LAN-HTTPS","version":"0.4.0"}
EOF
(cd "$OUT" && sha256sum vmlinuz initramfs.gz packages.txt repositories.txt build-manifest.json > SHA256SUMS; if [ -f routertop-x86_64.iso ]; then sha256sum routertop-x86_64.iso >> SHA256SUMS; fi)
echo "Built $OUT: compressed kernel + root $((KERNEL_BYTES + INITRAMFS_BYTES)) bytes (64 MiB aspirational budget)."
echo 'Artifact creation does not prove boot, DHCP, DNS, NAT or hardware compatibility.'
