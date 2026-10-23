#!/bin/sh
# Provision a NEW regular image file only. Never accepts a block device.
set -eu
umask 077
OUTPUT=${1:?usage: sh scripts/make-data-disk.sh NEW-FILE.img}
for tool in mkfs.ext4 sfdisk truncate dd mktemp; do command -v "$tool" >/dev/null || exit 1; done
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || { echo 'Refusing to overwrite existing path' >&2; exit 1; }
# noclobber prevents a concurrent creator from replacing our destination.
(set -C; : > "$OUTPUT")
[ -f "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || exit 1
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM
truncate -s 32M "$WORK/data.ext4"
mkfs.ext4 -q -F -L ROUTERTOP_DATA "$WORK/data.ext4"
truncate -s 33M "$OUTPUT"
printf 'label: dos\nstart=2048, type=83\n' | sfdisk "$OUTPUT" >/dev/null
dd if="$WORK/data.ext4" of="$OUTPUT" bs=512 seek=2048 conv=notrunc status=none
echo "Created $OUTPUT (33 MiB regular-file data disk, ext4 label ROUTERTOP_DATA)."
