#!/bin/sh
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=0.2.0
OUTPUT="$REPO/packaging/alpine/routertop-$VERSION.tar.gz"
[ ! -e "$OUTPUT" ] || { echo "Refusing to overwrite $OUTPUT" >&2; exit 1; }
for path in Cargo.toml Cargo.lock crates configs LICENSE; do
    [ -e "$REPO/$path" ] || { echo "Missing source input: $path" >&2; exit 1; }
done
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM
mkdir "$WORK/routertop-$VERSION"
for path in Cargo.toml Cargo.lock crates configs LICENSE; do
    cp -R "$REPO/$path" "$WORK/routertop-$VERSION/"
done
tar -C "$WORK" -czf "$OUTPUT" "routertop-$VERSION"
echo "Created $OUTPUT"
echo 'Run cd packaging/alpine && abuild checksum && abuild -r as an abuild user.'
