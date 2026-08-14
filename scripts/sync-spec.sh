#!/bin/sh
# Sync docs/drop.txt from the uhub tree, where the specification is authored.
#
# The copy here is kept byte-identical so the two can be compared with cmp;
# provenance lives in README.md rather than in a header, which would itself be
# a difference. Run with --check to verify without writing (for CI or a hook).
set -eu

uhub="${UHUB_DIR:-../uhub}"
src="$uhub/doc/drop.txt"
dst="$(dirname "$0")/../docs/drop.txt"

if [ ! -f "$src" ]; then
    echo "sync-spec: $src not found; set UHUB_DIR to your uhub checkout" >&2
    exit 2
fi

if [ "${1:-}" = "--check" ]; then
    if cmp -s "$src" "$dst"; then
        echo "docs/drop.txt is in sync with $src"
    else
        echo "docs/drop.txt has drifted from $src:" >&2
        diff -u "$dst" "$src" >&2 || true
        exit 1
    fi
else
    cp "$src" "$dst"
    echo "docs/drop.txt synced from $src"
fi
