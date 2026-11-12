#!/usr/bin/env bash
# Regenerates the ELF fixtures in this directory (see README.md).
# Needs clang (Apple clang 17 was used) and rust-lld (shipped with rustup).
set -euo pipefail
cd "$(dirname "$0")"
LLD=${LLD:-$(find "$(rustc --print sysroot)" -name rust-lld -type f | head -1)}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
link() { "$LLD" -flavor gnu -shared "$@"; }
for t in x86_64-linux-gnu i686-linux-gnu aarch64-linux-android armv7-linux-androideabi \
         aarch64_be-linux-gnu armebv7-linux-gnueabi; do
  clang -target "$t" -fPIC -O1 -c lib.c -o "$tmp/lib-$t.o"
  clang -target "$t" -fPIC -O1 -c dep.c -o "$tmp/dep-$t.o"
  link -soname libdep.so --version-script dep.map "$tmp/dep-$t.o" -o "$tmp/libdep-$t.so"
done
cp "$tmp/lib-x86_64-linux-gnu.o" rela-x86_64.o
cp "$tmp/lib-i686-linux-gnu.o" rel-i686.o
clang -target x86_64-linux-gnu -g -gz=zlib -O1 -c lib.c -o zdebug-x86_64.o
cp "$tmp/libdep-x86_64-linux-gnu.so" libdep-x86_64.so
x=x86_64-linux-gnu; i=i686-linux-gnu; a=aarch64-linux-android; r=armv7-linux-androideabi
b=aarch64_be-linux-gnu; e=armebv7-linux-gnueabi
link --build-id=sha1 --hash-style=gnu "$tmp/lib-$x.o" "$tmp/libdep-$x.so" -o plain-x86_64.so
link --build-id=sha1 --hash-style=gnu -z pack-relative-relocs "$tmp/lib-$x.o" "$tmp/libdep-$x.so" -o relr-x86_64.so
link --hash-style=sysv "$tmp/lib-$i.o" "$tmp/libdep-$i.so" -o plain-i686.so
link --hash-style=sysv -z pack-relative-relocs "$tmp/lib-$i.o" "$tmp/libdep-$i.so" -o relr-i686.so
link --hash-style=both "$tmp/lib-$a.o" "$tmp/libdep-$a.so" -o plain-aarch64.so
link --hash-style=both --pack-dyn-relocs=android "$tmp/lib-$a.o" "$tmp/libdep-$a.so" -o aps2-aarch64.so
link --hash-style=gnu --pack-dyn-relocs=android+relr --use-android-relr-tags "$tmp/lib-$a.o" "$tmp/libdep-$a.so" -o aps2-relr-aarch64.so
link --hash-style=sysv "$tmp/lib-$r.o" "$tmp/libdep-$r.so" -o plain-arm.so
link --hash-style=sysv --pack-dyn-relocs=android "$tmp/lib-$r.o" "$tmp/libdep-$r.so" -o aps2-arm.so
link --hash-style=gnu "$tmp/lib-$b.o" "$tmp/libdep-$b.so" -o plain-aarch64be.so
link --hash-style=gnu -z pack-relative-relocs "$tmp/lib-$b.o" "$tmp/libdep-$b.so" -o relr-aarch64be.so
link --hash-style=sysv "$tmp/lib-$e.o" "$tmp/libdep-$e.so" -o plain-armbe.so
link --hash-style=sysv --pack-dyn-relocs=android "$tmp/lib-$e.o" "$tmp/libdep-$e.so" -o aps2-armbe.so
