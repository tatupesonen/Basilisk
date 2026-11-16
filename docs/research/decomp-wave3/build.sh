#!/bin/sh
# Build one wave-3 oracle prototype (D07, D08) against a reference build's optimised objects.
# usage: build.sh REF SRC.cc OUT
# REF is the reference directory (../reference on the Mac,
# $BASILISK_REFERENCE_DIR on the build host).  Flags are the Makefile's
# com_opt flags plus build-reference.sh's ADDITIONAL_FLAGS, so class layouts
# match the objects; -fno-access-control reads private members.
set -eu
REF=$1; SRC=$2; OUT=$3
CPP="$REF/src/cpp"
OBJS=$(ls "$CPP"/com_opt/*.o | grep -v '/consolemain\.o$')
${CXX:-g++} -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -ffp-contract=off -D__TERMINAL__ \
  -fno-access-control -I "$CPP" -o "$OUT" "$SRC" $OBJS "$REF/src/zlib/libz.a"
