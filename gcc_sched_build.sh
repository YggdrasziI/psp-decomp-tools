#!/bin/bash
# Build cc1 and cc1plus of a GCC with another scheduling description and install them
# as a compiler of their own (gcc_sched_scan.py runs this, on Linux or in WSL).
#
#   gcc_sched_build.sh <work tree> <md path in it> <installed compiler> <new install> <md file> <slot>
#
# <work tree>: a configured and built GCC (source and build folders), e.g. the one a
#   toolchain kit leaves; copied once to <work tree>-sched<slot>, so several builds
#   run side by side. <md path in it>: the description to replace, e.g.
#   gcc-4.0.4/gcc/config/mips/allegrex-sched.md; the build folder is <work tree>/build.
# <installed compiler>: copied to <new install>, which then gets the two programs.
# HOST_CFLAGS: flags for the host compiler (default: what an old GCC needs from a
#   modern one). A leading ~/ in a path is the home folder.
set -eu
home() { case "$1" in "~/"*) echo "$HOME/${1#\~/}" ;; *) echo "$1" ;; esac; }
work=$(home "$1"); md=$2; installed=$(home "$3"); new=$(home "$4"); file=$5; slot=$6
tree=$work-sched$slot
[ -d "$tree" ] || cp -a "$work" "$tree"
cp "$file" "$tree/$md"
flags=${HOST_CFLAGS:--O1 -g0 -std=gnu89 -fcommon -fpermissive -w -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0}
(cd "$tree/build/gcc" && make -j"${JOBS:-4}" cc1 cc1plus MAKEINFO=true CFLAGS="$flags" > ../make-sched.log 2>&1) \
  || { grep -E "genattrtab:|rror" "$tree/build/make-sched.log" | tail -5; exit 1; }
rm -rf "$new"
cp -a "$installed" "$new"
dest=$(dirname "$(find "$new" -name cc1plus | head -1)")
cp "$tree/build/gcc/cc1" "$tree/build/gcc/cc1plus" "$dest/"
echo "BUILD_OK $new"
