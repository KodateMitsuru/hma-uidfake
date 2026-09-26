#!/usr/bin/env bash
# Run clang-tidy over both halves of the project.
#
#   userspace: the tools' own CMake project is configured with CMAKE_EXPORT_COMPILE_COMMANDS,
#              which is what a C++23 target built against the NDK needs -- hand-written flags
#              would have to repeat the sysroot, the standard library and the ABI.
#   kernel:    kbuild-compile-commands.py turns the .cmd files kbuild leaves next to the objects
#              into a database carrying the flags the module was really built with. Build first;
#              the KMI analysed is the first one under build/kmi.
#
# Both halves are silent when they are clean, and the script exits non-zero if either is not.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

ndk=${UG_NDK:-$(ls -d /opt/android-sdk/ndk/* 2>/dev/null | tail -1)}
kmi=$(ls build/kmi 2>/dev/null | head -1)
if [ -z "$kmi" ]; then
  echo "no build/kmi/* -- build the module first" >&2
  exit 1
fi

rc=0

echo "== userspace (compile database from the tools' CMake project)"
cmake -S src/tools -B build/tidy \
      -DCMAKE_TOOLCHAIN_FILE="$ndk/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=24 -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
clang-tidy -p build/tidy --warnings-as-errors='*' src/tools/*.cpp || rc=1
clang-tidy --warnings-as-errors='*' src/tools/uidbench.c -- -std=gnu11 || rc=1

echo "== kernel (compile database from the kbuild .cmd files of $kmi)"
python3 scripts/kbuild-compile-commands.py "$kmi" || rc=1
( cd "/opt/ddk/kdir/$kmi" && clang-tidy -p "$root/build/tidy/kernel" --warnings-as-errors='*' "$root"/src/*.c ) || rc=1

exit $rc
