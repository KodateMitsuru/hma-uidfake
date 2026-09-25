# HMA UID Fake

Kernel-side module that makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

`sync-tool` is the only userspace component. It watches HMA's `config.json` and the
package manager files (`packages.list`, `packages.xml`) with fsnotify, evaluates HMA's
hiding rules into `(caller, target)` pairs and pushes them to the module over generic
netlink (family `kaux`). The kernel side never reads files, never parses JSON and has no
module parameters.

## Layout

```
src/                  kernel module sources (built as hma_uidfake.ko)
  main.c hooks.c policy.c netlink.c
  include/uidfake.h   shared declarations
  Makefile            kbuild fragment (obj-m := hma_uidfake.o)
  tools/              userspace sync tool (own C++23 CMake project)
module/               files that end up in the flashable zip
CMakeLists.txt        build entry point
```

## Build

Requires the DDK (default `/opt/ddk`), an Android NDK and `nlohmann-json` from the distro
(`paru -S nlohmann-json`).

```bash
cmake -S . -B build -DUG_NDK=/opt/android-sdk/ndk/<ver>
cmake --build build                      # -> build/dist/hma-uidfake-<version>.zip
cmake --build build --target ko          # all KMI modules only
cmake --build build --target ko-android14-6.1
cmake --build build --target sync-tool
```

Version and id come from `module/module.prop`.

Kernel modules have to be linked by kbuild (modpost, vermagic, symbol CRCs), and kbuild
writes its objects into its `M=` directory. Each KMI therefore builds in
`build/kmi/<kmi>/`, a directory holding nothing but symlinks to `src/`, so the source
tree itself is never written to.

### KMI matrix

| KMI | status |
|---|---|
| android13-5.10, android13-5.15, android14-5.15, android14-6.1, android15-6.6, android16-6.12, android17-6.18 | built |
| android12-5.10 | not built: that kernel tree uses GCC global register variables and `"Q"` constraints, which clang rejects |

## Install

Flash `build/dist/hma-uidfake-<version>.zip` with KernelSU or Magisk.

```
module.prop  customize.sh  post-fs-data.sh  service.sh  README.md
sync-tool
ko/<kmi>_arm64_hma_uidfake.ko     customize.sh picks one via uname -r
```

`post-fs-data.sh` loads the module with `/data/adb/ksud insmod`; `service.sh` starts
`sync-tool`, which keeps the policy in sync from then on.

## Design invariants

1. Never take the `find_user()` hit path. A hit walks every process
   (`for_each_process_thread`) at roughly 1000x the cost of a miss, so even a small rate of
   unrewritten calls is visible in timing. The module rewrites the syscall argument instead
   and lets the kernel take its own miss branch.
2. The replacement uid must hash into the same bucket as the target
   (`__uidhashfn(uid) = ((uid >> 7) + uid) & 127`). Otherwise the `find_user()` bucket chain
   length differs between a hidden uid and a genuinely absent one.
3. The policy lookup must do constant work: fixed 16-step binary search, fixed 32-entry
   window, indices clamped so every iteration loads, `cmp`+`csel` for the value select.
4. Restore the syscall argument before returning. arm64's `kernel_exit` writes x0..x29 back
   from `pt_regs`, so an unrestored argument shows up in the caller's register.
