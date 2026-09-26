# HMA UID Fake

Kernel-side module that makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

The rules that apply to a process are decided by the app it was **born from**, not by the uid it
happens to hold when it calls, so an isolated process, an `app_zygote` child or anything that called
`setuid()` answers exactly as that uid would if it did not exist -- which is what makes the answer
survive a second question asked after changing uid.

## Data flow

```
/data/user/0/com.tsng.hidemyapplist/files/config.json   HMA's rules
/data/system/packages.list                              package name -> uid
        |  fsnotify
        v
sync-tool      the only userspace part: watches, evaluates, pushes
        |  generic netlink, family "kaux"
        v
(caller, target) pairs  +  caller code dirs (dev, ino, uid)
        v
kernel         sys_call_table           ten entries   uid scans, setuid family
               compat_sys_call_table    ten entries   AArch32
               android_vh_check_file_open             naming an isolated child
```

The kernel never reads a file, never parses JSON and never resolves a package name: it compares
numbers.

## Kernel

### Queries

The four syscalls a uid scanner uses have their entry points patched in `sys_call_table` (and the
AArch32 numbers in `compat_sys_call_table`), never the syscalls themselves: the hook substitutes the
uid argument and calls the original, which then takes its own "no such uid" branch. The caller side
comes from the birth tag rather than from the current uid -- one table load and a `csel` -- so
changing uid cannot move a process into a different set of rules.

### Naming an isolated child

An isolated process gets its uid at birth and nothing else says which app it came from, so the
module watches for the moment that becomes observable:

1. **Birth.** When zygote hands an app uid to a fresh process, or `app_zygote` hands an isolated uid
   to one, the app id goes into bits 40..55 of `thread_info.flags` (zero = untagged), and an
   isolated child also gets a pending bit above that field, so the hot path tests both with one AND.
   The tag is never rewritten or cleared, and `fork()` copies it.
2. **The first code file it opens.** While the pending bit is set, the vendor hook looks at
   consecutive opens until one lands on a filesystem an app's code lives on -- the framework's own
   startup reads properties, `/proc`, `/dev` and `/system`, none of which counts. From
   `file->f_path.dentry` it walks up at most four dentries comparing inodes against the registered
   caller code dirs; a hit names the whole thread group after that app, whichever file inside the
   directory was opened (apk, vdex, odex, library). A miss ends the wait for good.
3. **Before the module loads.** `uidfake_tag_prime()` derives the same tag for every running task
   from its uid and the SELinux sid of its creds, the pair the zygote path writes -- without it a
   manual `rmmod`/`insmod` would lose the identity of every running app. That pair is also what the
   `setuid`-family hooks write, which is why they are hooked: `setuid()` cannot choose its rules.

### Diagnostics

Diagnostics sit behind a static key (jump label): with the key off the branch is a NOP, so a normal
boot carries none of it.

```
insmod hma_uidfake.ko debug=1        # for 60 seconds, then off again
```

Only the two lines that report a real event are ungated (`iso birth uid ... marked`, `iso uid ...
belongs to app ...`). Everything else -- the devs treated as code, a directory an open reached with
no rule for it, an untagged caller -- is what the parameter is for.

## Design invariants

1. Never take the `find_user()` hit path: it walks every process at ~1000x the cost of a miss, and
   even a small rate of unrewritten calls is visible in timing. The module rewrites the syscall
   argument instead and lets the kernel take its own miss branch.
2. The replacement uid hashes into the same bucket as the target
   (`__uidhashfn(uid) = ((uid >> 7) + uid) & 127`), or the bucket chain length would differ between
   a hidden uid and a genuinely absent one.
3. The lookup does constant work: the target is hashed once with the kernel's own uid hash (read
   back from `find_user()` when a policy is applied), giving both the bucket line and the starting
   slot; the line index is that formula or its mirrored twin, whichever keeps the address
   independent of the contents; the number of probes is fixed when the policy is laid out (1, 2, 4
   or 8) and each reads its slot *and* the mask words of all eight; indices are masked, never
   branched on; `cmp`+`csel` picks the bit and the replacement. What a query touches is a function
   of `(caller, target)` alone -- `scripts/lookup_model.py` states that function.
4. Never touch the syscall's own `pt_regs`: the probe sits on `find_user()`, the first place a uid
   is a plain argument register, and substitutes it there. `/proc/<tid>/syscall`, ptrace, the
   syscall-exit stop and audit can only ever show the original argument, and there is nothing to
   restore. (arm64 has no in-register syscall entry to hook: no `__do_sys_`/`__se_sys_` symbol.)
5. The kernel only compares numbers; whatever needs a path, a package name or JSON happens in
   `sync-tool`, and the kernel checks the shape and size of what arrives.
6. A rejected update changes nothing: a policy that does not fit, a caller that is not an app uid, a
   group larger than the tables -- each is logged and the previous policy stays in force, because
   half a policy is exactly the state that leaks.

## Trust assumptions

- The netlink family is `GENL_ADMIN_PERM`: only root can push a policy, both blobs are length-checked
  before they are parsed, and nothing is copied back out.
- HMA's `config.json` is the policy's source of truth and belongs to HMA's uid -- whoever can write
  it decides who is hidden, and `sync-tool` reads nothing an app can write.
- The tag lives in bits 40..55 of `thread_info.flags`, which nothing else uses on these kernels, and
  is only ever read-modify-written with those bits masked out: a kernel that grew a flag there would
  collide with the tag rather than be corrupted by it.
- The ten hooked syscalls take at most three arguments, which is what the register object handed to
  them covers.
- Normal runs print no addresses; the two init lines that do are behind the debug key.
- The timing difference between a hidden and an absent uid is measured (`src/tools/uidbench.c`), not
  assumed away.

## Protocol

Little endian, same layout as `src/tools/netlink.cpp`.

```
KAUX_CMD_SET  (1)  blob: u32 npairs, then npairs * (caller, target); caller 0 = any caller
KAUX_CMD_PING (2)  no payload, ACK only
KAUX_CMD_APK  (3)  blob: u32 n, then n * (st_dev, ino_lo, ino_hi, uid)
```

Family `kaux`, version 1, all three commands `GENL_ADMIN_PERM`; a blob over 32 KiB is rejected
before it is parsed.

| limit | value |
|---|---|
| `(caller, target)` pairs | 4096 |
| callers | 4096 |
| code dirs (`UF_APK_MAX`) | 1024 |
| dentries walked per open (`UF_DIR_DEPTH`) | 4 |
| netlink blob (`MAX_BLOB_BYTES`) | 32 KiB |

## Layout

```
src/                  kernel module (hma_uidfake.ko)
  hooks.c             table entries, vendor hook, naming walk
  policy.c            the two tables and the query
  netlink.c           family "kaux"
  main.c              module parameter, static key, init/exit
  patch.c             text patching behind the table rewrite
  include/            declarations, per-KMI compatibility
  Makefile            kbuild fragment (obj-m := hma_uidfake.o)
  tools/              userspace (own C++23 CMake project)
    sync.cpp watcher.cpp hma.cpp packages.cpp netlink.cpp
    uidbench.c        side-channel detector, built by hand (see Tests)
module/               what ends up in the flashable zip
scripts/              host tests, access-shape model, symbol gate, lint
.github/workflows/    one build job per KMI, then pack
CMakeLists.txt        build entry point
```

## Build

Requires the DDK (default `/opt/ddk`), an Android NDK and `nlohmann-json` (`paru -S nlohmann-json`).

```bash
cmake -S . -B build -DUG_NDK=/opt/android-sdk/ndk/<ver>
cmake --build build                      # -> build/dist/hma-uidfake-<version>.zip
cmake --build build --target ko          # all KMI modules only
cmake --build build --target ko-android14-6.1
cmake --build build --target sync-tool
```

Each KMI builds with the compiler its kernel was built with -- clang CFI and the shadow call stack
come from that compiler, so mixing is not an option -- inside `build/kmi/<kmi>/`, a directory holding
only symlinks to `src/`, because kbuild has to link the module itself and writes its objects into
its `M=` directory.

| KMI | kernel | DDK clang |
|---|---|---|
| android12-5.10 | 5.10 | clang-r416183b |
| android13-5.10 | 5.10 | clang-r450784e |
| android13-5.15 | 5.15 | clang-r450784e |
| android14-5.15 | 5.15 | clang-r487747c |
| android14-6.1 | 6.1 | clang-r487747c |
| android15-6.6 | 6.6 | clang-r510928 |
| android16-6.12 | 6.12 | clang-r536225 |
| android17-6.18 | 6.18 | clang-r584948c |

`-DUG_USE_PREBUILT_KO=ON` packs the modules already in `build/ko` (what the CI packaging job does).
Version and `versionCode` come from the git tag, and `module/module.prop` keeps only the fallback for
a source tree without git. A `v*` tag makes the CI build, attach a release and refresh the
`update.json` that `module.prop` points `updateJson` at.

## Install

Flash `build/dist/hma-uidfake-<version>.zip` with KernelSU or Magisk.

```
module.prop  customize.sh  post-fs-data.sh  service.sh  README.md
sync-tool
ko/<kmi>_arm64_hma_uidfake.ko     customize.sh picks one via uname -r
```

`customize.sh` reads the branch (`android14`) and the kernel version (`6.1`) out of `uname -r` and
asks for `android14-6.1`; a branch with no module in the zip is reported instead of being replaced by
another branch's module. `post-fs-data.sh` loads the module with `/data/adb/ksud insmod`, and
`service.sh` starts `sync-tool`, which appends to `state/sync.log` (the kernel logs to dmesg).

Until the credential-encrypted storage is up, `sync-tool` waits on the property AOSP sets after the
unlock -- on the property's own futex, not by polling -- and from then on it is driven by fsnotify
with a 60 second resync in case a watch was lost.

```
sync-tool --once                              # evaluate and push once, then exit
sync-tool --config <json> --list <packages.list>
```

## Tests

```bash
bash scripts/run-hosttest.sh        # the real policy.c against the scripts/hosttest shims
cc -O1 -I src -I scripts/hosttest -I src/include \
   -o build/branch_encode_test scripts/branch_encode_test.c && ./build/branch_encode_test
python3 scripts/lookup_model.py     # addresses and load counts per query
bash scripts/check-undefined.sh     # every undefined symbol is exported by that KMI
bash scripts/test-kmi-map.sh        # uname -r -> KMI, and whether the zip carries it
bash scripts/run-clang-tidy.sh      # both halves, see below
```

The first two compile the real sources, so they catch what a model cannot see (word sizes, field
order, a branch encoding that writes into kernel text and has to be exact); the model states what
the C cannot assert about itself; and the symbol gate reads the DDK's per-KMI `Module.symvers`, the
same table kbuild uses.

Formatting and analysis follow the same split as the code: the module and the test sources use the
kernel's `.clang-format`, the userspace helper uses LLVM's, and `scripts/run-clang-tidy.sh` analyses
both halves -- the kernel one with the flags kbuild really compiled with, taken from its `.cmd`
files.

`src/tools/uidbench.c` is the side-channel detector and is not part of the build; cross-compile it
and run it as an app uid that hides:

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -o uidbench src/tools/uidbench.c
```

It samples the hidden, absent and unhooked cases in the same round and reports paired deltas, t
statistics and the sample count an attacker would need for a 5 sigma decision.
