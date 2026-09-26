# HMA UID Fake

Kernel-side module that makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

The rules that apply to a process are decided by the app it was **born from**, not by the uid it
happens to have when it calls. An isolated process, an `app_zygote` child, or anything that called
`setuid()` still answers exactly as that uid would if it did not exist. That is what makes the
answer survive the obvious counter-move: ask the same question twice, once before and once after
changing uid.

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
        |
        v
kernel         sys_call_table           ten entries   uid scans, setuid family
               compat_sys_call_table    ten entries   AArch32
               android_vh_check_file_open             naming an isolated child
```

`sync-tool` turns HMA's config into `(caller, target)` pairs and, per caller, registers the inode
of the directory its code lives in. The kernel never reads a file, never parses JSON and never
resolves a package name: it compares numbers.

## Kernel

### Queries

`getpriority(PRIO_USER)`, `setpriority(PRIO_USER)`, `ioprio_get(IOPRIO_WHO_USER)` and
`ioprio_set(IOPRIO_WHO_USER)` are what a uid scanner uses. Their entry points are patched in
`sys_call_table` (and the AArch32 numbers in `compat_sys_call_table`), never the syscalls
themselves: the hook substitutes the uid argument and calls the original, which then takes its own
"no such uid" branch. The setuid family is hooked for a different reason -- see "Naming an
isolated child".

The tables are laid out so that a query touches the same addresses and performs the same loads
whatever the policy says, and the caller side is resolved from the tag a process was born with
rather than from its current uid -- one table load and a `csel`, and no way to move a process into
a different set of rules by changing uid. See "Design invariants".

### Naming an isolated child

An isolated process is given its uid at birth and nothing else says which app it came from, so the
module watches for the moment its identity does become observable:

1. **Birth.** When zygote hands an app uid to a fresh process, or `app_zygote` hands an isolated
   uid to one, the app id is written into the free high bits of `thread_info.flags` (bits 40..55;
   zero means untagged). An isolated child also gets a pending bit above that field (bit 55), so
   the hot path tests the whole thing with one AND. The tag is never rewritten or cleared and
   `fork()` copies it, so a child keeps answering as the app it came from.
2. **The first code file it opens.** The pending bit makes the vendor hook look at consecutive
   opens until one lands on a filesystem an app's code lives on (`uidfake_dev_is_code`): while the
   framework is still setting the process up it reads properties, `/proc`, `/dev` and `/system`,
   and none of that counts. From `file->f_path.dentry` it walks up at most four dentries,
   comparing each ancestor's inode against the registered caller code dirs; a hit names the whole
   thread group after that app, whichever file inside the directory was opened (apk, vdex, odex or
   a library). A miss ends the wait for good -- the process keeps no rules of its own, and the
   module logs which directory was reached.
3. **Before the module loads.** Processes that already exist get their identity from
   `uidfake_tag_prime()`, which walks the running system and derives the same tag from each task's
   uid and the SELinux sid of its creds, the pair the zygote path uses. Without it, a manual
   `rmmod`/`insmod` would lose the identity of every running app until it restarted. The same pair
   is what the `setuid`-family hooks write, which is why they are hooked at all: `setuid()` cannot
   choose which rules apply to the process that calls it.

### Diagnostics

Diagnostics sit behind a static key: with the key off the branch is patched to a NOP (jump label),
so a normal boot carries none of this code.

```
insmod hma_uidfake.ko debug=1        # names things for 60 seconds, then turns itself off
```

Two lines stay outside the key, because they say something real happened and are never reached on
any hot path:

```
uidfake: iso birth uid 9905x marked, awaiting the apk it opens
uidfake: iso uid 9905x belongs to app 10333, from the apk it opened
```

The gated ones are: the devs treated as code (`code dev N`), the directory an open reached when
nothing matched (`no rule: <parent>/<name> (ino ...) depth N`), an isolated child that reached its
own code with no rule for it, and an untagged caller that asked anyway.

## Design invariants

1. Never take the `find_user()` hit path. A hit walks every process
   (`for_each_process_thread`) at roughly 1000x the cost of a miss, so even a small rate of
   unrewritten calls is visible in timing. The module rewrites the syscall argument instead
   and lets the kernel take its own miss branch.
2. The replacement uid must hash into the same bucket as the target
   (`__uidhashfn(uid) = ((uid >> 7) + uid) & 127`). Otherwise the `find_user()` bucket chain
   length differs between a hidden uid and a genuinely absent one.
3. The policy lookup must do constant work. The target is hashed once with the kernel's own uid
   hash (whose formula is read back from `find_user()` when a policy is applied), which gives
   both the bucket line -- eight buckets per line -- and the starting slot inside it. The line
   index is that same formula or its mirrored twin, whichever the layout needs to keep the
   address independent of the contents. The number of probes into the line is fixed when the
   policy is laid out (1, 2, 4 or 8), every probe reads its slot *and* the mask word(s) covering
   all eight slots, the probe index is masked with `& 7` so nothing branches, and `cmp`+`csel`
   picks both the mask bit and the replacement uid. What a query touches is therefore a function
   of `(caller, target)` alone; `scripts/lookup_model.py` states that function.
4. Never touch the syscall's own `pt_regs`. The probe sits on `find_user()` -- the first
   place a uid exists as a plain argument register, and the function that
   `getpriority(PRIO_USER)`, `setpriority(PRIO_USER)`, `ioprio_get` and `ioprio_set` all call
   for their uid branch (their pid/pgrp branches never reach it, so those stay untouched
   without a `which` check). Substituting the uid there leaves the syscall's `pt_regs`
   alone, so `/proc/<tid>/syscall`, ptrace register reads, syscall-exit stops and audit can
   only ever show the original argument -- and there is nothing to restore, hence no
   return handler. (arm64 has no in-register syscall entry to hook instead: there is no
   `__do_sys_`/`__se_sys_` symbol, the body is inlined into the `__arm64_sys_` wrapper.)
5. The kernel only compares numbers. Whatever needs a path, a package name or JSON is done in
   `sync-tool`, and the kernel verifies the shape and the size of what arrives before using it.
6. A rejected update changes nothing. A policy that does not fit, a caller that is not an app uid,
   a group larger than the tables -- each is logged and the previous policy stays in force, because
   half a policy hides some of the callers and is exactly the state that leaks.

## Protocol

Little endian, same layout as `src/tools/netlink.cpp`.

```
KAUX_CMD_SET  (1)  blob: u32 npairs, then npairs * (caller, target); caller 0 = any caller
KAUX_CMD_PING (2)  no payload, ACK only
KAUX_CMD_APK  (3)  blob: u32 n, then n * (st_dev, ino_lo, ino_hi, uid)
```

Family `kaux`, version 1, all three commands `GENL_ADMIN_PERM`. A blob over 32 KiB is rejected
before it is parsed.

| limit | value |
|---|---|
| `(caller, target)` pairs | 4096 |
| callers (rows of the caller table) | 4096 |
| code dirs the kernel knows (`UF_APK_MAX`) | 1024 |
| dentries walked from an opened file (`UF_DIR_DEPTH`) | 4 |
| netlink blob (`MAX_BLOB_BYTES`) | 32 KiB |

## Layout

```
src/                  kernel module sources (built as hma_uidfake.ko)
  hooks.c             the ten table entries, the vendor hook, the naming walk
  policy.c            the two tables and the query
  netlink.c           family "kaux"
  main.c              module parameter, static key, init/exit
  patch.c             text patching behind the table rewrite
  include/            shared declarations, per-KMI compatibility
  Makefile            kbuild fragment (obj-m := hma_uidfake.o)
  tools/              userspace sync tool (own C++23 CMake project)
    sync.cpp          parse, evaluate, push, daemon loop
    watcher.cpp       fsnotify watches, debounce, the unlock wait
    hma.cpp           HMA's config.json
    packages.cpp      /data/system/packages.list
    netlink.cpp       client for family "kaux"
    uidbench.c        side-channel detector, built by hand (see Tests)
module/               files that end up in the flashable zip
scripts/              host tests, the access-shape model, the exported-symbol gate
.github/workflows/    one build job per KMI in the matching DDK container, then pack
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

Version and id come from `module/module.prop`. `-DUG_USE_PREBUILT_KO=ON` packs the modules already
in `build/ko` instead of building them; the CI packaging job uses it to combine the per-KMI jobs.

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
`sync-tool`, which keeps the policy in sync from then on. `sync-tool` appends to
`state/sync.log` in the module directory; the kernel side logs to dmesg.

Before the credential-encrypted storage is available, `sync-tool` is started but cannot read
anything: it waits for the property AOSP sets after the unlock, and does so on the property's own
futex (`__system_property_wait`, resolved at run time) rather than by polling. From then on it is
driven by fsnotify alone, with a 60 s resync in case a watch was lost.

```
sync-tool --once                              # evaluate and push once, then exit
sync-tool --config <json> --list <packages.list>
```

## Tests

```bash
bash scripts/run-hosttest.sh        # compiles the real policy.c against scripts/hosttest shims
cc -O1 -I src -I scripts/hosttest -I src/include \
   -o build/branch_encode_test scripts/branch_encode_test.c && ./build/branch_encode_test
python3 scripts/lookup_model.py     # addresses and load counts per query
bash scripts/check-undefined.sh     # every undefined symbol is exported by that KMI
```

The first two compile the real sources, so they catch C-level mistakes a model cannot see (word
sizes, field order, a wrong branch encoding -- the branch encoder writes into kernel text and has
to be exact). The model states what the C cannot assert about itself: which addresses a query
touches, and how many, as a function of `(caller, target)` alone, never of the policy contents.

`check-undefined.sh` reads the DDK's per-KMI `Module.symvers`, the same table kbuild uses, and
would have caught the real bug that shipped once: `__builtin___clear_cache()` lowered to
`__clear_cache()`, which is not exported, and the module then refused to load with
`Unknown symbol __clear_cache`.

For the timing side channel there is `src/tools/uidbench.c`, which is not part of the build.
Cross-compile it and run it as an app uid that hides:

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -o uidbench src/tools/uidbench.c
```

It samples the hidden, absent and unhooked cases in the same round, so drift and frequency changes
cancel, and reports paired deltas, t statistics and the number of samples an attacker would need
for a 5 sigma decision.
