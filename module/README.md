# HMA UID Fake

Makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

`customize.sh` runs in the staging directory (`/data/adb/modules_update/<id>`), picks the
`ko/` entry matching `uname -r`, renames it to `ko/hma_uidfake.ko` and removes the rest.
`post-fs-data.sh` loads it with `/data/adb/ksud insmod`. `service.sh` starts `sync-tool`,
which watches HMA's config and the package manager files and keeps the kernel policy in
sync. Logs end up in the module's own `state/sync.log`; the kernel side logs to dmesg.
