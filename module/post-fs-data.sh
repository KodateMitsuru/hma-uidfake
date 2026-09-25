#!/system/bin/sh
# Load the kernel module as early as possible (KernelSU: ksud insmod only).
MODDIR=${0%/*}
KO="$MODDIR/ko/hma_uidfake.ko"
LOG="$MODDIR/state/sync.log"
mkdir -p "$MODDIR/state"
[ -f "$KO" ] || exit 0
lsmod | grep -q '^hma_uidfake ' && exit 0
/data/adb/ksud insmod "$KO" >>"$LOG" 2>&1
echo "[post-fs-data] ksud insmod rc=$? $(date '+%m-%d %H:%M:%S')" >>"$LOG"
