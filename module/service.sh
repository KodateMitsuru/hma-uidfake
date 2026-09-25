#!/system/bin/sh
# Load the module if post-fs-data did not, then start sync-tool: it sets up its own
# fsnotify watches, parses HMA's config and pushes the policy over netlink, forever.
MODDIR=${0%/*}
STATE="$MODDIR/state"
KO="$MODDIR/ko/hma_uidfake.ko"
LOG="$STATE/sync.log"
mkdir -p "$STATE"

if [ -f "$KO" ] && ! lsmod | grep -q '^hma_uidfake '; then
  /data/adb/ksud insmod "$KO" >>"$LOG" 2>&1
fi

[ -x "$MODDIR/sync-tool" ] && "$MODDIR/sync-tool" >>"$LOG" 2>&1 &
