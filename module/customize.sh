#!/system/bin/sh
SKIPUNZIP=0

ui_print "- HMA UID Fake"

# 6.1.138-android14-11-g0c3559bcd85-ab14529422 -> android14-6.1
kmi_from_uname() {
  _r="$(uname -r)"
  _k="$(echo "$_r" | grep -oE 'android[0-9]+-[0-9]+\.[0-9]+' | head -n1)"
  [ -n "$_k" ] && { echo "$_k"; return; }
  _mm="$(echo "$_r" | grep -oE '^[0-9]+\.[0-9]+' | head -n1)"
  for _c in $(ls "$MODPATH/ko" 2>/dev/null | sed 's/_arm64_hma_uidfake\.ko$//' | sort -u); do
    [ "${_c#*-}" = "$_mm" ] && { echo "$_c"; return; }
  done
  echo ""
}

KMI="$(kmi_from_uname)"
ui_print "- kernel: $(uname -r)"
ui_print "- KMI: ${KMI:-Unknown}"

SRC=""
[ -n "$KMI" ] && [ -f "$MODPATH/ko/${KMI}_arm64_hma_uidfake.ko" ] && SRC="$MODPATH/ko/${KMI}_arm64_hma_uidfake.ko"

if [ -n "$SRC" ]; then
  cp -f "$SRC" "$MODPATH/ko/hma_uidfake.ko"
  for f in "$MODPATH"/ko/*_arm64_hma_uidfake.ko; do
    [ -e "$f" ] && rm -f "$f"
  done
  ui_print "- Placed ko/hma_uidfake.ko（$(basename "$SRC")）"
else
  ui_print "! No matching ${KMI:-Unknown KMI} ko; candidates: $(ls "$MODPATH/ko" 2>/dev/null | tr '\n' ' ')"
  ui_print "! Please report to the developer if you want to use this module on your device."
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
for f in "$MODPATH"/*.sh; do chmod 0755 "$f"; done
[ -f "$MODPATH/ko/hma_uidfake.ko" ] && chmod 0644 "$MODPATH/ko/hma_uidfake.ko"
[ -f "$MODPATH/sync-tool" ] && chmod 0755 "$MODPATH/sync-tool"

ui_print "- Done"
