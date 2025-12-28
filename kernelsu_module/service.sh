#!/system/bin/sh
# HCE-F Hook - KernelSU Module Service Script
#
# This script runs after boot is complete
# Purpose: Grant root privileges to NFC service and HCE-F Hook app
#
# Requirements: KernelSU with root access

MODDIR="${0%/*}"
LOGFILE="/data/local/tmp/hcefhook_ksu.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
    echo "[HCE-F Hook KSU Service] $*"
}

log "=== HCE-F Hook Service Script Starting ==="

# Wait for system to be fully booted
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

log "System boot completed"

# Grant root to HCE-F Hook app (app.aoki.yuki.hcefhook)
APP_PACKAGE="app.aoki.yuki.hcefhook"
APP_UID=$(dumpsys package "$APP_PACKAGE" 2>/dev/null | grep userId= | head -1 | sed 's/.*userId=\([0-9]*\).*/\1/')

if [ -n "$APP_UID" ]; then
    log "Found HCE-F Hook app with UID: $APP_UID"
    # KernelSU automatically grants root to apps in whitelist
    # User needs to manually add app to KernelSU whitelist via KernelSU Manager
    log "Ensure $APP_PACKAGE is added to KernelSU root whitelist"
else
    log "WARNING: HCE-F Hook app not installed"
fi

# Grant root to NFC service (com.android.nfc)
NFC_PACKAGE="com.android.nfc"
NFC_UID=$(dumpsys package "$NFC_PACKAGE" 2>/dev/null | grep userId= | head -1 | sed 's/.*userId=\([0-9]*\).*/\1/')

if [ -n "$NFC_UID" ]; then
    log "Found NFC service with UID: $NFC_UID"
    log "Ensure $NFC_PACKAGE is added to KernelSU root whitelist for native hooks"
else
    log "WARNING: NFC service package not found"
fi

# Set SELinux to permissive for NFC-related contexts (if needed for debugging)
# Uncomment the following lines only if hooks fail due to SELinux denials
# setenforce 0
# log "SELinux set to permissive mode"

log "=== HCE-F Hook Service Script Complete ==="
log "Manual steps required:"
log "1. Add $APP_PACKAGE to KernelSU root whitelist"
log "2. Add $NFC_PACKAGE to KernelSU root whitelist"
log "3. Restart NFC service or reboot device"
