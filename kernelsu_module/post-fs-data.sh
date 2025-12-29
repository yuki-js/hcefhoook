#!/system/bin/sh
# HCE-F Hook - KernelSU Module Post-FS-Data Script
#
# This script runs at post-fs-data stage (before system fully boots)
# Purpose: Overlay NFC configuration files to enable Observe Mode and
# custom FeliCa handling
#
# Requirements: KernelSU with root access

MODDIR="/data/adb/modules/hcefhook"
LOGFILE="/data/local/tmp/hcefhook_ksu.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}


log "=== HCE-F Hook KernelSU Module Starting ==="
mkdir -p "/data/adb/modules/hcefhook/system/vendor/etc"
log "Module directory: $MODDIR"
log "User ID: $(id -u)"

# Ensure we have root
if [ "$(id -u)" != "0" ]; then
    log "ERROR: Not running as root!"
    exit 1
fi

log "Root access confirmed"

override_key() {
    local FILE="$1"
    local KEY="$2"
    local NEW_VALUE="$3"

    if grep -qE '^\\s*$KEY\\s*=' "$FILE"; then
        log "Overriding $KEY in $FILE to $NEW_VALUE"
        sed -i -E 's|^\\s*($KEY\\s*=).*|\\1 $NEW_VALUE|g' "$FILE"
    else
        log "Adding $KEY to $FILE with value $NEW_VALUE"
        echo "$KEY = $NEW_VALUE" >> "$FILE"
    fi
}

# Check if libnfc-nci.conf exists on device
VENDOR_NFC_CONF="/system/vendor/etc/libnfc-nci.conf"
VENDOR_FELICA_CONF="/system/vendor/etc/libnfc-nci-felica.conf"

execute_replace_nci() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local MAGISK_REPLACE="$MODDIR/system/vendor/etc/$BASENAME"

    if [ -f "$MAGISK_REPLACE" ]; then
        log "Deleting previous $MAGISK_REPLACE"
        rm -f "$MAGISK_REPLACE"
    fi
    cp "$TARGET_FILE" "$MAGISK_REPLACE"

    override_key "$MAGISK_REPLACE" "NFC_DEBUG_ENABLED" "1"
    override_key "$MAGISK_REPLACE" "DEFAULT_SYS_CODE" "{40:00}"
}

if [ -f "$VENDOR_NFC_CONF" ]; then
    execute_replace_nci $VENDOR_NFC_CONF
else
    log "WARNING: $VENDOR_NFC_CONF not found on device"
    log "Device may use different NFC configuration path"
fi

# Handle FeliCa-specific config if it exists
if [ -f "$VENDOR_FELICA_CONF" ]; then
    execute_replace_nci $VENDOR_FELICA_CONF
else
    log "No FeliCa-specific config found (this is normal for most devices)"
fi


VENDOR_HALST_CONF="/system/vendor/etc/libnfc-hal-st.conf"
VENDOR_HALST_P_CONF="/system/vendor/etc/libnfc-hal-st-st54j.conf"

execute_replace_halst() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local MAGISK_REPLACE="$MODDIR/system/vendor/etc/$BASENAME"

    if [ -f "$MAGISK_REPLACE" ]; then
        log "Deleting previous $MAGISK_REPLACE"
        rm -f "$MAGISK_REPLACE"
    fi
    cp "$TARGET_FILE" "$MAGISK_REPLACE"

    override_key "$MAGISK_REPLACE" "DEFAULT_SYS_CODE_ROUTE" "0x00"
    override_key "$MAGISK_REPLACE" "DEFAULT_NFCF_ROUTE" "0x00"
    override_key "$MAGISK_REPLACE" "DEFAULT_ROUTE" "0x00"
    override_key "$MAGISK_REPLACE" "DEFAULT_ISODEP_ROUTE" "0x00"
    override_key "$MAGISK_REPLACE" "NFC_DEBUG_ENABLED" "1"

}

if [ -f "$VENDOR_HALST_CONF" ]; then
    execute_replace_halst $VENDOR_HALST_CONF
else
    log "WARNING: $VENDOR_HALST_CONF not found on device"
    log "Device may use different NFC HAL-ST configuration path"
fi

if [ -f "$VENDOR_HALST_P_CONF" ]; then
    execute_replace_halst $VENDOR_HALST_P_CONF
else
    log "No HAL-ST FeliCa-specific config found (this is normal for most devices)"
fi

OVERLAY_DIR="$MODDIR/system/vendor/etc"
# Set correct permissions for overlay files
if [ -d "$OVERLAY_DIR" ]; then
    chmod 755 "$OVERLAY_DIR"
    chmod 644 "$OVERLAY_DIR"/*.conf 2>/dev/null
    chown root:root "$OVERLAY_DIR"/*.conf 2>/dev/null
    log "Permissions set for overlay files"
fi

# Grant root access to com.android.nfc process (for hooks to work)
# This will be done via service.sh when NFC service starts

log "=== HCE-F Hook KernelSU Module Complete ==="
log "Overlay directory: $OVERLAY_DIR"