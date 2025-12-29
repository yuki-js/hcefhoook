#!/system/bin/sh
# HCE-F Hook - KernelSU Module Post-FS-Data Script
#
# This script runs at post-fs-data stage (before system fully boots)
# Purpose: Overlay NFC configuration files to enable Observe Mode and
# custom FeliCa handling
#
# Requirements: KernelSU with root access
#
# IMPORTANT: KernelSU uses different mount points than Magisk
# - For /vendor partition: use $MODDIR/vendor/etc/ (NOT /system/vendor/)
# - For /system partition: use $MODDIR/system/etc/

MODDIR="${0%/*}"
LOGFILE="/data/local/tmp/hcefhook_ksu.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

log "=== HCE-F Hook KernelSU Module Starting ==="
log "Module directory: $MODDIR"
log "User ID: $(id -u)"
log "Script path: $0"

# Ensure we have root
if [ "$(id -u)" != "0" ]; then
    log "ERROR: Not running as root!"
    exit 1
fi

log "Root access confirmed"

# Create overlay directories
# KernelSU: vendor partition is mounted separately, use $MODDIR/vendor/
# NOT $MODDIR/system/vendor/
mkdir -p "$MODDIR/vendor/etc"
mkdir -p "$MODDIR/system/etc"

log "Created overlay directories"
log "  $MODDIR/vendor/etc"
log "  $MODDIR/system/etc"

override_key() {
    local FILE="$1"
    local KEY="$2"
    local NEW_VALUE="$3"

    if grep -qE "^[[:space:]]*${KEY}[[:space:]]*=" "$FILE"; then
        log "Overriding $KEY in $FILE to $NEW_VALUE"
        sed -i "s|^[[:space:]]*${KEY}[[:space:]]*=.*|${KEY} = ${NEW_VALUE}|g" "$FILE"
    else
        log "Adding $KEY to $FILE with value $NEW_VALUE"
        echo "${KEY} = ${NEW_VALUE}" >> "$FILE"
    fi
}

# Config files are in /vendor/etc/ on most devices
VENDOR_NFC_CONF="/vendor/etc/libnfc-nci.conf"
VENDOR_FELICA_CONF="/vendor/etc/libnfc-nci-felica.conf"
VENDOR_HALST_CONF="/vendor/etc/libnfc-hal-st.conf"
VENDOR_HALST_P_CONF="/vendor/etc/libnfc-hal-st-st54j.conf"

# Public libraries list for linker namespace bypass
SYSTEM_PUBLIC_LIBS="/system/etc/public.libraries.txt"

execute_replace_nci() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    # KernelSU: Use $MODDIR/vendor/etc/ for vendor overlay
    local KSU_REPLACE="$MODDIR/vendor/etc/$BASENAME"

    log "Processing NCI config: $TARGET_FILE -> $KSU_REPLACE"

    if [ -f "$KSU_REPLACE" ]; then
        log "Deleting previous $KSU_REPLACE"
        rm -f "$KSU_REPLACE"
    fi
    
    if [ ! -f "$TARGET_FILE" ]; then
        log "WARNING: Source file not found: $TARGET_FILE"
        return 1
    fi
    
    cp "$TARGET_FILE" "$KSU_REPLACE"

    override_key "$KSU_REPLACE" "NFC_DEBUG_ENABLED" "1"
    override_key "$KSU_REPLACE" "DEFAULT_SYS_CODE" "{40:00}"
    
    chmod 644 "$KSU_REPLACE"
    chown root:root "$KSU_REPLACE"
    
    log "Created overlay: $KSU_REPLACE"
    return 0
}

execute_replace_halst() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    # KernelSU: Use $MODDIR/vendor/etc/ for vendor overlay
    local KSU_REPLACE="$MODDIR/vendor/etc/$BASENAME"

    log "Processing HAL-ST config: $TARGET_FILE -> $KSU_REPLACE"

    if [ -f "$KSU_REPLACE" ]; then
        log "Deleting previous $KSU_REPLACE"
        rm -f "$KSU_REPLACE"
    fi
    
    if [ ! -f "$TARGET_FILE" ]; then
        log "WARNING: Source file not found: $TARGET_FILE"
        return 1
    fi
    
    cp "$TARGET_FILE" "$KSU_REPLACE"

    override_key "$KSU_REPLACE" "DEFAULT_SYS_CODE_ROUTE" "0x00"
    override_key "$KSU_REPLACE" "DEFAULT_NFCF_ROUTE" "0x00"
    override_key "$KSU_REPLACE" "DEFAULT_ROUTE" "0x00"
    override_key "$KSU_REPLACE" "DEFAULT_ISODEP_ROUTE" "0x00"
    override_key "$KSU_REPLACE" "NFC_DEBUG_ENABLED" "1"

    chmod 644 "$KSU_REPLACE"
    chown root:root "$KSU_REPLACE"
    
    log "Created overlay: $KSU_REPLACE"
    return 0
}

patch_public_libraries() {
    # Patch public.libraries.txt to allow loading libstnfc_nci_jni.so
    # This helps bypass linker namespace restrictions
    
    local KSU_PUBLIC_LIBS="$MODDIR/system/etc/public.libraries.txt"
    
    if [ ! -f "$SYSTEM_PUBLIC_LIBS" ]; then
        log "WARNING: $SYSTEM_PUBLIC_LIBS not found"
        return 1
    fi
    
    log "Patching public.libraries.txt for linker namespace bypass"
    
    cp "$SYSTEM_PUBLIC_LIBS" "$KSU_PUBLIC_LIBS"
    
    # Add NFC JNI libraries if not present
    if ! grep -q "libstnfc_nci_jni.so" "$KSU_PUBLIC_LIBS"; then
        echo "libstnfc_nci_jni.so" >> "$KSU_PUBLIC_LIBS"
        log "Added libstnfc_nci_jni.so to public.libraries.txt"
    fi
    
    if ! grep -q "libnfc_nci_jni.so" "$KSU_PUBLIC_LIBS"; then
        echo "libnfc_nci_jni.so" >> "$KSU_PUBLIC_LIBS"
        log "Added libnfc_nci_jni.so to public.libraries.txt"
    fi
    
    chmod 644 "$KSU_PUBLIC_LIBS"
    chown root:root "$KSU_PUBLIC_LIBS"
    
    log "Patched: $KSU_PUBLIC_LIBS"
    return 0
}

# Process NFC configs
if [ -f "$VENDOR_NFC_CONF" ]; then
    execute_replace_nci "$VENDOR_NFC_CONF"
else
    log "WARNING: $VENDOR_NFC_CONF not found on device"
fi

if [ -f "$VENDOR_FELICA_CONF" ]; then
    execute_replace_nci "$VENDOR_FELICA_CONF"
else
    log "No FeliCa-specific config found (normal for most devices)"
fi

# Process HAL-ST configs
if [ -f "$VENDOR_HALST_CONF" ]; then
    execute_replace_halst "$VENDOR_HALST_CONF"
else
    log "WARNING: $VENDOR_HALST_CONF not found on device"
fi

if [ -f "$VENDOR_HALST_P_CONF" ]; then
    execute_replace_halst "$VENDOR_HALST_P_CONF"
else
    log "No HAL-ST variant config found (normal for most devices)"
fi

# Patch public.libraries.txt for linker namespace bypass
patch_public_libraries

# Set correct permissions for overlay directories
chmod 755 "$MODDIR/vendor" 2>/dev/null
chmod 755 "$MODDIR/vendor/etc" 2>/dev/null
chmod 755 "$MODDIR/system" 2>/dev/null
chmod 755 "$MODDIR/system/etc" 2>/dev/null

log "=== HCE-F Hook KernelSU Module Complete ==="
log "Vendor overlay: $MODDIR/vendor/etc/"
log "System overlay: $MODDIR/system/etc/"
log "Check overlay files:"
ls -la "$MODDIR/vendor/etc/" >> "$LOGFILE" 2>&1
ls -la "$MODDIR/system/etc/" >> "$LOGFILE" 2>&1