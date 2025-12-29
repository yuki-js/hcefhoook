#!/system/bin/sh
# HCE-F Hook - KernelSU Module Post-FS-Data Script
#
# This script runs at post-fs-data stage (before system fully boots)
# Purpose: Overlay NFC configuration files to enable Observe Mode and
# custom FeliCa handling
#
# Requirements: KernelSU with root access
#
# KernelSU Module Structure:
# $MODDIR/
#   ├── module.prop
#   ├── post-fs-data.sh (this file)
#   ├── system/
#   │   └── etc/
#   │       └── public.libraries.txt (appended with libstnfc_nci_jni.so)
#   └── vendor/    <-- Mount point (NOT system/vendor!)
#       └── etc/
#           └── libnfc-nci.conf (etc.)

MODDIR="${0%/*}"
LOGFILE="/data/local/tmp/hcefhook_ksu.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

log "=== HCE-F Hook KernelSU Module Starting ==="
log "Module directory: $MODDIR"
log "Script path: $0"
log "User ID: $(id -u)"

# Ensure we have root
if [ "$(id -u)" != "0" ]; then
    log "ERROR: Not running as root!"
    exit 1
fi

log "Root access confirmed"

# Create overlay directories
# KernelSU uses $MODDIR/vendor for /vendor overlays (not $MODDIR/system/vendor)
mkdir -p "$MODDIR/vendor/etc"
mkdir -p "$MODDIR/system/etc"

log "Created overlay directories:"
log "  - $MODDIR/vendor/etc"
log "  - $MODDIR/system/etc"

override_key() {
    local FILE="$1"
    local KEY="$2"
    local NEW_VALUE="$3"

    if grep -qE "^[[:space:]]*${KEY}[[:space:]]*=" "$FILE" 2>/dev/null; then
        log "Overriding $KEY in $FILE to $NEW_VALUE"
        sed -i -E "s|^[[:space:]]*(${KEY}[[:space:]]*=).*|\1 ${NEW_VALUE}|g" "$FILE"
    else
        log "Adding $KEY to $FILE with value $NEW_VALUE"
        echo "$KEY = $NEW_VALUE" >> "$FILE"
    fi
}

# Check if libnfc-nci.conf exists on device
VENDOR_NFC_CONF="/vendor/etc/libnfc-nci.conf"
VENDOR_FELICA_CONF="/vendor/etc/libnfc-nci-felica.conf"

execute_replace_nci() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local OVERLAY_FILE="$MODDIR/vendor/etc/$BASENAME"

    if [ -f "$OVERLAY_FILE" ]; then
        log "Deleting previous $OVERLAY_FILE"
        rm -f "$OVERLAY_FILE"
    fi
    
    if [ -f "$TARGET_FILE" ]; then
        cp "$TARGET_FILE" "$OVERLAY_FILE"
        log "Copied $TARGET_FILE to $OVERLAY_FILE"

        override_key "$OVERLAY_FILE" "NFC_DEBUG_ENABLED" "1"
        override_key "$OVERLAY_FILE" "DEFAULT_SYS_CODE" "{40:00}"
    else
        log "WARNING: Source file $TARGET_FILE not found"
    fi
}

if [ -f "$VENDOR_NFC_CONF" ]; then
    execute_replace_nci "$VENDOR_NFC_CONF"
else
    log "WARNING: $VENDOR_NFC_CONF not found on device"
    log "Device may use different NFC configuration path"
fi

# Handle FeliCa-specific config if it exists
if [ -f "$VENDOR_FELICA_CONF" ]; then
    execute_replace_nci "$VENDOR_FELICA_CONF"
else
    log "No FeliCa-specific config found (this is normal for most devices)"
fi

VENDOR_HALST_CONF="/vendor/etc/libnfc-hal-st.conf"
VENDOR_HALST_P_CONF="/vendor/etc/libnfc-hal-st-st54j.conf"

execute_replace_halst() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local OVERLAY_FILE="$MODDIR/vendor/etc/$BASENAME"

    if [ -f "$OVERLAY_FILE" ]; then
        log "Deleting previous $OVERLAY_FILE"
        rm -f "$OVERLAY_FILE"
    fi
    
    if [ -f "$TARGET_FILE" ]; then
        cp "$TARGET_FILE" "$OVERLAY_FILE"
        log "Copied $TARGET_FILE to $OVERLAY_FILE"

        override_key "$OVERLAY_FILE" "DEFAULT_SYS_CODE_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_NFCF_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_ISODEP_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "NFC_DEBUG_ENABLED" "1"
    else
        log "WARNING: Source file $TARGET_FILE not found"
    fi
}

if [ -f "$VENDOR_HALST_CONF" ]; then
    execute_replace_halst "$VENDOR_HALST_CONF"
else
    log "WARNING: $VENDOR_HALST_CONF not found on device"
    log "Device may use different NFC HAL-ST configuration path"
fi

if [ -f "$VENDOR_HALST_P_CONF" ]; then
    execute_replace_halst "$VENDOR_HALST_P_CONF"
else
    log "No HAL-ST FeliCa-specific config found (this is normal for most devices)"
fi

# Patch public.libraries.txt to allow loading libstnfc_nci_jni.so
# This bypasses linker namespace restrictions for the NFC JNI library
PUBLIC_LIBS="/system/etc/public.libraries.txt"
OVERLAY_PUBLIC_LIBS="$MODDIR/system/etc/public.libraries.txt"

if [ -f "$PUBLIC_LIBS" ]; then
    cp "$PUBLIC_LIBS" "$OVERLAY_PUBLIC_LIBS"
    
    # Add libstnfc_nci_jni.so if not already present
    if ! grep -q "libstnfc_nci_jni.so" "$OVERLAY_PUBLIC_LIBS" 2>/dev/null; then
        echo "libstnfc_nci_jni.so" >> "$OVERLAY_PUBLIC_LIBS"
        log "Added libstnfc_nci_jni.so to public.libraries.txt"
    else
        log "libstnfc_nci_jni.so already in public.libraries.txt"
    fi
    
    # Also add libnfc_nci_jni.so for AOSP builds
    if ! grep -q "libnfc_nci_jni.so" "$OVERLAY_PUBLIC_LIBS" 2>/dev/null; then
        echo "libnfc_nci_jni.so" >> "$OVERLAY_PUBLIC_LIBS"
        log "Added libnfc_nci_jni.so to public.libraries.txt"
    fi
    
    chmod 644 "$OVERLAY_PUBLIC_LIBS"
    chown root:root "$OVERLAY_PUBLIC_LIBS"
else
    log "WARNING: $PUBLIC_LIBS not found"
fi

# Set correct permissions for overlay files
VENDOR_OVERLAY_DIR="$MODDIR/vendor/etc"
if [ -d "$VENDOR_OVERLAY_DIR" ]; then
    chmod 755 "$MODDIR/vendor"
    chmod 755 "$VENDOR_OVERLAY_DIR"
    for f in "$VENDOR_OVERLAY_DIR"/*.conf; do
        if [ -f "$f" ]; then
            chmod 644 "$f"
            chown root:root "$f"
        fi
    done
    log "Permissions set for vendor overlay files"
fi

SYSTEM_OVERLAY_DIR="$MODDIR/system/etc"
if [ -d "$SYSTEM_OVERLAY_DIR" ]; then
    chmod 755 "$MODDIR/system"
    chmod 755 "$SYSTEM_OVERLAY_DIR"
    for f in "$SYSTEM_OVERLAY_DIR"/*; do
        if [ -f "$f" ]; then
            chmod 644 "$f"
            chown root:root "$f"
        fi
    done
    log "Permissions set for system overlay files"
fi

# List created files
log "=== Created overlay files ==="
find "$MODDIR/vendor" -type f 2>/dev/null | while read f; do
    log "  $f"
done
find "$MODDIR/system" -type f 2>/dev/null | while read f; do
    log "  $f"
done

log "=== HCE-F Hook KernelSU Module Complete ==="