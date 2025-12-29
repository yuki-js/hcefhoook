##########################################################################################
#
# MMT Extended Config Script
#
##########################################################################################

##########################################################################################
# Config Flags
##########################################################################################

# HCE-F Hook requires Android 11+ (API 30+) for Observe Mode support
MINAPI=30
# No maximum API restriction
#MAXAPI=35

# No dynamic lib requirements
#DYNLIB=true

# We modify vendor partition
#PARTOVER=true
PARTITIONS="/vendor"

##########################################################################################
# Replace list
##########################################################################################

# We don't replace entire directories, just overlay config files
REPLACE=""

##########################################################################################
# Permissions
##########################################################################################

set_permissions() {
  # Set permissions for overlaid NFC configuration files
  # All files in $MODPATH/system/vendor/etc should be readable
  if [ -d "$MODPATH/system/vendor/etc" ]; then
    set_perm_recursive $MODPATH/system/vendor/etc 0 0 0755 0644
  fi
  
  if [ -d "$MODPATH/system/etc" ]; then
    set_perm_recursive $MODPATH/system/etc 0 0 0755 0644
  fi
}

##########################################################################################
# MMT Extended Logic - Don't modify anything after this
##########################################################################################

SKIPUNZIP=1
unzip -qjo "$ZIPFILE" 'common/functions.sh' -d $TMPDIR >&2
. $TMPDIR/functions.sh

##########################################################################################
# HCE-F Hook Installation Logic
##########################################################################################

LOGFILE="/data/local/tmp/hcefhook_install.log"

log_install() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
    ui_print "$*"
}

log_install "=== HCE-F Hook Module Installation ==="
log_install "Module path: $MODPATH"

# Create necessary directories
mkdir -p "$MODPATH/system/vendor/etc"
mkdir -p "$MODPATH/system/etc"

log_install "Created overlay directories"

# Function to override config keys
override_key() {
    local FILE="$1"
    local KEY="$2"
    local NEW_VALUE="$3"

    if grep -qE "^[[:space:]]*${KEY}[[:space:]]*=" "$FILE" 2>/dev/null; then
        log_install "  Overriding $KEY = $NEW_VALUE"
        sed -i -E "s|^[[:space:]]*(${KEY}[[:space:]]*=).*|\1 ${NEW_VALUE}|g" "$FILE"
    else
        log_install "  Adding $KEY = $NEW_VALUE"
        echo "$KEY = $NEW_VALUE" >> "$FILE"
    fi
}

# NFC configuration files to overlay
VENDOR_NFC_CONF="/vendor/etc/libnfc-nci.conf"
VENDOR_FELICA_CONF="/vendor/etc/libnfc-nci-felica.conf"
VENDOR_HALST_CONF="/vendor/etc/libnfc-hal-st.conf"
VENDOR_HALST_P_CONF="/vendor/etc/libnfc-hal-st-st54j.conf"

execute_replace_nci() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local OVERLAY_FILE="$MODPATH/system/vendor/etc/$BASENAME"
    
    if [ -f "$TARGET_FILE" ]; then
        cp "$TARGET_FILE" "$OVERLAY_FILE"
        log_install "Copied $BASENAME to module overlay"
        
        override_key "$OVERLAY_FILE" "NFC_DEBUG_ENABLED" "1"
        override_key "$OVERLAY_FILE" "DEFAULT_SYS_CODE" "{40:00}"
        
        chmod 644 "$OVERLAY_FILE"
    else
        log_install "WARNING: $TARGET_FILE not found (device may not have this file)"
    fi
}

execute_replace_halst() {
    local TARGET_FILE="$1"
    local BASENAME="$(basename "$TARGET_FILE")"
    local OVERLAY_FILE="$MODPATH/system/vendor/etc/$BASENAME"
    
    if [ -f "$TARGET_FILE" ]; then
        cp "$TARGET_FILE" "$OVERLAY_FILE"
        log_install "Copied $BASENAME to module overlay"
        
        override_key "$OVERLAY_FILE" "DEFAULT_SYS_CODE_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_NFCF_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "DEFAULT_ISODEP_ROUTE" "0x00"
        override_key "$OVERLAY_FILE" "NFC_DEBUG_ENABLED" "1"
        
        chmod 644 "$OVERLAY_FILE"
    else
        log_install "WARNING: $TARGET_FILE not found (device may not have this file)"
    fi
}

log_install "Processing NFC configuration files..."

# Process NFC configs
execute_replace_nci "$VENDOR_NFC_CONF"
execute_replace_nci "$VENDOR_FELICA_CONF"
execute_replace_halst "$VENDOR_HALST_CONF"
execute_replace_halst "$VENDOR_HALST_P_CONF"

# Patch public.libraries.txt to allow loading NFC JNI libraries
PUBLIC_LIBS="/system/etc/public.libraries.txt"
OVERLAY_PUBLIC_LIBS="$MODPATH/system/etc/public.libraries.txt"

if [ -f "$PUBLIC_LIBS" ]; then
    cp "$PUBLIC_LIBS" "$OVERLAY_PUBLIC_LIBS"
    
    # Add NFC JNI libraries if not present
    if ! grep -q "libstnfc_nci_jni.so" "$OVERLAY_PUBLIC_LIBS" 2>/dev/null; then
        echo "libstnfc_nci_jni.so" >> "$OVERLAY_PUBLIC_LIBS"
        log_install "Added libstnfc_nci_jni.so to public.libraries.txt"
    fi
    
    if ! grep -q "libnfc_nci_jni.so" "$OVERLAY_PUBLIC_LIBS" 2>/dev/null; then
        echo "libnfc_nci_jni.so" >> "$OVERLAY_PUBLIC_LIBS"
        log_install "Added libnfc_nci_jni.so to public.libraries.txt"
    fi
    
    chmod 644 "$OVERLAY_PUBLIC_LIBS"
else
    log_install "WARNING: $PUBLIC_LIBS not found"
fi

log_install "=== Installation Complete ==="
log_install "Logs saved to: $LOGFILE"
log_install "Reboot to apply changes"

ui_print " "
ui_print "HCE-F Hook module installed successfully!"
ui_print "Configuration files overlaid for NFC Observe Mode support"
ui_print " "
ui_print "Reboot required to apply changes"
