#!/system/bin/sh
# HCE-F Hook - KernelSU Module Post-FS-Data Script
#
# This script runs at post-fs-data stage (before system fully boots)
# Purpose: Overlay NFC configuration files to enable Observe Mode and
# custom FeliCa handling
#
# Requirements: KernelSU with root access

MODDIR="${0%/*}"
LOGFILE="/data/local/tmp/hcefhook_ksu.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
    echo "[HCE-F Hook KSU] $*"
}

log "=== HCE-F Hook KernelSU Module Starting ==="
log "Module directory: $MODDIR"
log "User ID: $(id -u)"

# Ensure we have root
if [ "$(id -u)" != "0" ]; then
    log "ERROR: Not running as root!"
    exit 1
fi

log "Root access confirmed"

# Create overlay directory for vendor config files
OVERLAY_DIR="$MODDIR/system/vendor/etc"
mkdir -p "$OVERLAY_DIR"

# Check if libnfc-nci.conf exists on device
VENDOR_NFC_CONF="/vendor/etc/libnfc-nci.conf"
VENDOR_FELICA_CONF="/vendor/etc/libnfc-nci-felica.conf"

if [ -f "$VENDOR_NFC_CONF" ]; then
    log "Found $VENDOR_NFC_CONF"
    
    # Copy original if our overlay doesn't exist
    if [ ! -f "$MODDIR/system/vendor/etc/libnfc-nci.conf" ]; then
        log "Creating overlay config from original"
        cp "$VENDOR_NFC_CONF" "$MODDIR/system/vendor/etc/libnfc-nci.conf"
        
        # Modify configuration for Observe Mode
        log "Applying Observe Mode patches to libnfc-nci.conf"
        
        # Enable NCI Android polling frame notifications (if not already present)
        if ! grep -q "NCI_ANDROID_POLLING_FRAME_NTF" "$MODDIR/system/vendor/etc/libnfc-nci.conf"; then
            echo "" >> "$MODDIR/system/vendor/etc/libnfc-nci.conf"
            echo "###############################################################################" >> "$MODDIR/system/vendor/etc/libnfc-nci.conf"
            echo "# HCE-F Hook: Enable Observe Mode polling notifications" >> "$MODDIR/system/vendor/etc/libnfc-nci.conf"
            echo "NCI_ANDROID_POLLING_FRAME_NTF=0x01" >> "$MODDIR/system/vendor/etc/libnfc-nci.conf"
            log "Added NCI_ANDROID_POLLING_FRAME_NTF"
        fi
        
        # Disable eSE auto-response for wildcard System Code
        if ! grep -q "ESE_LISTEN_TECH_MASK" "$MODDIR/system/vendor/etc/libnfc-nci.conf"; then
            echo "ESE_LISTEN_TECH_MASK=0x00" >> "$MODDIR/system/vendor/etc/libnfc-nci.conf"
            log "Added ESE_LISTEN_TECH_MASK=0x00"
        fi
        
        log "Configuration overlay created successfully"
    else
        log "Overlay config already exists, skipping"
    fi
else
    log "WARNING: $VENDOR_NFC_CONF not found on device"
    log "Device may use different NFC configuration path"
fi

# Handle FeliCa-specific config if it exists
if [ -f "$VENDOR_FELICA_CONF" ]; then
    log "Found $VENDOR_FELICA_CONF"
    
    if [ ! -f "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf" ]; then
        log "Creating FeliCa config overlay"
        cp "$VENDOR_FELICA_CONF" "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
        
        # Enable Host-based FeliCa emulation
        if ! grep -q "FELICA_HOST_LISTEN" "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"; then
            echo "" >> "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
            echo "###############################################################################" >> "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
            echo "# HCE-F Hook: Enable Host-based FeliCa handling" >> "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
            echo "FELICA_HOST_LISTEN=0x01" >> "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
            echo "FELICA_SYSTEM_CODE=0xFFFF" >> "$MODDIR/system/vendor/etc/libnfc-nci-felica.conf"
            log "Added FeliCa Host listen configuration"
        fi
    else
        log "FeliCa overlay config already exists, skipping"
    fi
else
    log "No FeliCa-specific config found (this is normal for most devices)"
fi

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
log "Next: NFC service will use overlayed configs on next boot"
