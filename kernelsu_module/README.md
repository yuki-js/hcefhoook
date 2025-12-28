# HCE-F Hook - KernelSU Module

## Overview

This KernelSU module enables Host-based SENSF_RES injection in Android NFC Observe Mode by:

1. **Config File Overlay**: Modifies `/vendor/etc/libnfc-nci.conf` to enable Observe Mode and polling notifications
2. **Root Access**: Provides root privileges to NFC service for native hook injection
3. **FeliCa Support**: Configures Host-based FeliCa emulation for SC=FFFF wildcards

## Requirements

- **KernelSU**: Kernel-level root solution (https://kernelsu.org/)
- **LSPosed**: Xposed framework for hooking NFC service (https://github.com/LSPosed/LSPosed)
- **HCE-F Hook App**: Main application (app.aoki.yuki.hcefhook)
- **Android 14/15**: Tested on Google Pixel devices
- **NFC Hardware**: STMicroelectronics ST21NFC chip recommended

## Installation

### 1. Install KernelSU

Follow official KernelSU installation guide for your device.

### 2. Install LSPosed

Install LSPosed via KernelSU or Magisk.

### 3. Install HCE-F Hook App

```bash
adb install app-debug.apk
```

### 4. Install This Module

```bash
# Package module
cd kernelsu_module
zip -r hcefhook_ksu.zip *

# Install via KernelSU Manager or adb
adb push hcefhook_ksu.zip /sdcard/
# Then install via KernelSU Manager app
```

### 5. Configure Root Access

Open KernelSU Manager and add to root whitelist:
- `app.aoki.yuki.hcefhook` (HCE-F Hook app)
- `com.android.nfc` (NFC service)

### 6. Configure LSPosed

1. Open LSPosed Manager
2. Enable HCE-F Hook module
3. Select scope: `com.android.nfc`
4. Restart device

## What This Module Does

### Post-FS-Data Stage (`post-fs-data.sh`)

Creates overlay for `/vendor/etc/libnfc-nci.conf` with:

```
# Enable NCI Android polling frame notifications
NCI_ANDROID_POLLING_FRAME_NTF=0x01

# Disable eSE auto-response for wildcard System Code
ESE_LISTEN_TECH_MASK=0x00
```

And for `/vendor/etc/libnfc-nci-felica.conf` (if exists):

```
# Enable Host-based FeliCa handling
FELICA_HOST_LISTEN=0x01
FELICA_SYSTEM_CODE=0xFFFF
```

### Service Stage (`service.sh`)

- Waits for boot completion
- Identifies app and NFC service UIDs
- Logs information for manual KernelSU whitelist configuration

## Verification

Check if module is working:

```bash
# Check logs
adb shell cat /data/local/tmp/hcefhook_ksu.log

# Verify overlay is active
adb shell cat /vendor/etc/libnfc-nci.conf | grep NCI_ANDROID_POLLING_FRAME_NTF

# Check NFC service has root
adb shell su -c "ps -A | grep nfc"
```

## Troubleshooting

### Module Not Loading
- Check KernelSU Manager shows module as enabled
- Verify module.prop is valid
- Check `/data/local/tmp/hcefhook_ksu.log` for errors

### NFC Service Crashes
- Verify overlay config syntax is correct
- Try disabling module temporarily
- Check logcat: `adb logcat | grep -i nfc`

### Hooks Not Working
- Ensure both apps are in KernelSU root whitelist
- Verify LSPosed module is enabled and scoped correctly
- Check Xposed logs in LSPosed Manager

### SELinux Denials
- Check for denials: `adb shell su -c "dmesg | grep avc"`
- Temporarily set permissive: `adb shell su -c "setenforce 0"`
- For permanent fix, create custom SELinux policy

## Uninstallation

1. Disable module in KernelSU Manager
2. Reboot device
3. Original NFC configs will be restored

## Security Notice

This module:
- Modifies system NFC configuration
- Requires root access
- May affect NFC security features
- Is for research and educational purposes only

**Use responsibly and only on devices you own.**

## References

- Main project: https://github.com/yuki-js/hcefhoook
- KernelSU: https://kernelsu.org/
- LSPosed: https://github.com/LSPosed/LSPosed
- NCI Specification 2.2
- JIS X 6319-4 (FeliCa)
