# HCE-F Hook - KernelSU/Magisk Module

NFC Observe Mode support module for Android devices.

## What This Module Does

This module overlays NFC configuration files to:
- Enable NFC debug logging
- Set default NFC-F system code to 0x4000
- Route NFC-F traffic to host (not secure element)
- Allow Xposed module to access NFC JNI libraries

## Requirements

- Android 11+ (API 30+)
- KernelSU or Magisk
- NFC-enabled device
- ST Microelectronics NFC controller (ST21NFCD or similar)

## Installation

1. Flash this module via KernelSU or Magisk Manager
2. Reboot device
3. Install HCE-F Hook app
4. Enable Xposed/LSPosed module
5. Reboot again

## Files Modified (Overlaid)

The module overlays the following files (originals are preserved):

- `/vendor/etc/libnfc-nci.conf` - Main NFC configuration
- `/vendor/etc/libnfc-nci-felica.conf` - FeliCa-specific config (if exists)
- `/vendor/etc/libnfc-hal-st.conf` - ST HAL configuration
- `/vendor/etc/libnfc-hal-st-st54j.conf` - ST54J variant config (if exists)
- `/system/etc/public.libraries.txt` - Added NFC JNI library access

## Configuration Changes

### NFC Configuration Files
- `NFC_DEBUG_ENABLED = 1` - Enable debug logging
- `DEFAULT_SYS_CODE = {40:00}` - Set default system code

### HAL Configuration Files
- `DEFAULT_SYS_CODE_ROUTE = 0x00` - Route to DH (host)
- `DEFAULT_NFCF_ROUTE = 0x00` - Route NFC-F to host
- `DEFAULT_ROUTE = 0x00` - Default route to host
- `DEFAULT_ISODEP_ROUTE = 0x00` - ISO-DEP to host

## Logs

Installation logs are saved to: `/data/local/tmp/hcefhook_install.log`

## Uninstallation

Remove the module via KernelSU/Magisk Manager and reboot.
All overlaid files will be reverted to originals automatically.

## License

See main project LICENSE file.

## Author

yuki-js (https://github.com/yuki-js/hcefhoook)

## Based On

MMT-Extended template by Zackptg5 (https://github.com/symbuzzer/MMT-Extended-Next)
