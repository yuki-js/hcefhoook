# STMicroelectronics ST21 NFC HAL Symbol Map

Reference binary: `ref_aosp/nfc_nci.st21nfc.st.so`

Collected via `nm -D nfc_nci.st21nfc.st.so` (64-bit). Key exported targets for inline hooks (Dobby/Frida):

| Symbol | Address (ref build) | Notes |
| --- | --- | --- |
| `_Z17HalSendDownstreamPvPKhm` | 0x001bf20 | Downstream TX path (hooked via Dobby in native_hook when enabled) |
| `_Z15HalSendUpstreamPvPKhm` | 0x001c2c0 | Upstream path (monitor responses) |
| `_Z22HalSendDownstreamTimerPvPKhmj` | 0x001c090 | Timer-based downstream send |
| `_Z22HalSendDownstreamTimerPvj` | 0x001c210 | Timer control |
| `_Z23hal_wrapper_send_configib` | 0x0020f50 | Config send wrapper |
| `_Z33hal_wrapper_send_core_config_propi` | 0x0020cb0 | Core config send (prop) |
| `NCI_ANDROID_GET_CAPS` | 0x0028bc0 (data) | Capability table |
| `NCI_ANDROID_GET_CAPS_RSP` | 0x0028bc4 (data) | Capability response |

### Hooking Notes
- The Dobby path in `app/src/main/cpp/native_hook.cpp` resolves `_Z17HalSendDownstreamPvPKhm` and installs a passive logging hook when `ENABLE_DOBBY=ON`.
- Additional hooks can be added for upstream (`HalSendUpstream`) to observe NFCC responses or to manipulate timers (`HalSendDownstreamTimer*`) to stretch spray cadence.
- If symbols are stripped on target builds, fall back to pattern scanning around the addresses above relative to the mapped `libnfc-nci.so` base.

### Enabling Dobby
Pass `-DENABLE_DOBBY=ON` to CMake and provide `libdobby` on the link path. The build will add `USE_DOBBY` and link against the provided Dobby shared library. Default builds keep the hook disabled to avoid a hard dependency.

