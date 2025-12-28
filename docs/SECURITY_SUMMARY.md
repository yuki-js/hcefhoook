# Security Summary - HCEFHook Project

## Overview

This document provides a comprehensive security analysis of the HCEFHook project, which implements Host-based NFC Observe Mode with SENSF_RES injection capabilities.

## Security Requirements

### 1. Permission Requirements

#### Root Access
- **Required**: Yes
- **Reason**: Access to system NFC service process (`com.android.nfc`)
- **Risk**: Full system access if root is compromised
- **Mitigation**: Requires explicit user consent through Magisk/KernelSU

#### KernelSU Module
- **Required**: Yes
- **Reason**: Overlay `/vendor/etc/libnfc-nci.conf` to enable `NCI_ANDROID_POLLING_FRAME_NTF`
- **Risk**: Kernel-level modification
- **Mitigation**: Module is read-only overlay, no executable code

#### Xposed/LSPosed Framework
- **Required**: Yes
- **Reason**: Hook Java layer of NFC service
- **Risk**: Process injection into system service
- **Mitigation**: LSPosed provides sandboxing and module verification

### 2. SELinux Impact

#### Current Status
- **Mode**: Permissive recommended for development
- **Impact**: Reduces system security during testing
- **Production**: Would require custom SELinux policy

#### Potential SELinux Violations
- Reading/writing to NFC device nodes (`/dev/nfc*`)
- Accessing system service memory
- IPC between app and system process

### 3. Security Risks

#### HIGH RISK: Arbitrary NFC Response Injection
- **Description**: Ability to inject custom SENSF_RES frames
- **Impact**: Can impersonate FeliCa cards to readers
- **Mitigation**: 
  - Requires physical proximity (NFC range: ~10cm)
  - User must explicitly enable injection
  - Logs all injection attempts

#### MEDIUM RISK: Process Memory Access
- **Description**: Native hooks can read/write `nfa_dm_cb` structure
- **Impact**: Potential to crash NFC service or corrupt state
- **Mitigation**:
  - Read-only access preferred where possible
  - State restoration after injection
  - Defensive checks before memory operations

#### MEDIUM RISK: IPC Data Exposure
- **Description**: ContentProvider is exported for IPC
- **Impact**: Any app can query configuration data
- **Mitigation**:
  - No sensitive card data stored (only test IDm/PMm)
  - Production should add signature-level protection
  - Consider encryption for stored configurations

#### LOW RISK: Log Information Disclosure
- **Description**: Verbose logging includes protocol data
- **Impact**: May expose NFC communication patterns
- **Mitigation**:
  - IDm/PMm are test values only
  - Production should use Log.d() only in debug builds
  - Remove hex dumps in release builds

## Security Best Practices Implemented

### 1. Minimal Privilege Principle
- ✅ Only hooks necessary NFC service methods
- ✅ Does not request unnecessary Android permissions
- ✅ Xposed hooks isolated to `com.android.nfc` process

### 2. State Isolation
- ✅ State bypass is temporary (restored after injection)
- ✅ Native hooks can be enabled/disabled dynamically
- ✅ Spray mode stops automatically after timeout

### 3. Input Validation
- ✅ IDm/PMm length validation (must be 8 bytes)
- ✅ SENSF_RES format validation before injection
- ✅ Null checks on all IPC data

### 4. Error Handling
- ✅ Exceptions caught and logged, not propagated to system service
- ✅ Graceful degradation if native hooks fail
- ✅ Fallback to single-shot if spray mode unavailable

### 5. Audit Trail
- ✅ All injections logged with timestamp
- ✅ SENSF_REQ detection logged
- ✅ State changes logged

## Security Analysis Results

### CodeQL Analysis
```
Language: Java
Alerts: 0
Status: ✅ PASSED
```

No security vulnerabilities detected in:
- SQL injection
- Cross-site scripting (N/A for Android)
- Insecure data storage
- Insecure communication
- Code injection

### Manual Security Review

#### ✅ No Hardcoded Secrets
- Default IDm/PMm are test values
- No API keys or credentials

#### ✅ No Insecure Network Communication
- All IPC is local (ContentProvider, Broadcast)
- No network requests

#### ✅ No Arbitrary Code Execution
- Native hooks are pre-compiled
- No dynamic code loading
- No reflection-based RCE vectors

#### ⚠️ Warning: Potential Misuse Vectors

1. **Card Emulation Attack**
   - Impact: Could emulate valid FeliCa cards if valid IDm/PMm obtained
   - Mitigation: Requires attacker to know valid card credentials
   - Note: This is the intended functionality for research

2. **Reader Confusion Attack**
   - Impact: Spray mode could confuse readers with multiple responses
   - Mitigation: Limited to 20ms window, 10 transmissions max
   - Note: FeliCa readers should handle collision detection

3. **NFC Service DoS**
   - Impact: Excessive injection could destabilize NFC service
   - Mitigation: Rate limiting via IPC queue size
   - Note: Requires system restart to recover

## Responsible Use Guidelines

### ✅ Acceptable Use
- Security research and vulnerability assessment
- NFC protocol analysis
- FeliCa implementation testing
- Educational purposes

### ❌ Prohibited Use
- Unauthorized access to payment systems
- Fraud or identity theft
- Disruption of commercial NFC infrastructure
- Bypassing access control systems

## Disclosure Policy

### Vulnerabilities in This Code
- Report to: yuki-js/hcefhoook repository issues
- PGP key: (if available, add here)
- Response time: Best effort (research project)

### Vulnerabilities in Android NFC Stack
- Report to: Android Security Team
- URL: https://source.android.com/security/overview/updates-resources
- Follow responsible disclosure guidelines

## Legal Disclaimer

This software is provided for **educational and research purposes only**. 

- ⚠️ Users are responsible for compliance with local laws
- ⚠️ Unauthorized access to NFC systems may be illegal
- ⚠️ Use only on devices and systems you own or have permission to test
- ⚠️ The authors assume no liability for misuse

## Security Contact

For security-related questions or concerns:
- GitHub Issues: https://github.com/yuki-js/hcefhoook/issues
- Mark issue as "security" label
- For sensitive issues, use private reporting

## References

1. [Android Security Bulletin](https://source.android.com/security/bulletin)
2. [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
3. [NFC Forum Security Specifications](https://nfc-forum.org/our-work/specification-releases/)
4. [FeliCa Security White Paper](https://www.sony.net/Products/felica/)

---

**Last Updated**: 2025-12-28  
**Version**: 1.0  
**Status**: Research Project - Use at your own risk
