/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * REFERENCE FILE: Android 15 Observe Mode Implementation
 * This file documents the Observe Mode API and behavior.
 */

package android.nfc;

import android.os.Bundle;

/**
 * OBSERVE MODE DOCUMENTATION
 *
 * Observe Mode is a new feature introduced in Android 15 that allows
 * applications to passively observe NFC polling frames without the
 * device responding to them automatically.
 *
 * Key characteristics:
 * 1. NFCC monitors RF field but does not auto-respond
 * 2. eSE (Secure Element) is silenced - does not respond
 * 3. Polling frames are delivered to Host via notifications
 * 4. No data transmission is allowed in this mode
 *
 * Use cases:
 * - NFC security research and analysis
 * - Protocol inspection and debugging
 * - Custom response generation (this research's goal)
 */
public class NfcObserveMode {

    /**
     * Enable Observe Mode
     *
     * When enabled:
     * - SENSF_REQ (SC=FFFF) will be delivered to Host
     * - eSE will NOT respond automatically
     * - Standard HCE-F callbacks will NOT be invoked
     * - Polling frame callbacks WILL be invoked
     *
     * @param enable true to enable, false to disable
     * @return true if successful
     */
    public boolean setObserveMode(boolean enable) {
        // Implementation calls native NFA layer
        // nfa_dm_set_observe_mode_config(enable)
        return false;
    }

    /**
     * Register callback for polling frame notifications
     *
     * Callback receives raw polling frame data including:
     * - Technology type (A, B, F, V)
     * - Frame type (SENS_REQ, SENSF_REQ, etc.)
     * - Raw frame bytes
     */
    public interface PollingFrameCallback {
        void onPollingFrame(int technology, int frameType, byte[] frameData);
    }

    public void registerPollingFrameCallback(PollingFrameCallback callback) {
        // Register callback for NFA_POLL_FRAME_EVT
    }
}

/**
 * JAVA LAYER BLOCKING ANALYSIS
 *
 * Even if native layer bypass is achieved, Java/Kotlin layer may
 * also have blocking logic.
 *
 * Key classes to investigate:
 * 
 * 1. NfcService.java
 *    - Main NFC service implementation
 *    - Contains state machine for NFC operations
 *    - May block sendData() calls based on state
 *
 * 2. NfcAdapter.java
 *    - Public API for NFC operations
 *    - transceive() and related methods
 *
 * 3. HostNfcFService.java
 *    - HCE-F service base class
 *    - processCommandApdu() for receiving commands
 *    - sendResponseApdu() for sending responses
 *
 * 4. CardEmulation.java
 *    - Card emulation manager
 *    - System code routing configuration
 *
 * JAVA HOOKS (if needed):
 * - Use Xposed/LSPosed to hook Java methods
 * - NfcService.sendData() - bypass state check
 * - Enable debug mode to allow operations
 */

/**
 * AIDL INTERFACE
 * 
 * Communication between Java and Native layers uses AIDL.
 * 
 * INfcAdapter.aidl:
 * - setObserveMode(boolean enable)
 * - getPollingFrame() 
 * - sendRawFrame(byte[] data) - BLOCKED IN OBSERVE MODE
 *
 * The AIDL interface implementation in NfcService checks
 * current state before allowing operations.
 */

/**
 * SUMMARY: OBSERVE MODE BLOCKING HIERARCHY
 *
 * Level 1: Java/Kotlin (NfcService)
 * - State check in sendRawFrame()
 * - Bypass: Xposed hook on sendRawFrame()
 *
 * Level 2: AIDL/JNI Bridge
 * - May have additional state validation
 * - Bypass: Hook JNI function
 *
 * Level 3: NFA Layer (libnfc-nci.so)
 * - nfa_dm_is_data_exchange_allowed()
 * - Bypass: Frida hook returning true
 *
 * Level 4: NCI Layer (libnfc-nci.so)
 * - nci_snd_data() state check
 * - Bypass: Frida hook or state modification
 *
 * Level 5: HAL Layer
 * - hal_nfc_write() - minimal checking
 * - Bypass: Direct call to HAL write
 *
 * Level 6: NFCC Firmware
 * - Hardware state machine
 * - Bypass: UNKNOWN - may not be possible
 *   - Firmware validates RF state
 *   - May silently drop packets not expected in current state
 */
