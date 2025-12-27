/*
 * Copyright (C) 2010-2014 NXP Semiconductors
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * REFERENCE FILE: AOSP system/nfc NFA T3T Module
 * This file is a reference excerpt for research purposes.
 *
 * NFC-F (FeliCa/T3T) specific handling - CRITICAL for SENSF_RES injection
 */

#include "nfa_t3t_int.h"

/*******************************************************************************
 * T3T/NFC-F PROTOCOL OVERVIEW
 * 
 * FeliCa (NFC-F) uses Type 3 Tag (T3T) protocol.
 * 
 * Key Commands:
 * - SENSF_REQ: Polling request from reader
 * - SENSF_RES: Response from tag/emulator
 * 
 * Frame Structure:
 * SENSF_REQ: [Length][0x00][SC_H][SC_L][RC][TSN]
 * SENSF_RES: [Length][0x01][IDm 8B][PMm 8B][RD 2B opt]
 ******************************************************************************/

/*******************************************************************************
 * NFA_HciSendApdu / SendRawFrame for T3T
 * 
 * STANDARD API PATH:
 * Application -> NFA_SendRawFrame -> nfa_hci_send_raw_cmd -> nci_snd_data
 * 
 * BLOCKING IN OBSERVE MODE:
 * NFA_SendRawFrame() checks discovery state before proceeding.
 * In Observe Mode, state is DISCOVERY not LISTEN_ACTIVE, so it fails.
 ******************************************************************************/
tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len,
                              uint16_t presence_check_start_delay) {
    tNFA_DM_API_SEND_RAW* p_msg;

    // STATE CHECK - BLOCKING POINT
    if (!nfa_dm_is_data_exchange_allowed()) {
        LOG(ERROR) << "SendRawFrame: blocked by state machine";
        return NFA_STATUS_WRONG_DISCOVERY_STATE;  // Returns error code 0x0A
    }

    p_msg = (tNFA_DM_API_SEND_RAW*)GKI_getbuf(sizeof(tNFA_DM_API_SEND_RAW) + data_len);
    if (p_msg != nullptr) {
        p_msg->hdr.event = NFA_DM_API_RAW_FRAME_EVT;
        p_msg->p_data = (uint8_t*)(p_msg + 1);
        memcpy(p_msg->p_data, p_raw_data, data_len);
        p_msg->data_len = data_len;
        p_msg->presence_check_start_delay = presence_check_start_delay;
        
        nfa_sys_sendmsg(p_msg);
        return NFA_STATUS_OK;
    }
    return NFA_STATUS_FAILED;
}

/*******************************************************************************
 * nfa_t3t_handle_sensf_req
 * 
 * OBSERVE MODE RECEIVE PATH:
 * When NFCC receives SENSF_REQ and Observe Mode is enabled:
 * 1. NFCC does NOT auto-respond with SENSF_RES
 * 2. NFCC sends NCI_ANDROID_POLLING_FRAME_NTF to Host
 * 3. This function is called with the SENSF_REQ data
 * 4. Application is notified via callback
 * 
 * INJECTION POINT:
 * At step 3, if we could force a SENSF_RES transmission, we'd achieve
 * the host-based response goal.
 ******************************************************************************/
void nfa_t3t_handle_sensf_req(uint8_t* p_sensf_req, uint16_t req_len) {
    uint8_t sc_hi, sc_lo;
    uint8_t rc, tsn;
    
    if (req_len < 6) {
        LOG(ERROR) << "Invalid SENSF_REQ length: " << req_len;
        return;
    }
    
    // Parse SENSF_REQ
    // Format: [Len][0x00][SC_H][SC_L][RC][TSN]
    sc_hi = p_sensf_req[2];
    sc_lo = p_sensf_req[3];
    rc = p_sensf_req[4];
    tsn = p_sensf_req[5];
    
    uint16_t system_code = (sc_hi << 8) | sc_lo;
    
    LOG(DEBUG) << StringPrintf("SENSF_REQ: SC=0x%04X RC=0x%02X TSN=0x%02X",
                                system_code, rc, tsn);
    
    // Check for wildcard system code (SC=0xFFFF)
    if (system_code == 0xFFFF) {
        LOG(INFO) << "Wildcard SENSF_REQ received (SC=FFFF)";
        
        /*
         * CRITICAL: eSE BYPASS SCENARIO
         * 
         * Normal flow: When SC=FFFF, eSE would respond automatically.
         * Observe Mode: eSE is silenced, Host receives notification.
         * 
         * This is where Host-based SENSF_RES injection should occur.
         */
    }
    
    // Notify application
    tNFA_CONN_EVT_DATA evt_data;
    evt_data.sensf_req.p_data = p_sensf_req;
    evt_data.sensf_req.data_len = req_len;
    evt_data.sensf_req.system_code = system_code;
    
    (*nfa_dm_cb.p_conn_cback)(NFA_SENSF_REQ_EVT, &evt_data);
}

/*******************************************************************************
 * BUILD SENSF_RES FRAME
 * 
 * Utility function to construct a valid SENSF_RES response.
 * This would be the payload for injection.
 ******************************************************************************/
void nfa_t3t_build_sensf_res(uint8_t* p_idm, uint8_t* p_pmm, 
                              uint8_t* p_buffer, uint8_t* p_len) {
    uint8_t* p = p_buffer;
    
    // Length byte (placeholder, updated at end)
    *p++ = 0;
    
    // Response code
    *p++ = T3T_MSG_RSP_CODE_SENSF;  // 0x01
    
    // IDm (8 bytes)
    memcpy(p, p_idm, 8);
    p += 8;
    
    // PMm (8 bytes)
    memcpy(p, p_pmm, 8);
    p += 8;
    
    // Optional: RD (Request Data) - depends on RC in request
    // Omitted for basic response
    
    // Update length byte
    *p_len = p - p_buffer;
    p_buffer[0] = *p_len;
}

/*******************************************************************************
 * DIRECT NFCC ACCESS FOR SENSF_RES INJECTION
 * 
 * RESEARCH: POTENTIAL BYPASS PATHS
 * 
 * Path 1: nci_snd_vs_cmd() - Vendor-specific command
 *   - May allow raw RF frame transmission
 *   - Vendor-dependent (NXP, ST, Samsung have different OIDs)
 * 
 * Path 2: Direct HAL write
 *   - Bypass NCI state machine entirely
 *   - Write raw NCI packet to HAL transport
 *   - Risk: NFCC may reject malformed/unexpected packets
 * 
 * Path 3: State machine manipulation
 *   - Hook state check functions
 *   - Temporarily spoof LISTEN_ACTIVE state
 *   - Use normal SendRawFrame API
 ******************************************************************************/

/*******************************************************************************
 * VENDOR-SPECIFIC: NXP PN553/PN557 Raw RF Frame
 * 
 * NXP controllers support proprietary command for raw RF transmission.
 * OID: 0x3F (vendor-specific)
 * 
 * Frame format:
 * [GID=0F][OID=3F][Len][RF_Tech][Data...]
 ******************************************************************************/
#define NXP_NCI_PROP_OID_RAW_RF_FRAME 0x3F

tNFA_STATUS nfa_t3t_send_raw_rf_frame_nxp(uint8_t* p_data, uint16_t data_len) {
    uint8_t cmd_buf[256];
    uint8_t* p = cmd_buf;
    
    // RF Technology: NFC-F
    *p++ = NCI_RF_TECHNOLOGY_F;
    
    // Raw frame data (SENSF_RES)
    memcpy(p, p_data, data_len);
    p += data_len;
    
    return nci_snd_vs_cmd(NXP_NCI_PROP_OID_RAW_RF_FRAME, cmd_buf, p - cmd_buf);
}

/*******************************************************************************
 * INTERNAL NCI DATA SEND (BYPASSING NFA CHECKS)
 * 
 * This function shows how to send data at NCI layer directly.
 * The NFA layer checks can be bypassed by calling NCI functions directly.
 * 
 * However, NCI layer also has state validation.
 ******************************************************************************/
tNCI_STATUS nfa_t3t_force_send_data(uint8_t conn_id, uint8_t* p_data, uint16_t len) {
    BT_HDR* p_buf;
    uint8_t* p;
    
    p_buf = (BT_HDR*)GKI_getpoolbuf(NFC_NCI_POOL_ID);
    if (p_buf == nullptr) return NCI_STATUS_FAILED;
    
    p_buf->offset = NCI_MSG_OFFSET_SIZE + NCI_DATA_HDR_SIZE;
    p = (uint8_t*)(p_buf + 1) + p_buf->offset;
    
    memcpy(p, p_data, len);
    p_buf->len = len;
    
    /*
     * DIRECT CALL TO NCI:
     * Bypasses NFA state checks but NCI layer still validates.
     * 
     * To fully bypass, need to:
     * 1. Hook nci_snd_data() state check
     * 2. Or call nfc_ncif_send_data() directly (even lower level)
     */
    return nci_snd_data(conn_id, p_buf);
}
