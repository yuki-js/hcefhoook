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
 * REFERENCE FILE: AOSP system/nfc NCI Host Message Functions
 * This file is a reference excerpt for research purposes.
 *
 * Key functions relevant to Observe Mode and SENSF_RES injection research:
 */

#include "nci_hmsgs.h"

/*******************************************************************************
 * NCI_CORE_SET_CONFIG_CMD
 * Used to configure NFCC parameters including Listen mode settings.
 * 
 * CRITICAL FOR RESEARCH:
 * - This function can configure LA_NFCF_CONFIG (Listen A/F config)
 * - Parameter ID: 0x33 - LF_PROTOCOL_TYPE
 * - Parameter ID: 0x39 - LF_T3T_IDENTIFIERS_*
 * - Parameter ID: 0x3A - LF_T3T_PMM
 ******************************************************************************/
tNCI_STATUS nci_snd_core_set_config(uint8_t* p_param_tlvs, uint8_t tlv_size) {
    NFC_HDR* p;
    uint8_t* pp;

    p = NCI_GET_CMD_BUF(tlv_size);
    if (p == nullptr) return NCI_STATUS_FAILED;

    p->event = BT_EVT_TO_NFC_NCI;
    p->len = NCI_MSG_HDR_SIZE + 1 + tlv_size;
    p->offset = NCI_MSG_OFFSET_SIZE;
    pp = (uint8_t*)(p + 1) + p->offset;

    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_CORE);
    NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_SET_CONFIG);
    UINT8_TO_STREAM(pp, (uint8_t)(1 + tlv_size));
    UINT8_TO_STREAM(pp, (uint8_t)(tlv_size / 2)); // num params
    ARRAY_TO_STREAM(pp, p_param_tlvs, tlv_size);

    nfc_ncif_send_cmd(p);
    return NCI_STATUS_OK;
}

/*******************************************************************************
 * NCI_RF_DISCOVER_CMD
 * Initiates RF Discovery (for Listen/Poll modes).
 * 
 * OBSERVE MODE IMPLICATION:
 * When observe mode is enabled, discovery includes special handling that
 * prevents normal Listen mode responses. The NFCC enters a passive state
 * where it monitors RF but doesn't respond automatically.
 ******************************************************************************/
tNCI_STATUS nci_snd_discover_cmd(uint8_t num, tNCI_DISCOVER_PARAMS* p_param) {
    NFC_HDR* p;
    uint8_t* pp;
    int params_size;
    int i;

    params_size = 0;
    for (i = 0; i < num; i++) {
        params_size += 2; /* rf_tech_mode + discovery_frequency */
    }

    p = NCI_GET_CMD_BUF(params_size);
    if (p == nullptr) return NCI_STATUS_FAILED;

    p->event = BT_EVT_TO_NFC_NCI;
    p->len = NCI_MSG_HDR_SIZE + 1 + params_size;
    p->offset = NCI_MSG_OFFSET_SIZE;
    pp = (uint8_t*)(p + 1) + p->offset;

    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_RF_MANAGE);
    NCI_MSG_BLD_HDR1(pp, NCI_MSG_RF_DISCOVER);
    UINT8_TO_STREAM(pp, (uint8_t)(1 + params_size));
    UINT8_TO_STREAM(pp, num);

    for (i = 0; i < num; i++) {
        UINT8_TO_STREAM(pp, p_param[i].type);
        UINT8_TO_STREAM(pp, p_param[i].frequency);
    }

    nfc_ncif_send_cmd(p);
    return NCI_STATUS_OK;
}

/*******************************************************************************
 * nci_snd_data
 * 
 * CRITICAL FUNCTION FOR RESEARCH:
 * This is the primary function to send data packets via NCI.
 * In Observe Mode, this function's behavior is constrained by the
 * current RF state - data transmission is blocked when NFCC is not
 * in an active communication state.
 * 
 * BLOCKING POINT ANALYSIS:
 * - Checks nfc_cb.nfc_state against NFC_STATE_OPEN
 * - Verifies conn_id validity
 * - State machine must be in NFA_DM_RFST_LISTEN_ACTIVE or higher
 ******************************************************************************/
tNCI_STATUS nci_snd_data(uint8_t conn_id, BT_HDR* p_buf) {
    uint8_t* pp;
    uint8_t len;

    // STATE VALIDATION (BLOCKING POINT #1)
    if (nfc_cb.nfc_state != NFC_STATE_OPEN) {
        GKI_freebuf(p_buf);
        return NCI_STATUS_FAILED;
    }

    // CONNECTION VALIDATION (BLOCKING POINT #2)
    if (conn_id >= NCI_MAX_CONN_CBS || !nfc_cb.conn_cb[conn_id].p_cback) {
        GKI_freebuf(p_buf);
        return NCI_STATUS_FAILED;
    }

    len = p_buf->len;
    pp = (uint8_t*)(p_buf + 1) + p_buf->offset - NCI_DATA_HDR_SIZE;

    // Build NCI data packet header
    NCI_DATA_BLD_HDR(pp, conn_id, len);

    p_buf->offset -= NCI_DATA_HDR_SIZE;
    p_buf->len += NCI_DATA_HDR_SIZE;

    // Send to HAL layer
    nfc_ncif_send_data(p_buf, conn_id);
    return NCI_STATUS_OK;
}

/*******************************************************************************
 * VENDOR SPECIFIC COMMANDS
 * 
 * RESEARCH NOTE: Vendor-specific commands may provide backdoor access
 * to send raw RF data bypassing state machine checks.
 * 
 * NXP/ST/Samsung controllers have proprietary extensions.
 * Example: NCI_PROP_RAW_RF_FRAME (vendor-defined OID)
 ******************************************************************************/
tNCI_STATUS nci_snd_vs_cmd(uint8_t oid, uint8_t* p_data, uint16_t data_len) {
    NFC_HDR* p;
    uint8_t* pp;

    p = NCI_GET_CMD_BUF(data_len);
    if (p == nullptr) return NCI_STATUS_FAILED;

    p->event = BT_EVT_TO_NFC_NCI;
    p->len = NCI_MSG_HDR_SIZE + data_len;
    p->offset = NCI_MSG_OFFSET_SIZE;
    pp = (uint8_t*)(p + 1) + p->offset;

    // GID = 0x0F for vendor-specific
    NCI_MSG_BLD_HDR0(pp, NCI_MT_CMD, NCI_GID_PROP);
    NCI_MSG_BLD_HDR1(pp, oid);
    UINT8_TO_STREAM(pp, data_len);
    
    if (data_len > 0 && p_data) {
        ARRAY_TO_STREAM(pp, p_data, data_len);
    }

    nfc_ncif_send_cmd(p);
    return NCI_STATUS_OK;
}
