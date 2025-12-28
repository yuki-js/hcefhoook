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
 * REFERENCE FILE: AOSP system/nfc NCI Host Receive Functions
 * This file is a reference excerpt for research purposes.
 *
 * Key functions for Observe Mode polling frame notification handling:
 */

#include "nci_hrcv.h"

/*******************************************************************************
 * nci_proc_rf_management_ntf
 * 
 * CRITICAL FOR OBSERVE MODE:
 * This function processes RF Management Notifications from NFCC.
 * In Observe Mode, this includes:
 * - NCI_ANDROID_POLLING_FRAME_NTF (Android vendor-specific notification)
 * - Standard RF_INTF_ACTIVATED_NTF events
 * 
 * When observing SENSF_REQ (SC=FFFF), the notification path is:
 * NFCC -> HAL -> nci_proc_rf_management_ntf -> NFA layer -> App
 ******************************************************************************/
void nci_proc_rf_management_ntf(BT_HDR* p_msg) {
    uint8_t* p;
    uint8_t* pp;
    uint8_t op_code;
    uint8_t len;

    pp = (uint8_t*)(p_msg + 1) + p_msg->offset;
    
    NCI_MSG_PRS_HDR0(pp, &op_code);
    len = *pp++;

    switch (op_code) {
        case NCI_MSG_RF_DISCOVER_NTF:
            nfc_ncif_rf_disc_ntf(p_msg);
            break;

        case NCI_MSG_RF_INTF_ACTIVATED_NTF:
            nfc_ncif_rf_intf_activated(p_msg);
            break;

        case NCI_MSG_RF_DEACTIVATE_NTF:
            nfc_ncif_rf_deactivate(p_msg);
            break;

        case NCI_MSG_RF_FIELD_INFO_NTF:
            /*
             * OBSERVE MODE HOOK POINT:
             * Field detection notification - indicates external RF field presence
             * In Observe Mode, this triggers before polling frame notifications
             */
            nfc_ncif_rf_field_ntf(p_msg);
            break;

        case NCI_ANDROID_POLLING_FRAME_NTF:
            /*
             * ANDROID VENDOR EXTENSION FOR OBSERVE MODE:
             * This notification carries the raw polling frame data.
             * 
             * Payload structure:
             * [1B: Technology] [1B: Frame Type] [nB: Frame Data]
             * 
             * For SENSF_REQ:
             * Technology = NFC_RF_TECHNOLOGY_F
             * Frame Type = NFC_POLL_FRAME_TYPE_SENSF_REQ
             * Frame Data = [Len][00][SC_HI][SC_LO][RC][TSN]
             */
            nfc_ncif_proc_android_polling_ntf(p_msg);
            break;

        default:
            LOG(WARNING) << StringPrintf("Unknown RF NTF: 0x%02x", op_code);
            break;
    }
}

/*******************************************************************************
 * nfc_ncif_proc_android_polling_ntf
 * 
 * OBSERVE MODE POLLING FRAME HANDLER:
 * Processes Android-specific polling frame notifications.
 * This is where SENSF_REQ frames are delivered to the Host.
 ******************************************************************************/
void nfc_ncif_proc_android_polling_ntf(BT_HDR* p_msg) {
    uint8_t* p;
    uint8_t tech;
    uint8_t frame_type;
    uint8_t* p_frame_data;
    uint16_t frame_len;

    p = (uint8_t*)(p_msg + 1) + p_msg->offset + NCI_MSG_HDR_SIZE;
    
    STREAM_TO_UINT8(tech, p);
    STREAM_TO_UINT8(frame_type, p);
    frame_len = p_msg->len - NCI_MSG_HDR_SIZE - 2;
    p_frame_data = p;

    LOG(DEBUG) << StringPrintf("Polling NTF: tech=%d type=%d len=%d", 
                                tech, frame_type, frame_len);

    // Notify NFA layer
    tNFA_CONN_EVT_DATA conn_evt;
    conn_evt.polling_frame.tech = tech;
    conn_evt.polling_frame.frame_type = frame_type;
    conn_evt.polling_frame.frame_len = frame_len;
    conn_evt.polling_frame.p_data = p_frame_data;

    (*nfc_cb.p_conn_cback)(NFA_POLL_FRAME_EVT, &conn_evt);
}

/*******************************************************************************
 * RF STATE TRANSITIONS
 * 
 * CRITICAL STATE ANALYSIS FOR RESEARCH:
 * 
 * Normal HCE-F Flow:
 * IDLE -> DISCOVERY -> W4_ALL_DISCOVERIES_COMPLETE -> W4_HOST_SELECT 
 *      -> LISTEN_ACTIVE -> [Data Exchange]
 * 
 * Observe Mode Flow:
 * IDLE -> DISCOVERY -> OBSERVE_MODE_ACTIVE -> [Notifications Only]
 *                                          -> [NO DATA TX ALLOWED]
 * 
 * The key difference: In Observe Mode, the state machine never transitions
 * to LISTEN_ACTIVE, which is required for nci_snd_data() to succeed.
 ******************************************************************************/

// State definitions (from nfc_api.h)
#define NFA_DM_RFST_IDLE              0x00
#define NFA_DM_RFST_DISCOVERY         0x01
#define NFA_DM_RFST_W4_ALL_DISCOVERIES_COMPLETE 0x02
#define NFA_DM_RFST_W4_HOST_SELECT    0x03
#define NFA_DM_RFST_POLL_ACTIVE       0x04
#define NFA_DM_RFST_LISTEN_ACTIVE     0x05
#define NFA_DM_RFST_LISTEN_SLEEP      0x06
#define NFA_DM_RFST_LP_LISTEN         0x07
#define NFA_DM_RFST_LP_ACTIVE         0x08

/*******************************************************************************
 * CHECK STATE FOR DATA TX
 * 
 * BLOCKING LOGIC IDENTIFIED:
 * This check prevents data transmission unless in active states.
 ******************************************************************************/
bool nfc_ncif_can_send_data(void) {
    uint8_t rf_state = nfa_dm_cb.disc_cb.disc_state;
    
    // BLOCKING CONDITION:
    // Only POLL_ACTIVE or LISTEN_ACTIVE allow data transmission
    if (rf_state == NFA_DM_RFST_POLL_ACTIVE || 
        rf_state == NFA_DM_RFST_LISTEN_ACTIVE) {
        return true;
    }
    
    LOG(WARNING) << "Data TX blocked: RF state=" << rf_state;
    return false;
}
