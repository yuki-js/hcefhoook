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
 * REFERENCE FILE: AOSP system/nfc NFA Discovery Module
 * This file is a reference excerpt for research purposes.
 *
 * NFA Device Manager - Discovery state machine implementation
 * Critical for understanding Observe Mode behavior
 */

#include "nfa_dm_int.h"

/*******************************************************************************
 * OBSERVE MODE STATE MACHINE
 * 
 * This module manages RF discovery including the Observe Mode introduced
 * in Android 15. Key insight: Observe Mode is a software construct that
 * configures NFCC to not auto-respond while still reporting RF activity.
 ******************************************************************************/

/*******************************************************************************
 * nfa_dm_start_rf_discover
 * 
 * Initiates RF Discovery with configured technologies.
 * For Observe Mode, special configuration prevents auto-response.
 ******************************************************************************/
tNFA_STATUS nfa_dm_start_rf_discover(void) {
    tNFC_DISCOVER_PARAMS disc_params[NFA_DM_MAX_DISC_PARAMS];
    uint8_t num_params = 0;

    // Check if Observe Mode is enabled
    if (nfa_dm_cb.flags & NFA_DM_FLAGS_OBSERVE_MODE) {
        LOG(INFO) << "Starting discovery in Observe Mode";
        
        /*
         * OBSERVE MODE CONFIGURATION:
         * 1. Enable RF field detection notifications
         * 2. Disable automatic SENSF_RES generation
         * 3. Route all polling frames to Host
         */
        nfa_dm_set_observe_mode_config(true);
    }

    // Configure Listen modes
    if (nfa_dm_cb.disc_cb.listen_enabled) {
        // Listen A
        if (nfa_dm_cb.disc_cb.listen_tech_mask & NFA_TECHNOLOGY_MASK_A) {
            disc_params[num_params].type = NCI_DISCOVERY_TYPE_LISTEN_A;
            disc_params[num_params].frequency = 1;
            num_params++;
        }
        
        // Listen F (FeliCa) - CRITICAL FOR SENSF_REQ OBSERVATION
        if (nfa_dm_cb.disc_cb.listen_tech_mask & NFA_TECHNOLOGY_MASK_F) {
            disc_params[num_params].type = NCI_DISCOVERY_TYPE_LISTEN_F;
            disc_params[num_params].frequency = 1;
            num_params++;
        }
    }

    // Send discovery command to NFCC
    return nfc_ncif_discover(num_params, disc_params);
}

/*******************************************************************************
 * nfa_dm_set_observe_mode_config
 * 
 * CRITICAL FUNCTION FOR OBSERVE MODE:
 * Configures NFCC for Observe Mode operation.
 * 
 * Key configuration parameters:
 * - LF_T3T_FLAGS: Disable automatic T3T response
 * - NCI_PARAM_OBSERVE_MODE: Vendor extension for observe mode
 ******************************************************************************/
void nfa_dm_set_observe_mode_config(bool enable) {
    uint8_t config_buf[32];
    uint8_t* p = config_buf;

    if (enable) {
        /*
         * DISABLE AUTO-RESPONSE:
         * Setting LF_T3T_FLAGS to 0 prevents NFCC from automatically
         * generating SENSF_RES when SENSF_REQ is received.
         * 
         * Standard config: LF_T3T_FLAGS (0x53) = 0x00
         */
        UINT8_TO_STREAM(p, NCI_PARAM_ID_LF_T3T_FLAGS);
        UINT8_TO_STREAM(p, 1);  // length
        UINT8_TO_STREAM(p, 0);  // value: disable

        /*
         * ANDROID OBSERVE MODE EXTENSION:
         * Vendor-specific parameter to enable polling frame notifications
         */
        UINT8_TO_STREAM(p, NCI_PARAM_ID_ANDROID_OBSERVE_MODE);
        UINT8_TO_STREAM(p, 1);  // length
        UINT8_TO_STREAM(p, 1);  // value: enable

        LOG(INFO) << "Observe Mode configuration applied";
    } else {
        // Restore normal operation
        UINT8_TO_STREAM(p, NCI_PARAM_ID_LF_T3T_FLAGS);
        UINT8_TO_STREAM(p, 1);
        UINT8_TO_STREAM(p, 1);  // Enable auto-response

        UINT8_TO_STREAM(p, NCI_PARAM_ID_ANDROID_OBSERVE_MODE);
        UINT8_TO_STREAM(p, 1);
        UINT8_TO_STREAM(p, 0);  // Disable
    }

    nfc_ncif_set_config(p - config_buf, config_buf);
}

/*******************************************************************************
 * DISCOVERY STATE MACHINE
 * 
 * States:
 * - NFA_DM_RFST_IDLE: No RF activity
 * - NFA_DM_RFST_DISCOVERY: Active discovery, waiting for targets
 * - NFA_DM_RFST_LISTEN_ACTIVE: Activated in Listen mode (data exchange allowed)
 * 
 * OBSERVE MODE BLOCKING:
 * In Observe Mode, the state never transitions from DISCOVERY to LISTEN_ACTIVE.
 * This is intentional - the device is "observing" not "participating".
 ******************************************************************************/

static const uint8_t nfa_dm_disc_state_tbl[][NFA_DM_DISC_NUM_COLS] = {
    /* IDLE state */
    {NFA_DM_RFST_DISCOVERY, NFA_DM_RFST_IDLE, NFA_DM_RFST_IDLE},
    
    /* DISCOVERY state */
    {NFA_DM_RFST_DISCOVERY, NFA_DM_RFST_W4_ALL_DISCOVERIES_COMPLETE, NFA_DM_RFST_LISTEN_ACTIVE},
    
    /* OBSERVE MODE: Stays in DISCOVERY, never activates */
    /* This is the root cause of TX blocking */
};

/*******************************************************************************
 * nfa_dm_disc_sm_execute
 * 
 * Main discovery state machine execution.
 * 
 * HOOK POINT FOR BYPASS:
 * To enable TX in Observe Mode, one approach is to:
 * 1. Hook this function
 * 2. Force state to LISTEN_ACTIVE when polling frame received
 * 3. Attempt data transmission
 * 4. Restore original state
 ******************************************************************************/
void nfa_dm_disc_sm_execute(tNFA_DM_DISC_SM_EVT event, tNFA_DM_DISC_DATA* p_data) {
    tNFA_DM_DISC_SM_STATE old_state = nfa_dm_cb.disc_cb.disc_state;
    
    LOG(DEBUG) << StringPrintf("disc_sm event=%d state=%d", event, old_state);

    switch (nfa_dm_cb.disc_cb.disc_state) {
        case NFA_DM_RFST_IDLE:
            nfa_dm_disc_sm_idle(event, p_data);
            break;

        case NFA_DM_RFST_DISCOVERY:
            nfa_dm_disc_sm_discovery(event, p_data);
            break;

        case NFA_DM_RFST_W4_ALL_DISCOVERIES_COMPLETE:
            nfa_dm_disc_sm_w4_all_disc_complete(event, p_data);
            break;

        case NFA_DM_RFST_W4_HOST_SELECT:
            nfa_dm_disc_sm_w4_host_select(event, p_data);
            break;

        case NFA_DM_RFST_POLL_ACTIVE:
            nfa_dm_disc_sm_poll_active(event, p_data);
            break;

        case NFA_DM_RFST_LISTEN_ACTIVE:
            nfa_dm_disc_sm_listen_active(event, p_data);
            break;

        case NFA_DM_RFST_LISTEN_SLEEP:
            nfa_dm_disc_sm_listen_sleep(event, p_data);
            break;
    }

    LOG(DEBUG) << StringPrintf("disc_sm: state change %d -> %d", 
                                old_state, nfa_dm_cb.disc_cb.disc_state);
}

/*******************************************************************************
 * DATA EXCHANGE BLOCKING CHECK
 * 
 * CRITICAL FUNCTION - PRIMARY BLOCKING POINT:
 * This function is called before any data transmission attempt.
 * Returns false (blocking) unless in LISTEN_ACTIVE or POLL_ACTIVE state.
 ******************************************************************************/
bool nfa_dm_is_data_exchange_allowed(void) {
    uint8_t state = nfa_dm_cb.disc_cb.disc_state;
    
    /*
     * BLOCKING CONDITION:
     * Only these states allow data exchange:
     * - NFA_DM_RFST_POLL_ACTIVE (device activated a target)
     * - NFA_DM_RFST_LISTEN_ACTIVE (device was activated by external reader)
     * 
     * In Observe Mode, state stays at NFA_DM_RFST_DISCOVERY,
     * so this check ALWAYS FAILS -> TX is blocked
     */
    if (state != NFA_DM_RFST_POLL_ACTIVE && 
        state != NFA_DM_RFST_LISTEN_ACTIVE) {
        LOG(WARNING) << "Data exchange blocked: state=" << state;
        return false;
    }
    
    return true;
}

/*******************************************************************************
 * BYPASS STRATEGY #1: State Spoofing
 * 
 * RESEARCH APPROACH:
 * Hook nfa_dm_is_data_exchange_allowed() to always return true
 * 
 * Risks:
 * - NFCC may still reject the data at firmware level
 * - Timing issues with RF protocol
 * - Potential crash if connection ID is invalid
 ******************************************************************************/
