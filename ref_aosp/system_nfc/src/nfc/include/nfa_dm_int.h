/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * REFERENCE FILE: AOSP system/nfc Control Blocks
 * This file contains global state structures that are critical for
 * understanding and manipulating the NFC stack state.
 */

#ifndef NFA_DM_INT_H
#define NFA_DM_INT_H

#include <stdint.h>
#include "nci_defs.h"

/*******************************************************************************
 * NFA DEVICE MANAGER STATE DEFINITIONS
 * 
 * These states control the discovery state machine.
 * CRITICAL: Data transmission is only allowed in specific states.
 ******************************************************************************/

/* RF Discovery States */
#define NFA_DM_RFST_IDLE                    0x00
#define NFA_DM_RFST_DISCOVERY               0x01
#define NFA_DM_RFST_W4_ALL_DISCOVERIES      0x02
#define NFA_DM_RFST_W4_HOST_SELECT          0x03
#define NFA_DM_RFST_POLL_ACTIVE             0x04
#define NFA_DM_RFST_LISTEN_ACTIVE           0x05  /* REQUIRED FOR DATA TX */
#define NFA_DM_RFST_LISTEN_SLEEP            0x06
#define NFA_DM_RFST_LP_LISTEN               0x07
#define NFA_DM_RFST_LP_ACTIVE               0x08

/*******************************************************************************
 * NFA DM FLAGS
 ******************************************************************************/
#define NFA_DM_FLAGS_DM_IS_ACTIVE           0x0001
#define NFA_DM_FLAGS_EXCL_RF_ACTIVE         0x0002
#define NFA_DM_FLAGS_POLLING_ENABLED        0x0004
#define NFA_DM_FLAGS_OBSERVE_MODE           0x0008  /* Observe mode enabled */
#define NFA_DM_FLAGS_SEND_RAW_FRAME         0x0010
#define NFA_DM_FLAGS_AUTO_READING_NDEF      0x0020
#define NFA_DM_FLAGS_ENABLING_POLLING       0x0040
#define NFA_DM_FLAGS_DISABLING_POLLING      0x0080
#define NFA_DM_FLAGS_LISTEN_DISABLED        0x0100

/*******************************************************************************
 * NFA DM DISCOVERY CONTROL BLOCK
 * 
 * This structure maintains the discovery state.
 * The disc_state field is the CRITICAL field for state checking.
 ******************************************************************************/
typedef struct {
    uint8_t disc_state;             /* Current discovery state */
    uint8_t disc_flags;             /* Discovery flags */
    uint16_t listen_tech_mask;      /* Technologies for Listen mode */
    uint16_t poll_tech_mask;        /* Technologies for Poll mode */
    uint8_t num_disc_maps;          /* Number of discovery maps */
    bool listen_enabled;            /* Listen mode enabled */
    bool poll_enabled;              /* Poll mode enabled */
    
    /* T3T Listen configuration */
    uint8_t t3t_system_code[2];     /* System code for T3T */
    uint8_t t3t_pmm[8];             /* PMm for T3T */
    uint8_t t3t_idm[8];             /* IDm for T3T */
    
    /* Observe mode specific */
    bool observe_mode_enabled;       /* Observe mode flag */
    
} tNFA_DM_DISC_CB;

/*******************************************************************************
 * NFA DM CONTROL BLOCK (MAIN STRUCTURE)
 * 
 * This is the main control block for NFA Device Manager.
 * Contains all state information for the NFC stack.
 * 
 * GLOBAL VARIABLE: nfa_dm_cb (in libnfc-nci.so)
 ******************************************************************************/
typedef struct {
    uint32_t flags;                 /* NFA_DM_FLAGS_* */
    
    tNFA_DM_DISC_CB disc_cb;        /* Discovery control block */
    
    void* p_conn_cback;             /* Connection callback */
    void* p_excl_conn_cback;        /* Exclusive connection callback */
    
    uint8_t activated_tech_mode;    /* Activated technology mode */
    uint8_t activated_intf;         /* Activated interface */
    uint8_t activated_protocol;     /* Activated protocol */
    
    /* Connection data */
    uint8_t conn_id;                /* Connection ID for data exchange */
    bool data_exchange_active;      /* Data exchange in progress */
    
} tNFA_DM_CB;

/* Global control block - CRITICAL FOR HOOKING */
extern tNFA_DM_CB nfa_dm_cb;

/*******************************************************************************
 * NFC CONTROL BLOCK
 * 
 * Lower-level control block for NFC subsystem.
 ******************************************************************************/
typedef struct {
    uint8_t nfc_state;              /* NFC subsystem state */
    uint8_t num_conn_cbs;           /* Number of connection control blocks */
    
    /* Connection control blocks */
    struct {
        void* p_cback;
        uint8_t conn_id;
        uint8_t buff_size;
        uint8_t num_buff;
    } conn_cb[4];
    
    void* p_conn_cback;             /* Connection callback */
    void* p_resp_cback;             /* Response callback */
    
    uint8_t trace_level;            /* Trace level */
    
} tNFC_CB;

/* NFC states */
#define NFC_STATE_NONE              0x00
#define NFC_STATE_W4_HAL_OPEN       0x01
#define NFC_STATE_CORE_INIT         0x02
#define NFC_STATE_W4_POST_INIT_CPLT 0x03
#define NFC_STATE_IDLE              0x04
#define NFC_STATE_OPEN              0x05  /* REQUIRED FOR DATA TX */
#define NFC_STATE_CLOSING           0x06
#define NFC_STATE_W4_HAL_CLOSE      0x07
#define NFC_STATE_NFCC_POWER_OFF_SLEEP 0x08

/* Global control block - CRITICAL FOR HOOKING */
extern tNFC_CB nfc_cb;

/*******************************************************************************
 * HOOKING TARGET SUMMARY
 * 
 * To bypass state checks for SENSF_RES injection:
 * 
 * 1. nfa_dm_cb.disc_cb.disc_state
 *    - Current value in Observe Mode: NFA_DM_RFST_DISCOVERY (0x01)
 *    - Required value for TX: NFA_DM_RFST_LISTEN_ACTIVE (0x05)
 *    - ACTION: Temporarily modify to 0x05 before TX, restore after
 * 
 * 2. nfc_cb.nfc_state
 *    - Must be NFC_STATE_OPEN (0x05)
 *    - Usually already correct if NFC is enabled
 * 
 * 3. Connection ID
 *    - Need valid conn_id for data transmission
 *    - In Observe Mode, no connection is established
 *    - May need to use NCI_STATIC_RF_CONN_ID (0x00)
 * 
 * 4. Function hooks:
 *    - nfa_dm_is_data_exchange_allowed() - bypass state check
 *    - nci_snd_data() - bypass NCI state check
 *    - Or use HAL write directly
 ******************************************************************************/

/*******************************************************************************
 * FRIDA HOOK TARGETS
 * 
 * Symbol names in libnfc-nci.so:
 * 
 * Functions:
 * - _ZN3nfa2dm21is_data_exchange_allowedEv (nfa_dm_is_data_exchange_allowed)
 * - _Z12nci_snd_datahP6BT_HDR (nci_snd_data)
 * - _ZN3nfc5ncif9send_dataEP6BT_HDRh (nfc_ncif_send_data)
 * 
 * Global variables:
 * - nfa_dm_cb (mangled name varies)
 * - nfc_cb (mangled name varies)
 * 
 * HAL write:
 * - nfc_hal_entry->write
 ******************************************************************************/

#endif /* NFA_DM_INT_H */
