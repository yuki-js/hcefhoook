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
 * REFERENCE FILE: AOSP system/nfc HAL Interface
 * This file shows the HAL layer interface for NFC communication.
 * Critical for understanding the lowest level access points.
 */

#ifndef NFC_HAL_API_H
#define NFC_HAL_API_H

#include <stdint.h>

/*******************************************************************************
 * HAL INTERFACE OVERVIEW
 * 
 * The HAL (Hardware Abstraction Layer) is the lowest software layer
 * before the NFC Controller (NFCC) firmware.
 * 
 * Data flow:
 * Application -> NFA -> NCI -> HAL -> NFCC Firmware -> RF Frontend
 * 
 * For SENSF_RES injection, intercepting at HAL level provides:
 * - Bypass of all software state checks
 * - Direct packet transmission to NFCC
 * - But NFCC firmware may still reject packets based on its state
 ******************************************************************************/

/*******************************************************************************
 * HAL CALLBACK TYPES
 ******************************************************************************/
typedef void(tHAL_NFC_STATUS_CBACK)(uint8_t event, uint8_t status);
typedef void(tHAL_NFC_CBACK)(uint8_t event, uint16_t data_len, uint8_t* p_data);
typedef void(tHAL_NFC_DATA_CBACK)(uint16_t data_len, uint8_t* p_data);

/*******************************************************************************
 * HAL EVENTS
 ******************************************************************************/
#define HAL_NFC_OPEN_CPLT_EVT           0x00
#define HAL_NFC_CLOSE_CPLT_EVT          0x01
#define HAL_NFC_POST_INIT_CPLT_EVT      0x02
#define HAL_NFC_PRE_DISCOVER_CPLT_EVT   0x03
#define HAL_NFC_REQUEST_CONTROL_EVT     0x04
#define HAL_NFC_RELEASE_CONTROL_EVT     0x05
#define HAL_NFC_ERROR_EVT               0x06

/*******************************************************************************
 * HAL FUNCTION POINTERS
 * 
 * These are the key functions implemented by the HAL module.
 ******************************************************************************/
typedef struct {
    /*
     * HAL_NfcOpen
     * Opens the NFC stack and initializes hardware.
     */
    void (*open)(tHAL_NFC_CBACK* p_hal_cback, 
                 tHAL_NFC_DATA_CBACK* p_data_cback);
    
    /*
     * HAL_NfcClose
     * Closes the NFC stack.
     */
    void (*close)(void);
    
    /*
     * HAL_NfcCoreInitialized
     * Called after core initialization is complete.
     */
    void (*core_initialized)(uint16_t data_len, uint8_t* p_core_init_rsp);
    
    /*
     * HAL_NfcWrite
     * 
     * CRITICAL FUNCTION FOR INJECTION:
     * This function writes data directly to the NFCC.
     * It bypasses NCI and NFA layer checks.
     * 
     * However, the NFCC firmware validates packets and may reject
     * malformed or unexpected packets.
     * 
     * Parameters:
     *   data_len: Length of data to write
     *   p_data: Pointer to NCI packet (including header)
     * 
     * Returns:
     *   Number of bytes written
     */
    int (*write)(uint16_t data_len, uint8_t* p_data);
    
    /*
     * HAL_NfcPreDiscover
     * Called before RF discovery starts.
     */
    int (*prediscover)(void);
    
    /*
     * HAL_NfcControlGranted
     * Called when control of NFC is granted (for power management).
     */
    void (*control_granted)(void);
    
    /*
     * HAL_NfcPowerCycle
     * Power cycles the NFC controller.
     */
    void (*power_cycle)(void);
    
    /*
     * HAL_NfcGetMaxNfcee
     * Returns maximum number of NFCEEs supported.
     */
    int (*get_max_nfcee)(void);
    
} tHAL_NFC_ENTRY;

/*******************************************************************************
 * HAL WRITE IMPLEMENTATION REFERENCE
 * 
 * This is how a typical HAL write implementation looks.
 * The write function sends NCI packets directly to NFCC.
 ******************************************************************************/
/*
int hal_nfc_write(uint16_t data_len, uint8_t* p_data) {
    int ret;
    
    // Write to NFC transport (I2C/SPI/UART)
    ret = transport_write(nfc_dev_node, p_data, data_len);
    
    if (ret < 0) {
        LOG(ERROR) << "HAL write failed: " << ret;
        return 0;
    }
    
    return ret;
}
*/

/*******************************************************************************
 * DIRECT HAL ACCESS FOR SENSF_RES INJECTION
 * 
 * RESEARCH: BYPASS STRATEGY
 * 
 * If we can obtain a pointer to the HAL write function, we can:
 * 1. Construct a raw NCI data packet containing SENSF_RES
 * 2. Call HAL write directly, bypassing NCI/NFA state checks
 * 
 * Method to obtain HAL pointer:
 * - The HAL entry point is stored in nfc_hal_entry (global)
 * - Can be accessed via dlsym() or memory inspection
 * - Frida can easily hook and use this function
 * 
 * Packet construction:
 * - NCI Data packet header: [conn_id][credits][len]
 * - Payload: SENSF_RES frame
 * 
 * However: NFCC firmware state machine may still reject the packet
 * if it doesn't expect data in current RF state.
 ******************************************************************************/

/*******************************************************************************
 * EXAMPLE: Direct SENSF_RES injection via HAL
 ******************************************************************************/
/*
void inject_sensf_res_via_hal(uint8_t* idm, uint8_t* pmm) {
    uint8_t nci_pkt[32];
    uint8_t* p = nci_pkt;
    
    // NCI Data Header
    *p++ = NCI_STATIC_RF_CONN_ID;  // conn_id = 0
    *p++ = 0;                       // credits
    *p++ = 17;                      // length (SENSF_RES len)
    
    // SENSF_RES payload
    *p++ = 17;      // Length byte
    *p++ = 0x01;    // Response code
    memcpy(p, idm, 8); p += 8;
    memcpy(p, pmm, 8); p += 8;
    
    // Direct HAL write
    nfc_hal_entry->write(p - nci_pkt, nci_pkt);
}
*/

/*******************************************************************************
 * HAL GLOBAL REFERENCE
 * 
 * In libnfc-nci.so, the HAL entry point is typically stored in:
 * - nfc_hal_entry (pointer to tHAL_NFC_ENTRY)
 * - Can be found by searching for symbol or pattern matching
 ******************************************************************************/
extern tHAL_NFC_ENTRY* nfc_hal_entry;

#endif /* NFC_HAL_API_H */
