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
 * REFERENCE FILE: AOSP system/nfc NCI Definitions Header
 * This file contains critical constants and structures for NCI protocol.
 */

#ifndef NCI_DEFS_H
#define NCI_DEFS_H

#include <stdint.h>

/*******************************************************************************
 * NCI MESSAGE TYPES (MT)
 ******************************************************************************/
#define NCI_MT_DATA     0x00  /* Data packet */
#define NCI_MT_CMD      0x01  /* Command packet */
#define NCI_MT_RSP      0x02  /* Response packet */
#define NCI_MT_NTF      0x03  /* Notification packet */

/*******************************************************************************
 * NCI GROUP IDS (GID)
 ******************************************************************************/
#define NCI_GID_CORE        0x00  /* Core group */
#define NCI_GID_RF_MANAGE   0x01  /* RF Management group */
#define NCI_GID_EE_MANAGE   0x02  /* NFCEE Management group */
#define NCI_GID_PROP        0x0F  /* Vendor-specific/Proprietary group */

/*******************************************************************************
 * NCI CORE MESSAGE OPCODES (OID)
 ******************************************************************************/
#define NCI_MSG_CORE_RESET          0x00
#define NCI_MSG_CORE_INIT           0x01
#define NCI_MSG_CORE_SET_CONFIG     0x02
#define NCI_MSG_CORE_GET_CONFIG     0x03
#define NCI_MSG_CORE_CONN_CREATE    0x04
#define NCI_MSG_CORE_CONN_CLOSE     0x05
#define NCI_MSG_CORE_CONN_CREDITS   0x06
#define NCI_MSG_CORE_GEN_ERR_STATUS 0x07
#define NCI_MSG_CORE_INTF_ERR_STATUS 0x08

/*******************************************************************************
 * NCI RF MANAGEMENT MESSAGE OPCODES (OID)
 ******************************************************************************/
#define NCI_MSG_RF_DISCOVER_MAP     0x00
#define NCI_MSG_RF_SET_ROUTING      0x01
#define NCI_MSG_RF_GET_ROUTING      0x02
#define NCI_MSG_RF_DISCOVER         0x03
#define NCI_MSG_RF_DISCOVER_SELECT  0x04
#define NCI_MSG_RF_INTF_ACTIVATED   0x05
#define NCI_MSG_RF_DEACTIVATE       0x06
#define NCI_MSG_RF_FIELD_INFO       0x07
#define NCI_MSG_RF_T3T_POLLING      0x08
#define NCI_MSG_RF_NFCEE_ACTION     0x09
#define NCI_MSG_RF_NFCEE_DISCOVERY_REQ 0x0A
#define NCI_MSG_RF_PARAMETER_UPDATE 0x0B

/*******************************************************************************
 * NCI NOTIFICATION OPCODES (CRITICAL FOR OBSERVE MODE)
 ******************************************************************************/
#define NCI_MSG_RF_DISCOVER_NTF         0x03
#define NCI_MSG_RF_INTF_ACTIVATED_NTF   0x05
#define NCI_MSG_RF_DEACTIVATE_NTF       0x06
#define NCI_MSG_RF_FIELD_INFO_NTF       0x07

/* Android Vendor Extension for Observe Mode */
#define NCI_ANDROID_POLLING_FRAME_NTF   0x40  /* Vendor-specific OID */

/*******************************************************************************
 * NCI DISCOVERY TYPES
 ******************************************************************************/
#define NCI_DISCOVERY_TYPE_POLL_A        0x00
#define NCI_DISCOVERY_TYPE_POLL_B        0x01
#define NCI_DISCOVERY_TYPE_POLL_F        0x02
#define NCI_DISCOVERY_TYPE_POLL_V        0x06
#define NCI_DISCOVERY_TYPE_LISTEN_A      0x80
#define NCI_DISCOVERY_TYPE_LISTEN_B      0x81
#define NCI_DISCOVERY_TYPE_LISTEN_F      0x82  /* FeliCa Listen Mode */

/*******************************************************************************
 * NCI RF TECHNOLOGY TYPES
 ******************************************************************************/
#define NCI_RF_TECHNOLOGY_A     0x00
#define NCI_RF_TECHNOLOGY_B     0x01
#define NCI_RF_TECHNOLOGY_F     0x02  /* FeliCa (212/424 kbps) */
#define NCI_RF_TECHNOLOGY_V     0x06

/*******************************************************************************
 * NCI CONFIGURATION PARAMETERS (CRITICAL FOR OBSERVE MODE)
 ******************************************************************************/
/* Common parameters */
#define NCI_PARAM_ID_TOTAL_DURATION     0x00
#define NCI_PARAM_ID_CON_DISCOVERY_PARAM 0x02

/* Listen A parameters */
#define NCI_PARAM_ID_LA_BIT_FRAME_SDD   0x30
#define NCI_PARAM_ID_LA_PLATFORM_CONFIG 0x31
#define NCI_PARAM_ID_LA_SEL_INFO        0x32
#define NCI_PARAM_ID_LA_NFCID1          0x33

/* Listen F parameters (CRITICAL FOR NFC-F) */
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_1  0x40
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_2  0x41
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_3  0x42
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_4  0x43
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_5  0x44
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_6  0x45
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_7  0x46
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_8  0x47
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_9  0x48
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_10 0x49
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_11 0x4A
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_12 0x4B
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_13 0x4C
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_14 0x4D
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_15 0x4E
#define NCI_PARAM_ID_LF_T3T_IDENTIFIERS_16 0x4F
#define NCI_PARAM_ID_LF_T3T_PMM             0x51
#define NCI_PARAM_ID_LF_T3T_MAX             0x52
#define NCI_PARAM_ID_LF_T3T_FLAGS           0x53  /* CRITICAL: Auto-response control */
#define NCI_PARAM_ID_LF_PROTOCOL_TYPE       0x50
#define NCI_PARAM_ID_LF_CON_BITR_F          0x54

/* Android vendor-specific parameters */
#define NCI_PARAM_ID_ANDROID_OBSERVE_MODE   0xF0  /* Enable observe mode */

/*******************************************************************************
 * T3T (FeliCa) MESSAGE CODES
 ******************************************************************************/
#define T3T_MSG_CMD_CODE_SENSF_REQ  0x00  /* SENSF Request */
#define T3T_MSG_RSP_CODE_SENSF      0x01  /* SENSF Response */

/*******************************************************************************
 * NCI STATUS CODES
 ******************************************************************************/
typedef uint8_t tNCI_STATUS;

#define NCI_STATUS_OK                   0x00
#define NCI_STATUS_REJECTED             0x01
#define NCI_STATUS_RF_FRAME_CORRUPTED   0x02
#define NCI_STATUS_FAILED               0x03
#define NCI_STATUS_NOT_INITIALIZED      0x04
#define NCI_STATUS_SYNTAX_ERROR         0x05
#define NCI_STATUS_SEMANTIC_ERROR       0x06
#define NCI_STATUS_INVALID_PARAM        0x09
#define NCI_STATUS_MSG_SIZE_TOO_BIG     0x0A

/*******************************************************************************
 * NCI HEADER SIZES
 ******************************************************************************/
#define NCI_MSG_HDR_SIZE        3  /* MT/PBF/GID + OID/LEN + LEN */
#define NCI_DATA_HDR_SIZE       3  /* conn_id + credits + len */
#define NCI_MSG_OFFSET_SIZE     1

/*******************************************************************************
 * NCI CONNECTION IDS
 ******************************************************************************/
#define NCI_STATIC_RF_CONN_ID   0x00  /* Static connection for RF */
#define NCI_NFCEE_CONN_ID_BASE  0x02  /* NFCEE connections start here */

/*******************************************************************************
 * STRUCTURES
 ******************************************************************************/

/* Discovery parameters */
typedef struct {
    uint8_t type;       /* NCI_DISCOVERY_TYPE_* */
    uint8_t frequency;  /* Discovery frequency */
} tNCI_DISCOVER_PARAMS;

/* RF Interface configuration */
typedef struct {
    uint8_t intf_type;      /* Interface type */
    uint8_t intf_mode;      /* Interface mode */
    uint8_t num_credits;    /* Number of credits */
} tNCI_INTF_CONFIG;

/*******************************************************************************
 * NCI PACKET BUILDING MACROS
 ******************************************************************************/
#define NCI_MSG_BLD_HDR0(p, mt, gid) \
    *(p)++ = (uint8_t)(((mt) << 5) | (gid));

#define NCI_MSG_BLD_HDR1(p, oid) \
    *(p)++ = (uint8_t)(oid);

#define NCI_DATA_BLD_HDR(p, conn_id, len) \
    *(p)++ = (uint8_t)(conn_id); \
    *(p)++ = (uint8_t)(0); \
    *(p)++ = (uint8_t)(len);

#define NCI_MSG_PRS_HDR0(p, op) \
    *(op) = (*(p) & 0x3F); \
    (p)++;

/*******************************************************************************
 * STREAM MANIPULATION MACROS
 ******************************************************************************/
#define UINT8_TO_STREAM(p, u8) \
    { *(p)++ = (uint8_t)(u8); }

#define UINT16_TO_STREAM(p, u16) \
    { *(p)++ = (uint8_t)(u16); *(p)++ = (uint8_t)((u16) >> 8); }

#define ARRAY_TO_STREAM(p, a, len) \
    { memcpy((p), (a), (len)); (p) += (len); }

#define STREAM_TO_UINT8(u8, p) \
    { (u8) = *(p)++; }

#define STREAM_TO_UINT16(u16, p) \
    { (u16) = *(p) + (*(p+1) << 8); (p) += 2; }

#endif /* NCI_DEFS_H */
