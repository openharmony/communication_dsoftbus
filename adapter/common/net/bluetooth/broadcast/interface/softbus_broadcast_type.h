/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file softbus_broadcast_type.h
 * @brief Declare constants for the softbus broadcast.
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_TYPE_H
#define SOFTBUS_BROADCAST_TYPE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines mac address length.
 *
 * @since 4.1
 * @version 1.0
 */
#define BC_ADDR_MAC_LEN 6

// Bluetooth scan duty cycle, unit: ms
#define SOFTBUS_BC_SCAN_INTERVAL_P2 3000
#define SOFTBUS_BC_SCAN_INTERVAL_P10 300
#define SOFTBUS_BC_SCAN_INTERVAL_P25 240
#define SOFTBUS_BC_SCAN_INTERVAL_P100 1000
#define SOFTBUS_BC_SCAN_WINDOW_P2 60
#define SOFTBUS_BC_SCAN_WINDOW_P10 30
#define SOFTBUS_BC_SCAN_WINDOW_P25 60
#define SOFTBUS_BC_SCAN_WINDOW_P100 1000

/**
 * @brief Defines the maxium lenght of irk information.
 *
 * @since 4.1
 * @version 1.0
 */
#define BC_IRK_LEN   16

/**
 * @brief Defines the maxium lenght of udid hash information.
 *
 * @since 4.1
 * @version 1.0
 */
#define BC_UDID_HASH_LEN 32

/**
 * @brief Defines the length of local name, the maximum length of complete local name is 30 bytes.
 *
 * @since 4.1
 * @version 1.0
 */
#define BC_LOCAL_NAME_LEN_MAX 30

/**
 * @brief Defines the broadcast service type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SRV_TYPE_HB, // The service type is heart beat.
    SRV_TYPE_CONN, // The service type is connection.
    SRV_TYPE_TRANS_MSG, // The service type is transmission message.
    SRV_TYPE_DIS, // The service type is distrubite discovery.
    SRV_TYPE_SHARE, // The service type is share discovery.
    SRV_TYPE_APPROACH, // The service type is approach discovery.
    SRV_TYPE_SH, // The service type is sensorhub.
    SRV_TYPE_FAST_OFFLINE, // The service type is fast offline.
    SRV_TYPE_BUTT,
} BaseServiceType;

/**
 * @brief Defines the broadcast status type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_STATUS_SUCCESS = 0x00,
    SOFTBUS_BC_STATUS_FAIL,
    SOFTBUS_BC_STATUS_NOT_READY,
    SOFTBUS_BC_STATUS_NOMEM,
    SOFTBUS_BC_STATUS_BUSY,
    SOFTBUS_BC_STATUS_DONE,
    SOFTBUS_BC_STATUS_UNSUPPORTED,
    SOFTBUS_BC_STATUS_PARM_INVALID,
    SOFTBUS_BC_STATUS_UNHANDLED,
    SOFTBUS_BC_STATUS_AUTH_FAILURE,
    SOFTBUS_BC_STATUS_RMT_DEV_DOWN,
    SOFTBUS_BC_STATUS_AUTH_REJECTED
} SoftBusBcStatus;

/**
 * @brief Defines the broadcast event type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_EVT_NON_CONNECTABLE_NON_SCANNABLE = 0x00,
    SOFTBUS_BC_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED = 0x04,
    SOFTBUS_BC_EVT_CONNECTABLE = 0x01,
    SOFTBUS_BC_EVT_CONNECTABLE_DIRECTED = 0x05,
    SOFTBUS_BC_EVT_SCANNABLE = 0x02,
    SOFTBUS_BC_EVT_SCANNABLE_DIRECTED = 0x06,
    SOFTBUS_BC_EVT_LEGACY_NON_CONNECTABLE = 0x10,
    SOFTBUS_BC_EVT_LEGACY_SCANNABLE = 0x12,
    SOFTBUS_BC_EVT_LEGACY_CONNECTABLE = 0x13,
    SOFTBUS_BC_EVT_LEGACY_CONNECTABLE_DIRECTED = 0x15,
    SOFTBUS_BC_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN = 0x1A,
    SOFTBUS_BC_EVT_LEGACY_SCAN_RSP_TO_ADV = 0x1B
} SoftBusBcScanResultEvtType;

/**
 * @brief Defines the broadcast mac type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS = 0x00,
    SOFTBUS_BC_RANDOM_DEVICE_ADDRESS = 0x01,
    SOFTBUS_BC_PUBLIC_IDENTITY_ADDRESS = 0x02,
    SOFTBUS_BC_RANDOM_STATIC_IDENTITY_ADDRESS = 0x03,
    SOFTBUS_BC_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS = 0xFE,
    SOFTBUS_BC_NO_ADDRESS = 0xFF,
} SoftBusBcScanResultAddrType;

/**
 * @brief Defines the scan type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_SCAN_TYPE_PASSIVE = 0x00,
    SOFTBUS_BC_SCAN_TYPE_ACTIVE,
} SoftBusBcScanType;

/**
 * @brief Defines the scan physics type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_SCAN_PHY_NO_PACKET = 0x00,
    SOFTBUS_BC_SCAN_PHY_1M = 0x01,
    SOFTBUS_BC_SCAN_PHY_2M = 0x02,
    SOFTBUS_BC_SCAN_PHY_CODED = 0x03
} SoftBusBcScanResultPhyType;

/**
 * @brief Defines the scan filter policy type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL = 0x00,
    SOFTBUS_BC_SCAN_FILTER_POLICY_ONLY_WHITE_LIST,
    SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL_AND_RPA,
    SOFTBUS_BC_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA
} SoftBusBcScanFilterPolicy;

/**
 * @brief Defines the broadcast adv type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_ADV_IND = 0x00,
    SOFTBUS_BC_ADV_DIRECT_IND_HIGH = 0x01,
    SOFTBUS_BC_ADV_SCAN_IND = 0x02,
    SOFTBUS_BC_ADV_NONCONN_IND = 0x03,
    SOFTBUS_BC_ADV_DIRECT_IND_LOW  = 0x04,
} SoftBusBcAdvType;

/**
 * @brief Defines the broadcast adv filter and allow scan type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY = 0x00,
    SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY = 0x01,
    SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST = 0x02,
    SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST = 0x03,
} SoftBusBcAdvFilter;

/**
 * @brief Defines the broadcast data status.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_DATA_COMPLETE = 0x00,
    SOFTBUS_BC_DATA_INCOMPLETE_MORE_TO_COME = 0x01,
    SOFTBUS_BC_DATA_INCOMPLETE_TRUNCATED = 0x02,
} SoftBusBcScanResultDataStatus;

/**
 * @brief Defines the switch status of the ble and br.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    SOFTBUS_BC_BT_STATE_TURNING_ON = 0x0,
    SOFTBUS_BC_BT_STATE_TURN_ON,
    SOFTBUS_BC_BT_STATE_TURNING_OFF,
    SOFTBUS_BC_BT_STATE_TURN_OFF,
    SOFTBUS_BC_BR_STATE_TURNING_ON,
    SOFTBUS_BC_BR_STATE_TURN_ON,
    SOFTBUS_BC_BR_STATE_TURNING_OFF,
    SOFTBUS_BC_BR_STATE_TURN_OFF
} SoftBusBcStackState;

/**
 * @brief Defines the broadcast service type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    BC_DATA_TYPE_SERVICE, // The broadcast data type is service data.
    BC_DATA_TYPE_MANUFACTURER, // The broadcast data type is manufacturer data.
    BC_DATA_TYPE_BUTT,
} BroadcastDataType;

/**
 * @brief Defines the broadcast data information.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    BroadcastDataType type; // broadcast data type {@link BroadcastDataType}.
    uint16_t id; // broadcast data id, uuid or company id.
    uint16_t payloadLen;
    uint8_t *payload; // if pointer defines rsp payload, pointer may be null
} BroadcastPayload;

/**
 * @brief Defines the broadcast packet.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    BroadcastPayload bcData;
    BroadcastPayload rspData;
    // By default, the flag behavior is supported. If the flag behavior is not supported, the value must be set to false
    bool isSupportFlag;
    uint8_t flag;
} BroadcastPacket;

/**
 * @brief Defines mac address information
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t addr[BC_ADDR_MAC_LEN];
} BcMacAddr;

/**
 * @brief Defines uuid information
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t uuidLen;
    int8_t *uuid;
} BroadcastUuid;

/**
 * @brief Defines the device information returned by <b>SoftbusBroadcastCallback</b>.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t eventType;
    uint8_t dataStatus;
    uint8_t primaryPhy;
    uint8_t secondaryPhy;
    uint8_t advSid;
    int8_t txPower;
    int8_t rssi;
    uint8_t addrType;
    BcMacAddr addr;
    int8_t *deviceName;
    uint8_t localName[BC_LOCAL_NAME_LEN_MAX];
    BroadcastPacket packet;
} BroadcastReportInfo;

/**
 * @brief Defines the broadcast parameters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    int32_t minInterval;
    int32_t maxInterval;
    uint8_t advType;
    uint8_t advFilterPolicy;
    uint8_t ownAddrType;
    uint8_t peerAddrType;
    BcMacAddr peerAddr;
    int32_t channelMap;
    int32_t duration;
    int8_t txPower;
    bool isSupportRpa;
    uint8_t ownIrk[BC_IRK_LEN];
    uint8_t ownUdidHash[BC_UDID_HASH_LEN];
} BroadcastParam;

/**
 * @brief Defines broadcast scan filters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    int8_t *address;
    int8_t *deviceName;
    uint16_t serviceUuid;
    uint32_t serviceDataLength;
    uint8_t *serviceData;
    uint8_t *serviceDataMask;
    uint16_t manufactureId;
    uint32_t manufactureDataLength;
    uint8_t *manufactureData;
    uint8_t *manufactureDataMask;
} BcScanFilter;

/**
 * @brief Defines broadcast scan parameters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint16_t scanInterval;
    uint16_t scanWindow;
    uint8_t scanType;
    uint8_t scanPhy;
    uint8_t scanFilterPolicy;
} BcScanParams;

/**
 * @brief Defines broadcast parameters of the low power chip.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    int32_t bcHandle;
    BroadcastPacket packet;
    BroadcastParam bcParam;
} LpBroadcastParam;

/**
 * @brief Defines scan parameters of the low power chip.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    BcScanParams scanParam;
    int32_t listenerId;
} LpScanParam;

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_TYPE_H */
