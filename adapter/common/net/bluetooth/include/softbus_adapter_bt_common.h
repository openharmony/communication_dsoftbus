/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_BT_COMMON_H
#define SOFTBUS_ADAPTER_BT_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_type_def.h"
#include "softbus_adapter_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16

#define MAC_FIRST_INDEX 0
#define MAC_ONE_INDEX 1
#define MAC_FIVE_INDEX 5
#define BLE_WRITE_TIMEOUT_IN_MS 500

typedef enum {
    BLE_DISABLE = 0,
    BLE_ENABLE = 1,
    BLE_STATE_BUTT,
} SoftBusBleState;

typedef enum {
    BR_DISABLE = 0,
    BR_ENABLE = 1,
    BR_STATE_BUTT,
} SoftBusBrState;

typedef enum {
    SOFTBUS_BT_STATUS_SUCCESS = 0x00,
    SOFTBUS_BT_STATUS_FAIL,
    SOFTBUS_BT_STATUS_NOT_READY,
    SOFTBUS_BT_STATUS_NOMEM,
    SOFTBUS_BT_STATUS_BUSY,
    SOFTBUS_BT_STATUS_DONE,
    SOFTBUS_BT_STATUS_UNSUPPORTED,
    SOFTBUS_BT_STATUS_PARM_INVALID,
    SOFTBUS_BT_STATUS_UNHANDLED,
    SOFTBUS_BT_STATUS_AUTH_FAILURE,
    SOFTBUS_BT_STATUS_RMT_DEV_DOWN,
    SOFTBUS_BT_STATUS_AUTH_REJECTED
} SoftBusBtStatus;

typedef enum {
    SOFTBUS_BLE_STATE_TURNING_ON = 0x0,
    SOFTBUS_BLE_STATE_TURN_ON,
    SOFTBUS_BLE_STATE_TURNING_OFF,
    SOFTBUS_BLE_STATE_TURN_OFF,
    SOFTBUS_BR_STATE_TURNING_ON,
    SOFTBUS_BR_STATE_TURN_ON,
    SOFTBUS_BR_STATE_TURNING_OFF,
    SOFTBUS_BR_STATE_TURN_OFF
} SoftBusBtStackState;

typedef enum {
    SOFTBUS_ACL_STATE_CONNECTED = 0x0,
    SOFTBUS_ACL_STATE_DISCONNECTED,
    SOFTBUS_ACL_STATE_LE_CONNECTED,
    SOFTBUS_ACL_STATE_LE_DISCONNECTED,
} SoftBusAclState;

typedef struct {
    unsigned char addr[BT_ADDR_LEN];
} SoftBusBtAddr;

typedef struct {
    unsigned char uuidLen;
    char *uuid;
} SoftBusBtUuid;

typedef enum {
    SOFTBUS_BT_CONNECT = 0x01,
    SOFTBUS_BT_DISCONNECT = 0x03
} SoftBusBtConnectState;

typedef struct {
    unsigned short advLength;
    uint8_t *advData;
    unsigned short scanRspLength;
    uint8_t *scanRspData;
} SoftBusBleAdvData;

typedef struct {
    void (*OnBtStateChanged)(int listenerId, int state);
    void (*OnBtAclStateChanged)(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState, int32_t hciReason);
} SoftBusBtStateListener;

typedef struct {
    bool isWriteAvailable;
    SoftBusCond sendCond;
    SoftBusMutex sendCondLock;
} SoftBusBleSendSignal;

int SoftBusEnableBt(void);

int SoftBusDisableBt(void);

int SoftBusGetBtState(void);

int SoftBusGetBrState(void);

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac);

int SoftBusGetBtName(unsigned char *name, unsigned int *len);

int SoftBusSetBtName(const char *name);

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener);

int SoftBusRemoveBtStateListener(int listenerId);

void SoftBusComputeWaitBleSendDataTime(uint32_t waitMillis, SoftBusSysTime *outtime);

int SoftBusBtInit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_BT_COMMON_H */