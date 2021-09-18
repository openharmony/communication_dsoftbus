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

#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16

#define BLE_DISABLE 0
#define BLE_ENABLE 1

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
    SOFTBUS_BT_STATE_TURNING_ON = 0x0,
    SOFTBUS_BT_STATE_TURN_ON,
    SOFTBUS_BT_STATE_TURNING_OFF,
    SOFTBUS_BT_STATE_TURN_OFF
} SoftBusBtStackState;

typedef struct {
    unsigned char addr[BT_ADDR_LEN];
} SoftBusBtAddr;

typedef struct {
    unsigned char uuidLen;
    char *uuid;
} SoftBusBtUuid;

typedef struct {
    void (*OnBtStateChanged)(int listenerId, int state);
} SoftBusBtStateListener;

int SoftBusEnableBt(void);

int SoftBusDisableBt(void);

int SoftBusGetBtState(void);

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac);

int SoftBusGetBtName(unsigned char *name, unsigned int *len);

int SoftBusSetBtName(const char *name);

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener);

int SoftBusRemoveBtStateListener(int listenerId);

#endif