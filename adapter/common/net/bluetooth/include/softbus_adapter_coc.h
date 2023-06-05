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

#ifndef SOFTBUS_ADAPTER_COC_H
#define SOFTBUS_ADAPTER_COC_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_adapter_bt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t BT_ADDR[BT_ADDR_LEN];

#define COC_READ_SOCKET_CLOSED 0
#define COC_READ_FAILED (-1)

typedef struct {
    int32_t serverFd;
    int32_t psm;
} CocPsm;

typedef struct {
    int32_t psm;
    BT_ADDR mac;
} BluetoothRemoteDevice;

typedef enum {
    SOFTBUS_COC_PRIORITY_BALANCED = 0x0,
    SOFTBUS_COC_PRIORITY_HIGH,
    SOFTBUS_COC_PRIORITY_LOW_POWER,
} SoftbusBleCocPriority;

typedef struct {
    int32_t (*OpenCocServer)(CocPsm *cocPsm);
    void (*CloseCocServer)(int32_t serverFd);
    int32_t (*CreateCocClient)();
    void (*DestroyCocClient)(int32_t clientFd);
    int32_t (*Connect)(int32_t clientFd, const BT_ADDR mac, int32_t psm);
    bool (*CancelConnect)(int32_t clientFd);
    int32_t (*DisConnect)(int32_t fd);
    bool (*IsConnected)(int32_t fd);
    int32_t (*Accept)(int32_t serverFd);
    int32_t (*Write)(int32_t fd, const uint8_t *buf, const int32_t length);
    int32_t (*Read)(int32_t fd, uint8_t *buf, const int32_t length);
    bool (*EnableFastCocConnection)(int32_t clientFd);
    bool (*SetCocPreferredPhy)(int32_t clientFd, int32_t txPhy, int32_t rxPhy, int32_t phyOptions);
    bool (*UpdateCocConnectionParams)(int32_t clientFd, int32_t priority);
    int32_t (*GetRemoteDeviceInfo)(int32_t fd, BluetoothRemoteDevice *device);
} CocSocketDriver;

CocSocketDriver *InitCocSocketDriver();

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_COC_H */