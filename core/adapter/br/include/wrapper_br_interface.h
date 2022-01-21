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

#ifndef WRAPPER_BR_INTERFACE_H
#define WRAPPER_BR_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_adapter_bt_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_NAME_LEN 16
#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16

typedef uint8_t BT_UUIDL[BT_UUID_LEN];
typedef uint8_t BT_ADDR[BT_ADDR_LEN];

#define BR_READ_SOCKET_CLOSED 0
#define BR_READ_FAILED (-1)

typedef struct {
    BT_UUIDL uuid;
    BT_ADDR mac;
    char name[BR_NAME_LEN];
} BluetoothRemoteDevice;

typedef struct tagSppSocketDriver {
    void (*Init)(const struct tagSppSocketDriver* this_p);
    int32_t (*OpenSppServer)(const char *name, int32_t nameLen, const char *uuid, int32_t isSecure);
    void (*CloseSppServer)(int32_t serverFd);
    int32_t (*Connect)(const char *uuid, const BT_ADDR mac);
    int32_t (*DisConnect)(int32_t clientFd);
    bool (*IsConnected)(int32_t clientFd);
    int32_t (*Accept)(int32_t serverFd);
    int32_t (*Write)(int32_t clientFd, const char* buf, const int32_t length);
    int32_t (*Read)(int32_t clientFd, char* buf, const int32_t length);
    int32_t (*GetRemoteDeviceInfo)(int32_t clientFd, const BluetoothRemoteDevice* device);
} SppSocketDriver;

SppSocketDriver* InitSppSocketDriver();
int32_t SppGattsRegisterHalCallback(const SoftBusBtStateListener *lister);

#ifdef __cplusplus
}
#endif
#endif /* WRAPPER_BR_INTERFACE_H */