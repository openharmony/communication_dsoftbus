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

#include <stdint.h>
#include "ohos_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_NAME_LEN 16
#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16

typedef uint8_t BT_UUIDL[BT_UUID_LEN];
typedef uint8_t BT_ADDR[BT_ADDR_LEN];

enum SppEventType {
    SPP_EVENT_TYPE_ACCEPT = 1,
    SPP_EVENT_TYPE_DISCONNECTED,
    SPP_EVENT_TYPE_CONNECTED,
    SPP_EVENT_TYPE_CONGEST
};

typedef struct {
    // 0:read, 1:accept, 2:disconnected, 3:congest, 4:connteced
    void (*OnEvent)(int32_t type, int32_t socketFd, int32_t value);
    void (*OnDataReceived)(int32_t socketFd, const char* buf, int32_t len);
} SppSocketEventCallback;

typedef struct {
    BT_UUIDL uuid;
    BT_ADDR mac;
    char name[BR_NAME_LEN];
} BluetoothRemoteDevice;

typedef struct tagSppSocketDriver {
    void (*Init)(const struct tagSppSocketDriver* this_p);
    int32_t (*OpenSppServer)(const BT_ADDR mac, const BT_UUIDL uuid, int32_t isSecure);
    int32_t (*OpenSppClient)(const BT_ADDR mac, const BT_UUIDL uuid, int32_t isSecure);
    int32_t (*CloseClient)(int32_t clientFd);
    void   (*CloseServer)(int32_t serverFd);
    int32_t (*Connect)(int32_t clientFd, const SppSocketEventCallback* callback);
    int32_t (*GetRemoteDeviceInfo)(int32_t clientFd, const BluetoothRemoteDevice* device);
    int32_t (*IsConnected)(int32_t clientFd);
    int32_t (*Accept)(int32_t serverFd, const SppSocketEventCallback* callback);
    int32_t (*Write)(int32_t clientFd, const char* buf, const int32_t length);
} SppSocketDriver;

SppSocketDriver* InitSppSocketDriver();

#ifdef __cplusplus
}
#endif
#endif /* WRAPPER_BR_INTERFACE_H */