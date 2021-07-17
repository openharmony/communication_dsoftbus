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

#ifndef SOFTBUS_CONNECTION_INFO_H
#define SOFTBUS_CONNECTION_INFO_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    LINK_TYPE_BR = 1,
    LINK_TYPE_WIFI_WLAN,
    LINK_TYPE_WIFI_P2P,
    LINK_TYPE_BLE,
    LINK_TYPE_LOOPBACK,
} LinkType;

/* Peer information */
typedef struct {
    char deviceId[DEVICE_ID_SIZE_MAX];
    char deviceIp[IP_LEN];
    int devicePort;
    int sessionPort;
} TcpDeviceInfo;

typedef struct {
    bool isUnique;
    char peerIp[IP_LEN];
    char deviceId[DEVICE_ID_SIZE_MAX];
    LinkType linkType;
    TcpDeviceInfo deviceInfo;
} ConnectionInfo;

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_CONNECTION_INFO_H
