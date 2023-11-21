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

#ifndef CONN_EVENT_FORM_H
#define CONN_EVENT_FORM_H

#include <stdint.h>

typedef enum {
    SCENE_CONNECT = 1,
} ConnEventScene;

typedef enum {
    STAGE_CONNECT_START = 1,
    STAGE_CONNECT_INVOKE_PROTOCOL = 2,
    STAGE_CONNECT_END = 3,
} ConnEventConnectStage;

typedef struct {
    int32_t requestId;       // REQ_ID
    int32_t linkType;        // LINK_TYPE
    int32_t expectRole;      // EXPECT_ROLE
    int32_t authType;        // AUTH_TYPE
    int32_t authId;          // AUTH_ID
    int32_t connectionId;    // CONN_ID
    int32_t peerNetworkId;   // PEER_NETID
    int32_t rssi;            // RSSI
    int32_t load;            // CHLOAD
    int32_t frequency;       // FREQ
    int32_t costTime;        // CONN_COST_TIME -> COST_TIME
    int32_t result;          // STAGE_RES
    int32_t errcode;         // ERROR_CODE
    const char *peerBrMac;   // PEER_BR_MAC
    const char *peerBleMac;  // PEER_BLE_MAC
    const char *peerWifiMac; // PEER_WIFI_MAC
    const char *peerIp;      // PEER_IP
    const char *peerPort;    // PEER_PORT
} ConnEventExtra;

#endif // CONN_EVENT_FORM_H
