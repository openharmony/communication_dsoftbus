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

#ifndef TRANS_EVENT_ATOM_FORM_H
#define TRANS_EVENT_ATOM_FORM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SCENE_OPEN_CHANNEL = 1,
    SCENE_CLOSE_CHANNEL_ACTIVE = 2,
    SCENE_CLOSE_CHANNEL_PASSIVE = 3,
    SCENE_CLOSE_CHANNEL_TIMEOUT = 4,
} TransEventScene;

typedef enum {
    STAGE_OPEN_CHANNEL_START = 1,
    STAGE_SELECT_LANE = 2,
    STAGE_START_CONNECT = 3,
    STAGE_HANDSHAKE_START = 4,
    STAGE_HANDSHAKE_REPLY = 5,
    STAGE_OPEN_CHANNEL_END = 6,
} TransEventOpenChannelStage;

typedef enum {
    STAGE_CLOSE_CHANNEL = 1,
} TransEventCloseChannelStage;

typedef struct {
    int32_t dataType;       // DATA_TYPE
    int32_t peerNetworkId;  // PEER_NETID
    int32_t linkType;       // LINK_TYPE
    int32_t channelType;    // LOCAL_CHAN_TYPE
    int32_t channelId;      // CHAN_ID
    int32_t peerChannelId;  // PEER_CHAN_ID
    int32_t requestId;      // REQ_ID
    int32_t connectionId;   // CONN_ID
    int32_t costTime;       // HANDSHAKE_TIME_CONSUMING & OPEN_SESSION_TIME_CONSUMING -> COST_TIME
    int32_t result;         // STAGE_RES
    int32_t errcode;        // ERROR_CODE
    const char *callerPkg;  // HOST_PKG
    const char *calleePkg;  // TO_CALL_PKG
    const char *socketName; // SESSION_NAME -> SOCKET_NAME
} TransEventExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_ATOM_FORM_H
