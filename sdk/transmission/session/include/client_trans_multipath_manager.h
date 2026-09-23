/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_MULTIPATH_MANAGER_H
#define CLIENT_TRANS_MULTIPATH_MANAGER_H

#include <stdint.h>

#include "client_trans_session_manager.h"
#include "client_trans_session_manager_struct.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* ========== Initialization and enable ========== */

int32_t TransMultipathCheckAndEnable(int32_t socket, const QosTV *qos, uint32_t qosCount);

/* ========== Read and write multipath state ========== */

int32_t TransMultipathGetEnabled(int32_t socket, bool *enabled);

int32_t TransMultipathSetEnabled(int32_t socket, bool enabled);

int32_t TransMultipathSetStrategy(int32_t socket, MultipathStrategy strategy);

/* ========== Primary and reserve channel management ========== */

int32_t TransMultipathSetChannel(int32_t sessionId, int32_t channelId, int32_t channelType);

int32_t TransMultipathUpdateReserveChannel(int32_t sessionId, const ChannelInfo *channel);

int32_t TransMultipathGetReserveChannel(
    int32_t sessionId, int32_t *channelId, int32_t *channelType, int32_t *routeType);

int32_t TransMultipathClearReserveChannel(int32_t sessionId);

int32_t TransMultipathGetChannelRole(int32_t sessionId, int32_t channelId, ChannelUseChooseState *useType);

bool TransMultipathIsSessionActive(const char *sessionName, int32_t *multipathSessionId);

/* ========== Link-down handling ========== */

bool TransMultipathNeedDelReserve(SessionInfo *sessionNode, int32_t routeType, bool *onlyReserveLinkDown);

void TransMultipathDelReserveLinkDown(
    SessionInfo *sessionNode, const ClientSessionServer *server, ListNode *destroyList, bool onlyReserveLinkDown);

void TransMultipathUpdateClosingState(SessionInfo *sessionNode, bool isClosing);

/* ========== Event reporting ========== */

void TransMultipathOnEvent(int32_t channelId, uint8_t changeType, int32_t linkType, int32_t reason);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // CLIENT_TRANS_MULTIPATH_MANAGER_H
