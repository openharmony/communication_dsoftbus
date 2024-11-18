/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_link_p2p.h"
#include "softbus_error_code.h"

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    (void)request;
    (void)laneReqId;
    (void)callback;
    return SOFTBUS_P2P_NOT_SUPPORT;
}
int32_t LnnDisconnectP2p(const char *networkId, uint32_t laneReqId)
{
    (void)networkId;
    (void)laneReqId;
    return SOFTBUS_P2P_NOT_SUPPORT;
}
void LnnDestroyP2p(void)
{
    return;
}

void LnnCancelWifiDirect(uint32_t laneReqId)
{
    (void)laneReqId;
    return;
}

int32_t CheckIsAuthSessionServer(const char *peerIp, bool *isServer)
{
    (void)peerIp;
    (void)isServer;
    return SOFTBUS_P2P_NOT_SUPPORT;
}

int32_t RemoveAuthSessionServer(const char *peerIp)
{
    (void)peerIp;
    return SOFTBUS_P2P_NOT_SUPPORT;
}

void LnnDisconnectP2pWithoutLnn(uint32_t laneReqId)
{
    (void)laneReqId;
    return;
}

void NotifyLinkFailForForceDown(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
    return;
}

void RecycleP2pLinkedReqByLinkType(const char *peerNetworkId, LaneLinkType linkType)
{
    (void)peerNetworkId;
    (void)linkType;
    return;
}

int32_t WifiDirectReconnectDevice(uint32_t p2pRequestId)
{
    (void)p2pRequestId;
    return SOFTBUS_P2P_NOT_SUPPORT;
}

int32_t LnnInitPtkSyncListener(void)
{
    return SOFTBUS_P2P_NOT_SUPPORT;
}
