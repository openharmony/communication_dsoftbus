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
#include "p2plink_interface.h"
#include "softbus_errcode.h"

int32_t P2pLinkGetRequestId(void)
{
    static int32_t requestId = 0;
    requestId++;
    if (requestId == 0) {
        requestId++;
    }
    return requestId;
}

int32_t P2pLinkInit(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info)
{
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info)
{
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t P2pLinkIsRoleConflict(const RoleIsConflictInfo *info)
{
    (void)info;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t P2pLinkGetPeerMacByPeerIp(const char *peerIp, char* peerMac, int32_t macLen)
{
    (void)peerIp;
    (void)peerMac;
    (void)macLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void P2pLinkRegPeerDevStateChange(const P2pLinkPeerDevStateCb *cb)
{
    (void)cb;
    return;
}

int32_t P2pLinkGetLocalIp(char *localIp, int32_t localIpLen)
{
    (void)localIp;
    (void)localIpLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t P2pLinkQueryDevIsOnline(const char *peerMac)
{
    (void)peerMac;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
