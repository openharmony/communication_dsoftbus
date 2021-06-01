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

#include "lnn_bus_center_ipc.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "softbus_interface.h"

int32_t LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addrTypeLen;
    return LnnServerJoin((ConnectionAddr *)addr);
}

int32_t LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    return LnnServerLeave(networkId);
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetAllOnlineNodeInfo((NodeBasicInfo **)info, infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo((NodeBasicInfo *)info);
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    return GetClientProvideInterface()->onJoinLNNResult(NULL, addr, addrTypeLen, networkId, retCode);
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetClientProvideInterface()->onLeaveLNNResult(NULL, networkId, retCode);
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return GetClientProvideInterface()->onNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return GetClientProvideInterface()->onNodeBasicInfoChanged(info, infoTypeLen, type);
}