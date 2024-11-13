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

#include "bus_center_event_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_busCenterEventDepsInterface = nullptr;
BusCenterEventDepsInterfaceMock::BusCenterEventDepsInterfaceMock()
{
    g_busCenterEventDepsInterface = reinterpret_cast<void *>(this);
}

BusCenterEventDepsInterfaceMock::~BusCenterEventDepsInterfaceMock()
{
    g_busCenterEventDepsInterface = nullptr;
}

static BusCenterEventDepsInterface *GetBusCenterEventDepsInterface()
{
    return reinterpret_cast<BusCenterEventDepsInterface *>(g_busCenterEventDepsInterface);
}

extern "C" {
void Anonymize(const char *plainStr, char **anonymizedStr)
{
    return GetBusCenterEventDepsInterface()->Anonymize(plainStr, anonymizedStr);
}

void AnonymizeFree(char *anonymizedStr)
{
    return GetBusCenterEventDepsInterface()->AnonymizeFree(anonymizedStr);
}

int32_t SetDefaultQdisc(void)
{
    return GetBusCenterEventDepsInterface()->SetDefaultQdisc();
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    return GetBusCenterEventDepsInterface()->LnnGetAllOnlineNodeNum(nodeNum);
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetLocalNum64Info(key, info);
}

int32_t LnnIpcNotifyDeviceNotTrusted(const char *msg)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyDeviceNotTrusted(msg);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
    int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyJoinResult(addr, addrTypeLen, networkId, retCode);
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyLeaveResult(networkId, retCode);
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetBusCenterEventDepsInterface()->LnnHasDiscoveryType(info, type);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetBusCenterEventDepsInterface()->LnnConvAddrTypeToDiscType(type);
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    return GetBusCenterEventDepsInterface()->CreateNewLooper(name);
}

int32_t  LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyOnlineState(isOnline, info, infoTypeLen);
}

void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnDCProcessOnlineState(isOnline, info);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyBasicInfoChanged(info, infoTypeLen, type);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetBusCenterEventDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnIpcLocalNetworkIdChanged(void)
{
    return GetBusCenterEventDepsInterface()->LnnIpcLocalNetworkIdChanged();
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetBusCenterEventDepsInterface()->LnnSetLocalStrInfo(key, info);
}

void LnnUpdateAuthExchangeUdid(void)
{
    return GetBusCenterEventDepsInterface()->LnnUpdateAuthExchangeUdid();
}
}
} // namespace OHOS
