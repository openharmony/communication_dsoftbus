/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bus_center_ipc_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_busCenterIpcInterface;
BusCenterIpcInterfaceMock::BusCenterIpcInterfaceMock()
{
    g_busCenterIpcInterface = reinterpret_cast<void *>(this);
}

BusCenterIpcInterfaceMock::~BusCenterIpcInterfaceMock()
{
    g_busCenterIpcInterface = nullptr;
}

static BusCenterIpcInterface *BusCenterIpcInterfaceInstance()
{
    return reinterpret_cast<BusCenterIpcInterfaceMock *>(g_busCenterIpcInterface);
}

extern "C" {
bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return BusCenterIpcInterfaceInstance()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

int32_t LnnServerLeave(const char *networkId, const char *pkgName)
{
    return BusCenterIpcInterfaceInstance()->LnnServerLeave(networkId, pkgName);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return BusCenterIpcInterfaceInstance()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return BusCenterIpcInterfaceInstance()->LnnIsLSANode(info);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return BusCenterIpcInterfaceInstance()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return BusCenterIpcInterfaceInstance()->LnnGetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag)
{
    return BusCenterIpcInterfaceInstance()->LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
}

int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    return BusCenterIpcInterfaceInstance()->LnnStartTimeSync(pkgName, callingPid, targetNetworkId, accuracy, period);
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    return BusCenterIpcInterfaceInstance()->LnnStopTimeSync(pkgName, targetNetworkId, callingPid);
}

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest)
{
    return BusCenterIpcInterfaceInstance()->LnnPublishService(pkgName, info, isInnerRequest);
}

int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest)
{
    return BusCenterIpcInterfaceInstance()->LnnUnPublishService(pkgName, publishId, isInnerRequest);
}

int32_t LnnStartDiscDevice(
    const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb, bool isInnerRequest)
{
    return BusCenterIpcInterfaceInstance()->LnnStartDiscDevice(pkgName, info, cb, isInnerRequest);
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    return BusCenterIpcInterfaceInstance()->LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
}

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return BusCenterIpcInterfaceInstance()->LnnActiveMetaNode(info, metaNodeId);
}

int32_t LnnDeactiveMetaNode(const char *metaNodeId)
{
    return BusCenterIpcInterfaceInstance()->LnnDeactiveMetaNode(metaNodeId);
}

int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    return BusCenterIpcInterfaceInstance()->LnnGetAllMetaNodeInfo(infos, infoNum);
}

int32_t LnnShiftLNNGear(
    const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    return BusCenterIpcInterfaceInstance()->LnnShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t ClientOnJoinLNNResult(
    PkgNameAndPidInfo *info, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    return BusCenterIpcInterfaceInstance()->ClientOnJoinLNNResult(info, addr, addrTypeLen, networkId, retCode);
}

int32_t ClientOnLeaveLNNResult(const char *pkgName, int32_t pid, const char *networkId, int32_t retCode)
{
    return BusCenterIpcInterfaceInstance()->ClientOnLeaveLNNResult(pkgName, pid, networkId, retCode);
}

int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return BusCenterIpcInterfaceInstance()->ClinetOnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return BusCenterIpcInterfaceInstance()->ClinetOnNodeBasicInfoChanged(info, infoTypeLen, type);
}

int32_t ClientOnTimeSyncResult(
    const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    return BusCenterIpcInterfaceInstance()->ClientOnTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason)
{
    return BusCenterIpcInterfaceInstance()->ClientOnPublishLNNResult(pkgName, pid, publishId, reason);
}

int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason)
{
    return BusCenterIpcInterfaceInstance()->ClientOnRefreshLNNResult(pkgName, pid, refreshId, reason);
}

int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen)
{
    return BusCenterIpcInterfaceInstance()->ClientOnRefreshDeviceFound(pkgName, pid, device, deviceLen);
}

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName)
{
    return BusCenterIpcInterfaceInstance()->LnnServerJoin(addr, pkgName);
}
}
} // namespace OHOS