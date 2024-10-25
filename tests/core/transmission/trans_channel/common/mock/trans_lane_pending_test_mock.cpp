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

#include "trans_lane_pending_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transLanePendingInterface = nullptr;
TransLanePendingTestInterfaceMock::TransLanePendingTestInterfaceMock()
{
    g_transLanePendingInterface = reinterpret_cast<void *>(this);
}

TransLanePendingTestInterfaceMock::~TransLanePendingTestInterfaceMock()
{
    g_transLanePendingInterface = nullptr;
}

static TransLanePendingTestInterface *GetTransLanePendingTestInterface()
{
    return reinterpret_cast<TransLanePendingTestInterface *>(g_transLanePendingInterface);
}

extern "C" {
SoftBusList *CreateSoftBusList(void)
{
    return GetTransLanePendingTestInterface()->CreateSoftBusList();
}

LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param)
{
    return GetTransLanePendingTestInterface()->TransGetLaneTransTypeBySession(param);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetTransLanePendingTestInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return GetTransLanePendingTestInterface()->TransGetUidAndPid(sessionName, uid, pid);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetTransLanePendingTestInterface()->LnnHasDiscoveryType(info, type);
}

LnnLaneManager* GetLaneManager(void)
{
    return GetTransLanePendingTestInterface()->GetLaneManager();
}

int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request, const ILaneListener *listener)
{
    return GetTransLanePendingTestInterface()->LnnRequestLane(laneReqId, request, listener);
}

int32_t TransSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis)
{
    return GetTransLanePendingTestInterface()->TransSoftBusCondWait(cond, mutex, timeMillis);
}

int32_t TransWaitingRequestCallback(uint32_t laneHandle)
{
    return GetTransLanePendingTestInterface()->TransWaitingRequestCallback(laneHandle);
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
    return GetTransLanePendingTestInterface()->SoftBusCondWait(cond, mutex, time);
}

int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo,
    const ConnectOption *connOpt, int32_t *channelId)
{
    return GetTransLanePendingTestInterface()->TransOpenChannelProc(type, appInfo, connOpt, channelId);
}

int32_t ClientIpcSetChannelInfo(const char *pkgName, const char *sessionName, int32_t sessionId,
    const TransInfo *transInfo, int32_t pid)
{
    return GetTransLanePendingTestInterface()->ClientIpcSetChannelInfo(pkgName, sessionName, sessionId, transInfo, pid);
}

int32_t TransLaneMgrAddLane(
    const TransInfo *transInfo, const LaneConnInfo *connInfo, uint32_t laneHandle, bool isQosLane, AppInfoData *myData)
{
    return GetTransLanePendingTestInterface()->TransLaneMgrAddLane(transInfo, connInfo, laneHandle, isQosLane, myData);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetTransLanePendingTestInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    return GetTransLanePendingTestInterface()->TransGetPkgNameBySessionName(sessionName, pkgName, len);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetTransLanePendingTestInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t LnnGetDLAuthCapacity(const char *networkId, uint32_t *authCapacity)
{
    return GetTransLanePendingTestInterface()->LnnGetDLAuthCapacity(networkId, authCapacity);
}
}
}
