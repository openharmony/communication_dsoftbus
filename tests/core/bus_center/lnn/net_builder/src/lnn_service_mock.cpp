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

#include "lnn_service_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_serviceInterface;
LnnServicetInterfaceMock::LnnServicetInterfaceMock()
{
    g_serviceInterface = reinterpret_cast<void *>(this);
}

LnnServicetInterfaceMock::~LnnServicetInterfaceMock()
{
    g_serviceInterface = nullptr;
}

static LnnServicetInterfaceMock *GetServiceInterface()
{
    return reinterpret_cast<LnnServicetInterfaceMock *>(g_serviceInterface);
}

extern "C" {
int32_t LnnInitBusCenterEvent(void)
{
    return GetServiceInterface()->LnnInitBusCenterEvent();
}

void LnnDeinitBusCenterEvent(void)
{
    return GetServiceInterface()->LnnDeinitBusCenterEvent();
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetServiceInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetServiceInterface()->LnnUnregisterEventHandler(event, handler);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void MetaNodeNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->MetaNodeNotifyJoinResult(addr, networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

void MetaNodeNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->MetaNodeNotifyLeaveResult(networkId, retCode);
}

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info)
{
    return GetServiceInterface()->LnnNotifyOnlineState(isOnline, info);
}

void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type)
{
    return GetServiceInterface()->LnnNotifyBasicInfoChanged(info, type);
}

void LnnNotifyWlanStateChangeEvent(SoftBusWifiState state)
{
    return GetServiceInterface()->LnnNotifyWlanStateChangeEvent(state);
}

void LnnNotifyBtStateChangeEvent(void *state)
{
    return GetServiceInterface()->LnnNotifyBtStateChangeEvent(state);
}

void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type,
    uint8_t relation, bool isJoin)
{
    return GetServiceInterface()->LnnNotifyLnnRelationChanged(udid, type, relation, isJoin);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char* masterNodeUdid, int32_t weight)
{
    return GetServiceInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}
}
}