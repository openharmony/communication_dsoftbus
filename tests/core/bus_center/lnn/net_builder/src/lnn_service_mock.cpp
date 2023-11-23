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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_log.h"
#include "lnn_service_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

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

static LnnServiceInterface *GetServiceInterface()
{
    return reinterpret_cast<LnnServiceInterface *>(g_serviceInterface);
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

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyLeaveResult(networkId, retCode);
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

int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler)
{
    return GetServiceInterface()->LnnInitGetDeviceName(handler);
}

void RegisterNameMonitor(void)
{
    return GetServiceInterface()->RegisterNameMonitor();
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetServiceInterface()->LnnUnregisterEventHandler(event, handler);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    return GetServiceInterface()->LnnOfflineTimingByHeartbeat(networkId, addrType);
}

int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    return GetServiceInterface()->LnnGetSettingDeviceName(deviceName, len);
}

uint32_t AuthGenRequestId(void)
{
    return GetServiceInterface()->AuthGenRequestId();
}

void AuthHandleLeaveLNN(int64_t authId)
{
    return GetServiceInterface()->AuthHandleLeaveLNN(authId);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetServiceInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t LnnServicetInterfaceMock::ActionOfLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    if (event == LNN_EVENT_TYPE_MAX || handler == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_lnnEventHandlers.emplace(event, handler);
    return SOFTBUS_OK;
}

int32_t LnnServicetInterfaceMock::ActionOfLnnInitGetDeviceName(LnnDeviceNameHandler handler)
{
    if (handler == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_deviceNameHandler = handler;
    return SOFTBUS_OK;
}

int32_t LnnServicetInterfaceMock::ActionOfLnnGetSettingDeviceName(char *deviceName, uint32_t len)
{
    if (deviceName == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(deviceName, len, "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
}
}