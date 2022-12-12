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

#include "lnn_hichain_mock.h"
#include "auth_interface.h"
#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const int32_t GRUOP_NUM1 = 10;
const int32_t GRUOP_NUM2 = 12;
const int32_t GRUOP_NUM3 = 100;
void *g_hichainInterface;

LnnHichainInterfaceMock::LnnHichainInterfaceMock()
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "construction");
    g_hichainInterface = reinterpret_cast<void *>(this);
}

LnnHichainInterfaceMock::~LnnHichainInterfaceMock()
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "delete");
    g_hichainInterface = nullptr;
}

static LnnHichainInterface *GetHichainInterface()
{
    return reinterpret_cast<LnnHichainInterfaceMock *>(g_hichainInterface);
}

extern "C" {
int32_t InitDeviceAuthService(void)
{
    return GetHichainInterface()->InitDeviceAuthService();
}

void DestroyDeviceAuthService(void)
{
    return GetHichainInterface()->DestroyDeviceAuthService();
}

const GroupAuthManager *GetGaInstance(void)
{
    return GetHichainInterface()->GetGaInstance();
}

const DeviceGroupManager *GetGmInstance(void)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetGmInstance");
    return GetHichainInterface()->GetGmInstance();
}
}

int32_t LnnHichainInterfaceMock::ActionOfProcessData(
    int64_t authSeq, const uint8_t *data, uint32_t len, const DeviceAuthCallback *gaCallback)
{
    (void)authSeq;
    (void)data;
    (void)len;
    g_devAuthCb.onTransmit = gaCallback->onTransmit;
    g_devAuthCb.onSessionKeyReturned = gaCallback->onSessionKeyReturned;
    g_devAuthCb.onFinish = gaCallback->onFinish;
    g_devAuthCb.onError = gaCallback->onError;
    g_devAuthCb.onRequest = gaCallback->onRequest;
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::AuthDeviceConnSend(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "AuthDeviceConnSend");
    (void)SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    if (appId == nullptr || listener == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHichainInterfaceMock::g_datachangelistener.emplace(appId, listener);
    return SOFTBUS_OK;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups1(int32_t osAccountId, const char *appId, int groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupType;
    *groupNum = 1;

    if (groupType == AUTH_IDENTICAL_ACCOUNT_GROUP) {
        *groupNum = GRUOP_NUM1;
    }
    if (groupType == AUTH_PEER_TO_PEER_GROUP) {
        *groupNum = GRUOP_NUM2;
    }
    *returnGroupVec = reinterpret_cast<char *>(SoftBusCalloc(*groupNum));
    if (*returnGroupVec == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups2(int32_t osAccountId, const char *appId, int groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupType;
    (void)returnGroupVec;
    *groupNum = GRUOP_NUM3;

    return HC_ERR_INVALID_PARAMS;
}
int32_t LnnHichainInterfaceMock::ActionofunRegDataChangeListener(const char *appId)
{
    (void)appId;
    LnnHichainInterfaceMock::g_datachangelistener.clear();
    return SOFTBUS_OK;
}
} // namespace OHOS