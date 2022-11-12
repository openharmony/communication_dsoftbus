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
#include "softbus_adapter_mem.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

const int32_t GRUOP_NUM1 = 10;
const int32_t GRUOP_NUM2 = 12;
const int32_t GRUOP_NUM3 = 100;

void *g_hichainInterface;
LnnHichainInterfaceMock::LnnHichainInterfaceMock()
{
    g_hichainInterface = reinterpret_cast<void *>(this);
}

LnnHichainInterfaceMock::~LnnHichainInterfaceMock()
{
    g_hichainInterface = nullptr;
}

int32_t LnnHichainInterfaceMock::InvokeAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    return 0;
}

int32_t LnnHichainInterfaceMock::InvokeDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    return 0;
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
    *returnGroupVec = (char *)SoftBusCalloc(*groupNum);
    if (*returnGroupVec == NULL) {
        return -1;
    }
    return 0;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups2(int32_t osAccountId, const char *appId, int groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupType;
    (void)returnGroupVec;
    *groupNum = GRUOP_NUM3;

    return -1;
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
    return GetHichainInterface()->GetGmInstance();
}
}
}