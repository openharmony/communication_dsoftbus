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

#include "client_bus_center_manager_mock.h"

#include <securec.h>

#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
void *g_clientBusCenterManagerInterface;
ClientBusCenterManagerInterfaceMock::ClientBusCenterManagerInterfaceMock()
{
    g_clientBusCenterManagerInterface = reinterpret_cast<void *>(this);
}

ClientBusCenterManagerInterfaceMock::~ClientBusCenterManagerInterfaceMock()
{
    g_clientBusCenterManagerInterface = nullptr;
}

static ClientBusCenterManagerInterfaceMock *GetBusCenterManagerInterface()
{
    return reinterpret_cast<ClientBusCenterManagerInterfaceMock *>(g_clientBusCenterManagerInterface);
}

extern "C" {
int32_t BusCenterServerProxyInit(void)
{
    return GetBusCenterManagerInterface()->BusCenterServerProxyInit();
}

void BusCenterServerProxyDeInit(void)
{
    return GetBusCenterManagerInterface()->BusCenterServerProxyDeInit();
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetBusCenterManagerInterface()->SoftbusGetConfig(type, val, len);
}

int32_t ServerIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    return GetBusCenterManagerInterface()->ServerIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
}

int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return GetBusCenterManagerInterface()->ServerIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
}

int32_t ServerIpcGetNodeKeyInfo(
    const char *pkgName, const char *networkId, int32_t key, unsigned char *buf, uint32_t len)
{
    return GetBusCenterManagerInterface()->ServerIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
}

int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    return GetBusCenterManagerInterface()->ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
}

int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, unsigned int addrTypeLen)
{
    return GetBusCenterManagerInterface()->ServerIpcJoinLNN(pkgName, addr, addrTypeLen);
}

int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId)
{
    return GetBusCenterManagerInterface()->ServerIpcLeaveLNN(pkgName, networkId);
}

int32_t ServerIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    return GetBusCenterManagerInterface()->ServerIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
}

int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return GetBusCenterManagerInterface()->ServerIpcStopTimeSync(pkgName, targetNetworkId);
}

int32_t ServerIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    return GetBusCenterManagerInterface()->ServerIpcPublishLNN(pkgName, info);
}

int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return GetBusCenterManagerInterface()->ServerIpcStopPublishLNN(pkgName, publishId);
}

int32_t ServerIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    return GetBusCenterManagerInterface()->ServerIpcRefreshLNN(pkgName, info);
}

int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    return GetBusCenterManagerInterface()->ServerIpcStopRefreshLNN(pkgName, refreshId);
}

int32_t ServerIpcRegDataLevelChangeCb(const char *pkgName)
{
    return GetBusCenterManagerInterface()->ServerIpcRegDataLevelChangeCb(pkgName);
}

int32_t ServerIpcUnregDataLevelChangeCb(const char *pkgName)
{
    return GetBusCenterManagerInterface()->ServerIpcUnregDataLevelChangeCb(pkgName);
}

int32_t ServerIpcSetDataLevel(const DataLevel *dataLevel)
{
    return GetBusCenterManagerInterface()->ServerIpcSetDataLevel(dataLevel);
}

int32_t SoftBusMutexLockInner(SoftBusMutex *mutex)
{
    return GetBusCenterManagerInterface()->SoftBusMutexLockInner(mutex);
}

int32_t SoftBusMutexUnlockInner(SoftBusMutex *mutex)
{
    return GetBusCenterManagerInterface()->SoftBusMutexUnlockInner(mutex);
}
} // extern "C"
} // namespace OHOS
