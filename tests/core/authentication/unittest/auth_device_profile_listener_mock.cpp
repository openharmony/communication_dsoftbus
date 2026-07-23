/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "auth_device_profile_listener_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authLaneInterface;
AuthDeviceProfileListenerInterfaceMock::AuthDeviceProfileListenerInterfaceMock()
{
    g_authLaneInterface = reinterpret_cast<void *>(this);
}

AuthDeviceProfileListenerInterfaceMock::~AuthDeviceProfileListenerInterfaceMock()
{
    g_authLaneInterface = nullptr;
}

static AuthDeviceProfileListenerInterfaceMock *GetInterface()
{
    return reinterpret_cast<AuthDeviceProfileListenerInterfaceMock *>(g_authLaneInterface);
}

extern "C" {
void DelNotTrustDevice(const char *udid)
{
    (void)udid;
}

void RestartCoapDiscovery(void) { }

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return GetInterface()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    (void)reason;
}

void NotifyRemoteDevOffLineByUserId(int32_t userId, const char *udid)
{
    (void)userId;
    (void)udid;
}

void LnnNotifyAccountAclChangeEvent(
    const char *udid, int32_t localUserId, int32_t peerUserId, const int64_t *serviceIdList, uint32_t serviceIdCount)
{
    (void)udid;
    (void)localUserId;
    (void)peerUserId;
    (void)serviceIdList;
    (void)serviceIdCount;
}

bool LnnIsLocalSupportBurstFeature(void)
{
    return GetInterface()->LnnIsLocalSupportBurstFeature();
}

int32_t GetActiveOsAccountIds(void)
{
    return GetInterface()->GetActiveOsAccountIds();
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId)
{
    return GetInterface()->DpHasAccessControlProfile(udid, isNeedUserId, localUserId);
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid)
{
    return GetInterface()->LnnDeleteSpecificTrustedDevInfo(udid);
}

SoftBusScreenState GetScreenState(void)
{
    return GetInterface()->GetScreenState();
}

bool IsHeartbeatEnable(void)
{
    return GetInterface()->IsHeartbeatEnable();
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

void LnnHbOnTrustedRelationIncreased(int32_t groupType)
{
    return GetInterface()->LnnHbOnTrustedRelationIncreased(groupType);
}

void LnnHbOnTrustedRelationReduced(void)
{
    return GetInterface()->LnnHbOnTrustedRelationReduced();
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    (void)type;
}

int32_t LnnJudgeDeviceTypeAndGetOsAccountInfo(uint8_t *accountHash, uint32_t len)
{
    return GetInterface()->LnnJudgeDeviceTypeAndGetOsAccountInfo(accountHash, len);
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return GetInterface()->JudgeDeviceTypeAndGetOsAccountIds();
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    (void)key;
    if (info != nullptr) {
        *info = 0;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetRemoteNumInfo(const char *id, IdCategory type, int32_t *info)
{
    (void)id;
    (void)type;
    if (info != nullptr) {
        *info = 0;
    }
    return SOFTBUS_OK;
}

int32_t GetAllForegroundAccountIds(int32_t **userIds, uint32_t *userIdsLen)
{
    if (userIds == nullptr || userIdsLen == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    *userIds = nullptr;
    *userIdsLen = 0;
    return SOFTBUS_OK;
}

bool IsForegroundUserId(int32_t userId)
{
    (void)userId;
    return true;
}
}
} // namespace OHOS
