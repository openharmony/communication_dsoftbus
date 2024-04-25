/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <vector>
#include <map>

#include "accesstoken_kit.h"
#include "access_control.h"
#include "access_control_profile.h"
#include "anonymizer.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "comm_log.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_enums.h"
#include "ipc_skeleton.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

namespace {
    using namespace OHOS::DistributedDeviceProfile;
    using namespace OHOS::Security::AccessToken;
}

static int32_t TransCheckAccessControl(uint32_t firstCallingId, const char *deviceId)
{
    char *tmpName = nullptr;
    Anonymize(deviceId, &tmpName);
    COMM_LOGI(COMM_PERM, "firstCaller=%{public}u, deviceId=%{public}s", firstCallingId, tmpName);
    AnonymizeFree(tmpName);

    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    std::string firstTokenIdStr = std::to_string(firstCallingId);
    parms.insert({{"tokenId", firstTokenIdStr}, {"trustDeviceId", deviceId}, {"status", active}});

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    COMM_LOGI(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
    if (profile.empty()) {
        COMM_LOGE(COMM_PERM, "check acl failed:firstCaller=%{public}u", firstCallingId);
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }
    for (auto &item : profile) {
        COMM_LOGI(COMM_PERM, "BindLevel=%{public}d, BindType=%{public}d", item.GetBindLevel(), item.GetBindType());
    }

    return SOFTBUS_OK;
}

int32_t TransCheckClientAccessControl(const char *peerNetworkId)
{
    if (peerNetworkId == nullptr) {
        COMM_LOGE(COMM_PERM, "peerDeviceId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t callingTokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    if (callingTokenId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)callingTokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_HAP) {
        COMM_LOGI(COMM_PERM, "tokenType=%{public}d, not hap, no verification required", tokenType);
        return SOFTBUS_OK;
    }

    char deviceId[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_DEV_UDID, deviceId, sizeof(deviceId));
    if (ret != SOFTBUS_OK) {
        char *tmpName = nullptr;
        Anonymize(peerNetworkId, &tmpName);
        COMM_LOGE(COMM_PERM, "get remote udid failed, caller=%{public}u, networkId=%{public}s, ret=%{public}d",
            callingTokenId, tmpName, ret);
        AnonymizeFree(tmpName);
        return ret;
    }
    return TransCheckAccessControl(callingTokenId, deviceId);
}

int32_t TransCheckServerAccessControl(uint32_t firstCallingId)
{
    if (firstCallingId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)firstCallingId);
    if (tokenType != ATokenTypeEnum::TOKEN_HAP) {
        COMM_LOGI(COMM_PERM, "tokenType=%{public}d, No need for permission verification", tokenType);
        return SOFTBUS_OK;
    }

    char deviceId[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, deviceId, sizeof(deviceId));
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "get local udid failed, firstCaller=%{public}u, ret=%{public}d", firstCallingId, ret);
        return ret;
    }
    return TransCheckAccessControl(firstCallingId, deviceId);
}

uint32_t TransACLGetFirstTokenID()
{
    return OHOS::IPCSkeleton::GetFirstTokenID();
}

uint32_t TransACLGetCallingTokenID()
{
    return OHOS::IPCSkeleton::GetCallingTokenID();
}
