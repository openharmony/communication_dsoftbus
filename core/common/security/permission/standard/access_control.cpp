/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

using namespace OHOS::DistributedDeviceProfile;
int32_t TransCheckAccessControl(const char *peerDeviceId)
{
    if (peerDeviceId == nullptr) {
        COMM_LOGE(COMM_PERM, "peerDeviceId is null");
        return SOFTBUS_ERR;
    }

    int32_t firstCallingId = OHOS::IPCSkeleton::GetFirstTokenID();
    if (firstCallingId == 0) {
        return SOFTBUS_OK;
    }

    char *tmpName = nullptr;
    Anonymize(peerDeviceId, &tmpName);
    COMM_LOGI(COMM_PERM, "firstCaller=%{public}d, peerDeviceId=%{public}s", firstCallingId, tmpName);
    AnonymizeFree(tmpName);

    char deviceId[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerDeviceId, STRING_KEY_DEV_UDID, deviceId, sizeof(deviceId)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "LnnGetRemoteStrInfo udid failed");
        return SOFTBUS_ERR;
    }
    Anonymize(deviceId, &tmpName);
    COMM_LOGI(COMM_PERM, "deviceId=%{public}s", tmpName);
    AnonymizeFree(tmpName);

    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    std::string firstTokenIdStr = std::to_string(firstCallingId);
    parms.insert({{"tokenId", firstTokenIdStr}, {"trustDeviceId", deviceId}, {"status", active}});

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    COMM_LOGI(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
    if (profile.empty()) {
        return SOFTBUS_ERR;
    }
    for (auto &item : profile) {
        COMM_LOGI(COMM_PERM,
            "GetBindLevel=%{public}d, GetBindType=%{public}d", item.GetBindLevel(), item.GetBindType());
    }

    return SOFTBUS_OK;
}
