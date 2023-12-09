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
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "auth_deviceprofile.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "access_control_profile.h"
#include "anonymizer.h"
#include "distributed_device_profile_client.h"
#include "lnn_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trust_device_profile.h"

using DpClient = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient;
static constexpr uint32_t CUST_UDID_LEN = 16;

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash)
{
    if (deviceIdHash == nullptr) {
        LNN_LOGE(LNN_STATE, "deviceIdHash is null");
        return false;
    }
    LNN_LOGI(LNN_STATE, "IsPotentialTrustedDeviceDp deviceIdHash=%s", deviceIdHash);
    std::vector<OHOS::DistributedDeviceProfile::TrustDeviceProfile> trustDevices;
    int32_t ret = DpClient::GetInstance().GetAllTrustDeviceProfile(trustDevices);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllTrustDeviceProfile ret=%d", ret);
        return false;
    }
    for (const auto &trustDevice : trustDevices) {
        if (trustDevice.GetDeviceIdType() != (int32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            trustDevice.GetDeviceId().empty()) {
            continue;
        }
        char *anonyUdid = nullptr;
        Anonymize(trustDevice.GetDeviceId().c_str(), &anonyUdid);
        LNN_LOGI(LNN_STATE, "udid=%s", anonyUdid);
        AnonymizeFree(anonyUdid);
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[CUST_UDID_LEN + 1] = {0};
        const unsigned char *udid = (const unsigned char *)trustDevice.GetDeviceId().c_str();
        if (SoftBusGenerateStrHash(udid, trustDevice.GetDeviceId().length(), udidHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate udidhash fail");
            continue;
        }
        if (ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash,
            CUST_UDID_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "convert udidhash hex string fail");
            continue;
        }
        if (strncmp(hashStr, deviceIdHash, strlen(deviceIdHash)) == 0) {
            LNN_LOGI(LNN_STATE, "device trusted in dp continue verify");
            return true;
        }
    }
    LNN_LOGI(LNN_STATE, "device is not trusted in dp");
    return false;
}