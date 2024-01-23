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
#include "bus_center_manager.h"
#include "distributed_device_profile_client.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_ohos_account.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trust_device_profile.h"

using DpClient = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient;
static constexpr uint32_t CUST_UDID_LEN = 16;
static constexpr uint32_t ACCOUNT_HASH_SHORT_LEN = 2;

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash)
{
    if (deviceIdHash == nullptr) {
        LNN_LOGE(LNN_STATE, "deviceIdHash is null");
        return false;
    }
    LNN_LOGI(LNN_STATE, "IsPotentialTrustedDeviceDp deviceIdHash=%{public}s", deviceIdHash);
    std::vector<OHOS::DistributedDeviceProfile::TrustDeviceProfile> trustDevices;
    int32_t ret = DpClient::GetInstance().GetAllTrustDeviceProfile(trustDevices);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS || trustDevices.empty()) {
        LNN_LOGE(LNN_STATE, "GetAllTrustDeviceProfile ret=%{public}d, size=%{public}zu", ret, trustDevices.size());
        return false;
    }
    for (const auto &trustDevice : trustDevices) {
        if (trustDevice.GetDeviceIdType() != (int32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            trustDevice.GetDeviceId().empty()) {
            continue;
        }
        char *anonyUdid = nullptr;
        Anonymize(trustDevice.GetDeviceId().c_str(), &anonyUdid);
        LNN_LOGI(LNN_STATE, "udid=%{public}s", anonyUdid);
        AnonymizeFree(anonyUdid);
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[CUST_UDID_LEN + 1] = {0};
        if (SoftBusGenerateStrHash((const unsigned char *)trustDevice.GetDeviceId().c_str(),
            trustDevice.GetDeviceId().length(), udidHash) != SOFTBUS_OK) {
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

static bool IsSameAccount(const std::string accountHashStr)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local accountHash fail");
        return false;
    }
    if (memcmp(localAccountHash, accountHashStr.c_str(), ACCOUNT_HASH_SHORT_LEN) == 0 && !LnnIsDefaultOhosAccount()) {
        LNN_LOGI(LNN_STATE, "accountHash=%{public}02x%{public}02x is same", localAccountHash[0], localAccountHash[1]);
        return true;
    }
    LNN_LOGI(LNN_STATE, "localAccountHash=%{public}02x%{public}02x, peeraccountHash=%{public}02x%{public}02x",
        localAccountHash[0], localAccountHash[1], accountHashStr[0], accountHashStr[1]);
    return false;
}

static int32_t GenerateDpAccesserAndAccessee(OHOS::DistributedDeviceProfile::Accesser &accesser,
    OHOS::DistributedDeviceProfile::Accessee &accessee, std::string peerUdid)
{
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local udid fail");
        return SOFTBUS_ERR;
    }
    std::string localUdid(udid);
    accesser.SetAccesserDeviceId(localUdid);
    accesser.SetAccesserUserId(GetActiveOsAccountIds());
    OHOS::AccountSA::OhosAccountInfo accountInfo;
    OHOS::ErrCode ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfo);
    if (ret != OHOS::ERR_OK || accountInfo.uid_.empty()) {
        LNN_LOGE(LNN_STATE, "getOhosAccountInfo fail ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    accesser.SetAccesserAccountId(accountInfo.uid_);
    accessee.SetAccesseeDeviceId(peerUdid);
    return SOFTBUS_OK;
}

static void InsertDpSameAccount(const std::string udid)
{
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_NOT_FIND_DATA && ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "getAllAccessControlProfile failed, ret=%{public}d", ret);
        return;
    }
    for (const auto &aclProfile : aclProfiles) {
        if (aclProfile.GetDeviceIdType() == (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID &&
            aclProfile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT &&
            udid == aclProfile.GetTrustDeviceId()) {
            LNN_LOGI(LNN_STATE, "dp has same account no need insert");
            return;
        }
    }

    OHOS::DistributedDeviceProfile::AccessControlProfile accessControlProfile;
    OHOS::DistributedDeviceProfile::Accesser accesser;
    OHOS::DistributedDeviceProfile::Accessee accessee;
    ret = GenerateDpAccesserAndAccessee(accesser, accessee, udid);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "generate accesser accessee fail");
        return;
    }
    accessControlProfile.SetBindType((uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT);
    accessControlProfile.SetDeviceIdType((uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID);
    accessControlProfile.SetStatus((uint32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE);
    accessControlProfile.SetAuthenticationType((uint32_t)OHOS::DistributedDeviceProfile::
        AuthenticationType::PERMANENT);
    accessControlProfile.SetTrustDeviceId(udid);
    accessControlProfile.SetAccesser(accesser);
    accessControlProfile.SetAccessee(accessee);
    ret = DpClient::GetInstance().PutAccessControlProfile(accessControlProfile);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "putAccessControlProfile failed, ret=%{public}d", ret);
        return;
    }
    char *anonyUdid = nullptr;
    Anonymize(udid.c_str(), &anonyUdid);
    LNN_LOGI(LNN_STATE, "insert dp same account succ, udid=%{public}s", anonyUdid);
    AnonymizeFree(anonyUdid);
}

void UpdateDpSameAccount(const char *accountHash, const char *deviceId)
{
    if (accountHash == nullptr || deviceId == nullptr) {
        LNN_LOGE(LNN_STATE, "accountHash or deviceId is null");
        return;
    }
    std::string accountHashStr(accountHash);
    std::string udid(deviceId);
    if (IsSameAccount(accountHashStr)) {
        InsertDpSameAccount(udid);
    }
}