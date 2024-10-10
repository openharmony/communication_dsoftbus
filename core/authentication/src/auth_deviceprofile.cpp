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
#include <set>
#include <mutex>
#include <string>
#include <vector>

#include "access_control_profile.h"
#include "anonymizer.h"
#include "auth_interface.h"
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
static constexpr uint32_t ACCOUNT_HASH_SHORT_LEN = 2;
static std::set<std::string> g_notTrustedDevices;
static std::mutex g_mutex;

static bool IsNotTrustDevice(std::string deviceIdHash)
{
    std::lock_guard<std::mutex> autoLock(g_mutex);
    if (g_notTrustedDevices.find(deviceIdHash) != g_notTrustedDevices.end()) {
        LNN_LOGI(LNN_STATE, "device not trusted");
        return true;
    }
    return false;
}

static void InsertNotTrustDevice(std::string deviceIdHash)
{
    std::lock_guard<std::mutex> autoLock(g_mutex);
    g_notTrustedDevices.insert(deviceIdHash);
}

void DelNotTrustDevice(const char *udid)
{
    if (udid == nullptr) {
        LNN_LOGE(LNN_STATE, "udid is null");
        return;
    }
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[CUST_UDID_LEN + 1] = {0};
    if (SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), udidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "generate udidhash fail");
        return;
    }
    if (ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash, CUST_UDID_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "convert udidhash hex string fail");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_mutex);
    if (g_notTrustedDevices.find(hashStr) != g_notTrustedDevices.end()) {
        LNN_LOGI(LNN_STATE, "remove not trust device");
        g_notTrustedDevices.erase(hashStr);
        return;
    }
    LNN_LOGI(LNN_STATE, "not need remove");
}

static bool IsTrustDevice(std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> &trustDevices,
    const char *deviceIdHash, const char *anonyDeviceIdHash)
{
    for (const auto &trustDevice : trustDevices) {
        if (trustDevice.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            trustDevice.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT ||
            trustDevice.GetTrustDeviceId().empty()) {
            continue;
        }
        char *anonyUdid = nullptr;
        Anonymize(trustDevice.GetTrustDeviceId().c_str(), &anonyUdid);
        LNN_LOGI(LNN_STATE, "udid=%{public}s, deviceIdHash=%{public}s",
            AnonymizeWrapper(anonyUdid), anonyDeviceIdHash);
        AnonymizeFree(anonyUdid);
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[CUST_UDID_LEN + 1] = {0};
        if (SoftBusGenerateStrHash((const unsigned char *)trustDevice.GetTrustDeviceId().c_str(),
            trustDevice.GetTrustDeviceId().length(), udidHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate udidhash fail");
            continue;
        }
        if (ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash,
            CUST_UDID_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "convert udidhash hex string fail");
            continue;
        }
        if (strncmp(hashStr, deviceIdHash, strlen(deviceIdHash)) == 0) {
            LNN_LOGI(LNN_STATE, "device trusted in dp continue verify, deviceIdHash=%{public}s", anonyDeviceIdHash);
            return true;
        }
    }
    return false;
}

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash)
{
    if (deviceIdHash == nullptr || IsNotTrustDevice(deviceIdHash)) {
        LNN_LOGE(LNN_STATE, "deviceIdHash is null or device not trusted");
        return false;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_NOT_FIND_DATA && ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return false;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        InsertNotTrustDevice(deviceIdHash);
        return false;
    }
    char *anonyDeviceIdHash = nullptr;
    Anonymize(deviceIdHash, &anonyDeviceIdHash);
    static uint32_t callCount = 0;
    if (IsTrustDevice(aclProfiles, deviceIdHash, anonyDeviceIdHash)) {
        AnonymizeFree(anonyDeviceIdHash);
        return true;
    }
    InsertNotTrustDevice(deviceIdHash);
    LNN_LOGI(LNN_STATE, "device is not trusted in dp, deviceIdHash=%{public}s, callCount=%{public}u",
        AnonymizeWrapper(anonyDeviceIdHash), callCount++);
    AnonymizeFree(anonyDeviceIdHash);
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
    LNN_LOGI(LNN_STATE, "insert dp same account succ, udid=%{public}s", AnonymizeWrapper(anonyUdid));
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

