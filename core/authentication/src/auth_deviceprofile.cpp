/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <cstring>
#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "distributed_device_profile_client.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "ohos_account_kits.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"

#define DEFAULT_ACCOUNT_UID         "ohosAnonymousUid"
#define DEFAULT_ACCOUNT_VALUE       "0"
#define DEFAULT_USER_KEY_INDEX      (-1)
#define DEFAULT_UKID_TIME           (-1)
#define DEFAULT_USERID              (-1)

using DpClient = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient;
static std::set<std::string> g_notTrustedDevices;
static std::mutex g_mutex;
static constexpr const int32_t LONG_TO_STRING_MAX_LEN = 21;

typedef struct {
    std::string localUdid;
    std::string peerUdid;
    int32_t peerUserId;
    int32_t sessionKeyId;
    uint64_t time;
} AclParams;

static bool IsNotTrustDevice(std::string deviceIdHash)
{
    std::lock_guard<std::mutex> autoLock(g_mutex);
    if (g_notTrustedDevices.find(deviceIdHash) != g_notTrustedDevices.end()) {
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
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    char hashStr[CUST_UDID_LEN + 1] = { 0 };
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

static int32_t GetAclLocalUserId(const OHOS::DistributedDeviceProfile::AccessControlProfile &trustDevice)
{
    if (trustDevice.GetTrustDeviceId() == trustDevice.GetAccessee().GetAccesseeDeviceId()) {
        return trustDevice.GetAccesser().GetAccesserUserId();
    }
    return trustDevice.GetAccessee().GetAccesseeUserId();
}

static int32_t GetAclPeerUserId(const OHOS::DistributedDeviceProfile::AccessControlProfile &trustDevice)
{
    if (trustDevice.GetTrustDeviceId() == trustDevice.GetAccessee().GetAccesseeDeviceId()) {
        return trustDevice.GetAccessee().GetAccesseeUserId();
    }
    return trustDevice.GetAccesser().GetAccesserUserId();
}

static int32_t GetStringHash(std::string str, char *hashStrBuf, int32_t len)
{
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((const unsigned char *)str.c_str(), str.length(), hash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "generate hash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(hashStrBuf, len + 1, hash, len / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "convert hash hex string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsTrustDevice(std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> &trustDevices,
    const char *deviceIdHash, const char *anonyDeviceIdHash, bool isOnlyPointToPoint)
{
    int32_t localUserId = GetActiveOsAccountIds();
    for (const auto &trustDevice : trustDevices) {
        if (isOnlyPointToPoint &&
            trustDevice.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
            continue;
        }
        if (trustDevice.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            trustDevice.GetTrustDeviceId().empty() ||
            trustDevice.GetStatus() == (uint32_t)OHOS::DistributedDeviceProfile::Status::INACTIVE ||
            localUserId != GetAclLocalUserId(trustDevice)) {
            continue;
        }
        char *anonyUdid = nullptr;
        Anonymize(trustDevice.GetTrustDeviceId().c_str(), &anonyUdid);
        LNN_LOGI(LNN_STATE, "udid=%{public}s, deviceIdHash=%{public}s", AnonymizeWrapper(anonyUdid),
            AnonymizeWrapper(anonyDeviceIdHash));
        AnonymizeFree(anonyUdid);
        uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
        char hashStr[CUST_UDID_LEN + 1] = { 0 };
        if (SoftBusGenerateStrHash((const unsigned char *)trustDevice.GetTrustDeviceId().c_str(),
            trustDevice.GetTrustDeviceId().length(), udidHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate udidhash fail");
            continue;
        }
        if (ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash, CUST_UDID_LEN / HEXIFY_UNIT_LEN) !=
            SOFTBUS_OK) {
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

static bool CompareAclWithPeerDeviceInfo(const OHOS::DistributedDeviceProfile::AccessControlProfile &aclProfile,
    const char *peerAccountHash, const char *peerUdid, int32_t peerUserId)
{
    int32_t localUserId = GetActiveOsAccountIds();
    char udid[UDID_BUF_LEN] = { 0 };
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };
    char localAccountString[SHA_256_HEX_HASH_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local udid fail");
        return false;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local account hash fail");
        return false;
    }
    if (ConvertBytesToHexString(
        localAccountString, SHA_256_HEX_HASH_LEN, (unsigned char *)localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "convert account to string fail");
        return false;
    }
    std::string localUdid(udid);
    std::string sourceAccountId = aclProfile.GetAccesser().GetAccesserAccountId();
    std::string sinkAccountId = aclProfile.GetAccessee().GetAccesseeAccountId();
    if (strcmp(DEFAULT_ACCOUNT_UID, sourceAccountId.c_str()) != 0) {
        if (StrCmpIgnoreCase(sourceAccountId.c_str(), peerAccountHash) != 0 &&
            StrCmpIgnoreCase(sourceAccountId.c_str(), localAccountString) != 0) {
            return false;
        }
    }
    if (strcmp(DEFAULT_ACCOUNT_UID, sinkAccountId.c_str()) != 0) {
        if (StrCmpIgnoreCase(sinkAccountId.c_str(), peerAccountHash) != 0 &&
            StrCmpIgnoreCase(sinkAccountId.c_str(), localAccountString) != 0) {
            return false;
        }
    }
    if (((aclProfile.GetAccessee().GetAccesseeDeviceId() != peerUdid ||
        aclProfile.GetAccesser().GetAccesserDeviceId() != localUdid) &&
        (aclProfile.GetAccesser().GetAccesserDeviceId() != peerUdid ||
        aclProfile.GetAccessee().GetAccesseeDeviceId() != localUdid)) ||
        GetAclLocalUserId(aclProfile) != localUserId || GetAclPeerUserId(aclProfile) != peerUserId) {
        return false;
    }
    return true;
}

bool IsTrustedDeviceFromAccess(const char *peerAccountHash, const char *peerUdid, int32_t peerUserId)
{
    if (peerAccountHash == nullptr || peerUdid == nullptr) {
        LNN_LOGE(LNN_STATE, "peerUdid is null");
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
        return false;
    }
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s", aclProfile.GetAccesser().dump().c_str(),
            aclProfile.GetAccessee().dump().c_str());
        if (aclProfile.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            aclProfile.GetTrustDeviceId().empty() || aclProfile.GetTrustDeviceId() != peerUdid) {
            continue;
        }
        if (!CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId)) {
            continue;
        }
        return true;
    }
    return false;
}

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint)
{
    if (deviceIdHash == nullptr) {
        LNN_LOGE(LNN_STATE, "deviceIdHash is null");
        return false;
    }
    if (IsNotTrustDevice(deviceIdHash)) {
        LNN_LOGD(LNN_STATE, "device not trusted");
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
    if (IsTrustDevice(aclProfiles, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint)) {
        AnonymizeFree(anonyDeviceIdHash);
        return true;
    }
    InsertNotTrustDevice(deviceIdHash);
    LNN_LOGI(LNN_STATE, "device is not trusted in dp, deviceIdHash=%{public}s, callCount=%{public}u",
        AnonymizeWrapper(anonyDeviceIdHash), callCount++);
    AnonymizeFree(anonyDeviceIdHash);
    return false;
}

bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId)
{
    if (udid == nullptr) {
        LNN_LOGE(LNN_STATE, "udid is null");
        return false;
    }

    char *anonyUdid = nullptr;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_STATE, "udid=%{public}s, isNeedUserId=%{public}d, localUserId=%{public}d", AnonymizeWrapper(anonyUdid),
        isNeedUserId, localUserId);
    AnonymizeFree(anonyUdid);
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_NOT_FIND_DATA && ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return false;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return false;
    }
    for (const auto &trustDevice : aclProfiles) {
        if (trustDevice.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            trustDevice.GetTrustDeviceId().empty() || trustDevice.GetTrustDeviceId() != udid) {
            continue;
        }
        if (isNeedUserId && GetAclLocalUserId(trustDevice) != localUserId) {
            continue;
        }

        LNN_LOGI(LNN_STATE, "dp has accessControlProfile");
        return true;
    }
    LNN_LOGI(LNN_STATE, "dp not has accessControlProfile");
    return false;
}

static void DumpAccountId(int64_t localAccountId, int64_t peerAccountId)
{
    char localAccountString[LONG_TO_STRING_MAX_LEN] = { 0 };
    if (sprintf_s(localAccountString, LONG_TO_STRING_MAX_LEN, "%" PRId64, localAccountId) == -1) {
        LNN_LOGE(LNN_STATE, "long to string fail");
        return;
    }

    char peerAccountString[LONG_TO_STRING_MAX_LEN] = { 0 };
    if (sprintf_s(peerAccountString, LONG_TO_STRING_MAX_LEN, "%" PRId64, peerAccountId) == -1) {
        LNN_LOGE(LNN_STATE, "long to string fail");
        return;
    }

    char *anonyLocalAccountId = nullptr;
    char *anonyPeerAccountId = nullptr;
    Anonymize(localAccountString, &anonyLocalAccountId);
    Anonymize(peerAccountString, &anonyPeerAccountId);
    LNN_LOGI(LNN_STATE, "localAccountId=%{public}s, peerAccountId=%{public}s", AnonymizeWrapper(anonyLocalAccountId),
        AnonymizeWrapper(anonyPeerAccountId));
    AnonymizeFree(anonyLocalAccountId);
    AnonymizeFree(anonyPeerAccountId);
}

static bool IsSameAccount(int64_t accountId)
{
    int64_t localAccountId = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_ACCOUNT_LONG, &localAccountId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local accountId fail");
        return false;
    }
    DumpAccountId(localAccountId, accountId);
    if (localAccountId == accountId && !LnnIsDefaultOhosAccount()) {
        return true;
    }
    return false;
}

static void DumpDpAclInfo(const std::string peerUdid, int32_t localUserId, int32_t peerUserId,
    const OHOS::DistributedDeviceProfile::AccessControlProfile &aclProfile)
{
    char *anonyUdid = nullptr;
    Anonymize(peerUdid.c_str(), &anonyUdid);
    LNN_LOGI(LNN_STATE,
        "dp has acl. udid=%{public}s, localUserId=%{public}d, peerUserId=%{public}d, "
        "Status=%{public}d",
        AnonymizeWrapper(anonyUdid), localUserId, peerUserId, aclProfile.GetStatus());
    AnonymizeFree(anonyUdid);
}

static UpdateDpAclResult UpdateDpSameAccountAcl(const std::string &peerUdid, int32_t peerUserId, int32_t sessionKeyId)
{
    peerUserId = peerUserId == 0 ? DEFAULT_USERID : peerUserId;
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == OHOS::DistributedDeviceProfile::DP_SUCCESS, GET_ALL_ACL_FAIL, LNN_STATE,
        "GetAllAccessControlProfile ret=%{public}d", ret);
    LNN_CHECK_AND_RETURN_RET_LOGE(!aclProfiles.empty(), GET_ALL_ACL_IS_EMPTY, LNN_STATE, "aclProfiles is empty");
    UpdateDpAclResult updateResult = UPDATE_ACL_NOT_MATCH;
    int32_t localUserId = GetActiveOsAccountIds();
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local udid fail");
    }
    std::string localUdid(udid);
    for (auto &aclProfile : aclProfiles) {
        if (aclProfile.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            aclProfile.GetTrustDeviceId().empty() || aclProfile.GetTrustDeviceId() != peerUdid ||
            aclProfile.GetBindType() != (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT ||
            aclProfile.GetAccesser().GetAccesserUserId() != localUserId ||
            ((aclProfile.GetAccessee().GetAccesseeUserId() != peerUserId) &&
            (aclProfile.GetAccessee().GetAccesseeUserId() != DEFAULT_USERID))) {
            continue;
        }
        OHOS::DistributedDeviceProfile::Accesser accesser(aclProfile.GetAccesser());
        if (sessionKeyId != DEFAULT_USER_KEY_INDEX) {
            accesser.SetAccesserSessionKeyId(sessionKeyId);
            accesser.SetAccesserSKTimeStamp(SoftBusGetSysTimeMs());
        }
        aclProfile.SetAccesser(accesser);
        OHOS::DistributedDeviceProfile::Accessee accessee(aclProfile.GetAccessee());
        if (accessee.GetAccesseeUserId() == DEFAULT_USERID && peerUserId != DEFAULT_USERID) {
            accessee.SetAccesseeUserId(peerUserId);
            aclProfile.SetAccessee(accessee);
        }
        if (aclProfile.GetAccessee().GetAccesseeDeviceId() == peerUdid &&
            aclProfile.GetAccesser().GetAccesserDeviceId() != localUdid) {
            continue;
        }
        DumpDpAclInfo(peerUdid, localUserId, peerUserId, aclProfile);
        if (aclProfile.GetStatus() != (int32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE) {
            aclProfile.SetStatus((int32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE);
        }
        ret = DpClient::GetInstance().UpdateAccessControlProfile(aclProfile);
        LNN_LOGI(LNN_STATE, "UpdateAccessControlProfile ret=%{public}d", ret);
        updateResult = UPDATE_ACL_SUCC;
    }
    return updateResult;
}

static void InsertDpSameAccountAcl(const std::string &peerUdid, int32_t peerUserId, int32_t sessionKeyId)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile accessControlProfile;
    OHOS::DistributedDeviceProfile::Accesser accesser;
    OHOS::DistributedDeviceProfile::Accessee accessee;
    char udid[UDID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local udid fail");
        return;
    }
    uint64_t currentTime = SoftBusGetSysTimeMs();
    std::string localUdid(udid);
    accesser.SetAccesserDeviceId(localUdid);
    accesser.SetAccesserUserId(GetActiveOsAccountIds());
    OHOS::AccountSA::OhosAccountInfo accountInfo;
    OHOS::ErrCode ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(accountInfo);
    if (ret != OHOS::ERR_OK || accountInfo.uid_.empty()) {
        LNN_LOGE(LNN_STATE, "GetOhosAccountInfo fail ret=%{public}d", ret);
        return;
    }
    accesser.SetAccesserAccountId(accountInfo.uid_);
    if (sessionKeyId != DEFAULT_USER_KEY_INDEX) {
        accesser.SetAccesserSessionKeyId(sessionKeyId);
        accesser.SetAccesserSKTimeStamp(currentTime);
    }
    accessee.SetAccesseeDeviceId(peerUdid);
    if (peerUserId != 0) {
        accessee.SetAccesseeUserId(peerUserId);
    }
    accessee.SetAccesseeAccountId(accountInfo.uid_);
    accessControlProfile.SetBindType((uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT);
    accessControlProfile.SetDeviceIdType((uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID);
    accessControlProfile.SetStatus((uint32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE);
    accessControlProfile.SetAuthenticationType((uint32_t)OHOS::DistributedDeviceProfile::AuthenticationType::PERMANENT);
    accessControlProfile.SetTrustDeviceId(peerUdid);
    accessControlProfile.SetAccesser(accesser);
    accessControlProfile.SetAccessee(accessee);
    ret = DpClient::GetInstance().PutAccessControlProfile(accessControlProfile);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "PutAccessControlProfile failed, ret=%{public}d", ret);
        return;
    }
    char *anonyUdid = nullptr;
    Anonymize(peerUdid.c_str(), &anonyUdid);
    LNN_LOGI(LNN_STATE,
        "insert dp same account succ, udid=%{public}s, localUserId=%{public}d, peerUserId=%{public}d, "
        "sessionKeyId=%{public}d, currentTime=%{public}" PRIu64,
        AnonymizeWrapper(anonyUdid), accesser.GetAccesserUserId(), accessee.GetAccesseeUserId(), sessionKeyId,
        currentTime);
    AnonymizeFree(anonyUdid);
}

static UpdateDpAclResult PutDpAclUkByUserId(
    int32_t userId, const uint8_t *sessionKey, uint32_t sessionKeyLen, int32_t *sessionKeyId)
{
    if (sessionKey == nullptr || sessionKeyId == nullptr) {
        LNN_LOGE(LNN_STATE, "put uk info is invalid param");
        return GET_ALL_ACL_FAIL;
    }
    std::vector<uint8_t> aclSessionKey;
    std::copy(sessionKey, sessionKey + sizeof(uint8_t) * sessionKeyLen, std::back_inserter(aclSessionKey));
    int32_t ret = DpClient::GetInstance().PutSessionKey(userId, aclSessionKey, *sessionKeyId);
    if (ret != OHOS::ERR_OK) {
        LNN_LOGE(LNN_STATE, "put session key fail, ret=%{public}d", ret);
        return UPDATE_ACL_NOT_MATCH;
    }
    LNN_LOGI(
        LNN_STATE, "set sessionKey for acl succ, sessionKeyId=%{public}d, userId=%{public}d", *sessionKeyId, userId);
    return UPDATE_ACL_SUCC;
}

void UpdateDpSameAccount(UpdateDpAclParams *aclParams, SessionKey sessionKey, bool isNeedUpdateDk,
    AclWriteState aclState)
{
    if (aclParams == nullptr || aclParams->deviceId == nullptr) {
        LNN_LOGE(LNN_STATE, "deviceId is null");
        return;
    }
    if (aclState == ACL_NOT_WRITE) {
        LNN_LOGE(LNN_STATE, "no need write acl");
        return;
    }
    int32_t sessionKeyId = DEFAULT_USER_KEY_INDEX;
    std::string peerUdid(aclParams->deviceId);
    UpdateDpAclResult ret = UPDATE_ACL_SUCC;

    if (isNeedUpdateDk) {
        ret = PutDpAclUkByUserId(GetActiveOsAccountIds(), sessionKey.value, sessionKey.len, &sessionKeyId);
        if (ret != UPDATE_ACL_SUCC) {
            LNN_LOGW(LNN_STATE, "not need update uk for acl");
        }
    }
    if (isNeedUpdateDk || IsSameAccount(aclParams->accountId) || (aclState == ACL_CAN_WRITE)) {
        ret = UpdateDpSameAccountAcl(peerUdid, aclParams->peerUserId, sessionKeyId);
        if (ret != UPDATE_ACL_SUCC) {
            InsertDpSameAccountAcl(peerUdid, aclParams->peerUserId, sessionKeyId);
        }
    }
}

bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, false, LNN_EVENT, "sessionKey is null");
    LNN_CHECK_AND_RETURN_RET_LOGE(length != NULL, false, LNN_EVENT, "length is null");
    std::vector<uint8_t> vecSessionKey;
    int32_t localUserId = GetActiveOsAccountIds();
    if (localUserId < 0) {
        LNN_LOGE(LNN_STATE, "GetUserId failed");
        return false;
    }
    int32_t rc = DpClient::GetInstance().GetSessionKey(localUserId, sessionKeyId, vecSessionKey);
    if (rc != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetSessionKey failed, ret=%{public}d", rc);
        return false;
    }
    std::copy(vecSessionKey.begin(), vecSessionKey.end(), sessionKey);
    *length = vecSessionKey.size();
    return true;
}

void DelSessionKeyProfile(int32_t sessionKeyId)
{
    int32_t localUserId = GetActiveOsAccountIds();
    if (localUserId < 0) {
        LNN_LOGE(LNN_STATE, "GetUserId failed");
        return;
    }
    int32_t rc = DpClient::GetInstance().DeleteSessionKey(localUserId, sessionKeyId);
    if (rc != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "DelSessionKey failed, ret=%{public}d", rc);
    }
}

static bool CompareAssetAclSameAccount(
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile, const AuthACLInfo *acl, bool isSameSide)
{
    std::string itemSourceDeviceId = aclProfile.GetAccesser().GetAccesserDeviceId();
    std::string itemSinkDeviceId = aclProfile.GetAccessee().GetAccesseeDeviceId();
    std::string itemSourceAccountId = aclProfile.GetAccesser().GetAccesserAccountId();
    std::string itemSinkAccountId = aclProfile.GetAccessee().GetAccesseeAccountId();
    if (aclProfile.GetBindType() != (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
        LNN_LOGE(LNN_STATE, "not same account");
        return false;
    }
    if (isSameSide) {
        if (itemSourceDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            itemSourceAccountId.compare(std::string(acl->sourceAccountId)) != 0 ||
            itemSinkAccountId.compare(std::string(acl->sinkAccountId)) != 0 ||
            strcmp(DEFAULT_ACCOUNT_UID, itemSourceAccountId.c_str()) == 0 ||
            strcmp(DEFAULT_ACCOUNT_UID, itemSinkAccountId.c_str()) == 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sourceUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sinkUserId) {
            LNN_LOGE(LNN_STATE, "same side compare fail");
            return false;
        }
        return true;
    } else {
        if (itemSourceDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            itemSourceAccountId.compare(std::string(acl->sinkAccountId)) != 0 ||
            itemSinkAccountId.compare(std::string(acl->sourceAccountId)) != 0 ||
            strcmp(DEFAULT_ACCOUNT_UID, itemSourceAccountId.c_str()) == 0 ||
            strcmp(DEFAULT_ACCOUNT_UID, itemSinkAccountId.c_str()) == 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sinkUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sourceUserId) {
            LNN_LOGE(LNN_STATE, "diff side compare fail");
            return false;
        }
        return true;
    }
}

static bool CompareAssetAclDiffAccountWithUserLevel(
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile, const AuthACLInfo *acl, bool isSameSide)
{
    std::string itemSourceDeviceId = aclProfile.GetAccesser().GetAccesserDeviceId();
    std::string itemSinkDeviceId = aclProfile.GetAccessee().GetAccesseeDeviceId();
    if (aclProfile.GetBindLevel() != (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER) {
        LNN_LOGE(LNN_STATE, "bind level is no user");
        return false;
    }
    if (isSameSide) {
        if (itemSourceDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sourceUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sinkUserId) {
            LNN_LOGE(LNN_STATE, "same side compare fail");
            return false;
        }
        return true;
    } else {
        if (itemSourceDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sinkUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sourceUserId) {
            LNN_LOGE(LNN_STATE, "diff side compare fail");
            return false;
        }
        return true;
    }
}

static bool CompareAssetAclDiffAccount(
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile, const AuthACLInfo *acl, bool isSameSide)
{
    std::string itemSourceDeviceId = aclProfile.GetAccesser().GetAccesserDeviceId();
    std::string itemSinkDeviceId = aclProfile.GetAccessee().GetAccesseeDeviceId();
    if (aclProfile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT ||
        aclProfile.GetBindLevel() == (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER) {
        LNN_LOGE(LNN_STATE, "is same account or user bind level");
        return false;
    }
    if (isSameSide) {
        if (itemSourceDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sourceUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sinkUserId ||
            (int32_t)aclProfile.GetAccesser().GetAccesserTokenId() != (int32_t)acl->sourceTokenId ||
            (int32_t)aclProfile.GetAccessee().GetAccesseeTokenId() != (int32_t)acl->sinkTokenId) {
            LNN_LOGE(LNN_STATE, "same side compare fail");
            return false;
        }
        return true;
    } else {
        if (itemSourceDeviceId.compare(std::string(acl->sinkUdid)) != 0 ||
            itemSinkDeviceId.compare(std::string(acl->sourceUdid)) != 0 ||
            aclProfile.GetAccesser().GetAccesserUserId() != acl->sinkUserId ||
            aclProfile.GetAccessee().GetAccesseeUserId() != acl->sourceUserId ||
            (int32_t)aclProfile.GetAccesser().GetAccesserTokenId() != (int32_t)acl->sinkTokenId ||
            (int32_t)aclProfile.GetAccessee().GetAccesseeTokenId() != (int32_t)acl->sourceTokenId) {
            LNN_LOGE(LNN_STATE, "diff side compare fail");
            return false;
        }
        return true;
    }
}

static bool CompareAssetAllAcl(OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile, const AuthACLInfo *acl,
    bool isSameSide, bool isSameAccount)
{
    if (isSameAccount) {
        return CompareAssetAclSameAccount(aclProfile, acl, isSameSide);
    }
    return CompareAssetAclDiffAccountWithUserLevel(aclProfile, acl, isSameSide) ||
        CompareAssetAclDiffAccount(aclProfile, acl, isSameSide);
}

static void InsertUserKeyToUKCache(const AuthACLInfo *acl, int32_t ukId, uint64_t time, bool isUserBindLevel)
{
    AuthUserKeyInfo userKeyInfo = {};
    AuthACLInfo info = {};
    (void)memset_s(&userKeyInfo, sizeof(AuthUserKeyInfo), 0, sizeof(AuthUserKeyInfo));
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    if (!acl->isServer) {
        info.isServer = !acl->isServer;
        if (strcpy_s(info.sourceUdid, UDID_BUF_LEN, acl->sinkUdid) != EOK ||
            strcpy_s(info.sinkUdid, UDID_BUF_LEN, acl->sourceUdid) != EOK ||
            strcpy_s(info.sourceAccountId, ACCOUNT_ID_BUF_LEN, acl->sinkAccountId) != EOK ||
            strcpy_s(info.sinkAccountId, ACCOUNT_ID_BUF_LEN, acl->sourceAccountId) != EOK) {
            LNN_LOGE(LNN_STATE, "copy info fail");
            return;
        }
        info.sourceUserId = acl->sinkUserId;
        info.sinkUserId = acl->sourceUserId;
        info.sourceTokenId = acl->sinkTokenId;
        info.sinkTokenId = acl->sourceTokenId;
    } else {
        info = *acl;
    }
    userKeyInfo.time = time;
    userKeyInfo.keyIndex = ukId;
    userKeyInfo.keyLen = SESSION_KEY_LENGTH;
    if (GetUserKeyByUkId(ukId, userKeyInfo.deviceKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        std::vector<uint8_t> sessionKey;
        if (DpClient::GetInstance().GetSessionKey(info.sourceUserId, ukId, sessionKey) != OHOS::ERR_OK) {
            LNN_LOGE(LNN_STATE, "getOhosAccountInfo fail");
            return;
        }
        if (SESSION_KEY_LENGTH < sessionKey.size()) {
            LNN_LOGE(LNN_STATE, "cannot memcpy uk, sessionKeyLen=%{public}u", (uint32_t)sessionKey.size());
            sessionKey.clear();
            return;
        }
        for (size_t i = 0; i < sessionKey.size(); ++i) {
            userKeyInfo.deviceKey[i] = sessionKey[i];
        }
        userKeyInfo.keyLen = sessionKey.size();
        sessionKey.clear();
    }
    (void)AuthInsertUserKey(&info, &userKeyInfo, isUserBindLevel);
    (void)memset_s(userKeyInfo.deviceKey, sizeof(userKeyInfo.deviceKey), 0, sizeof(userKeyInfo.deviceKey));
}

static void GetLocalUkIdFromAccess(OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile,
    const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    std::string accesserDeviceId = aclProfile.GetAccesser().GetAccesserDeviceId();
    std::string accesseeDeviceId = aclProfile.GetAccessee().GetAccesseeDeviceId();
    std::string localDeviceId = acl->isServer ? std::string(acl->sourceUdid) : std::string(acl->sinkUdid);
    if (accesserDeviceId.compare(localDeviceId) == 0) {
        *ukId = aclProfile.GetAccesser().GetAccesserSessionKeyId();
        *time = aclProfile.GetAccesser().GetAccesserSKTimeStamp();
    } else if (accesseeDeviceId.compare(localDeviceId) == 0) {
        *ukId = aclProfile.GetAccessee().GetAccesseeSessionKeyId();
        *time = aclProfile.GetAccessee().GetAccesseeSKTimeStamp();
    }
}

static void UpdateAccessProfileSessionKeyId(
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile, int32_t *ukId)
{
    *ukId = DEFAULT_USER_KEY_INDEX;
    OHOS::DistributedDeviceProfile::Accesser accesser(aclProfile.GetAccesser());
    accesser.SetAccesserSessionKeyId(*ukId);
    aclProfile.SetAccesser(accesser);
    OHOS::DistributedDeviceProfile::Accessee accessee(aclProfile.GetAccessee());
    accessee.SetAccesseeSessionKeyId(*ukId);
    aclProfile.SetAccessee(accessee);
    int32_t ret = DpClient::GetInstance().UpdateAccessControlProfile(aclProfile);
    LNN_LOGI(LNN_STATE, "sessionKey is invalid, UpdateAccessControlProfile ret=%{public}d", ret);
}

int32_t GetAccessUkIdSameAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    if (acl == nullptr || ukId == nullptr || time == nullptr) {
        LNN_LOGE(LNN_STATE, "find uk acl is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s",
            aclProfile.GetAccesser().dump().c_str(), aclProfile.GetAccessee().dump().c_str());
        if (!CompareAssetAclSameAccount(aclProfile, acl, acl->isServer)) {
            continue;
        }
        GetLocalUkIdFromAccess(aclProfile, acl, ukId, time);
        if (!AuthIsUkExpired(*time)) {
            UpdateAccessProfileSessionKeyId(aclProfile, ukId);
        } else {
            InsertUserKeyToUKCache(acl, *ukId, *time,
                aclProfile.GetBindLevel() == (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER);
        }
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_STATE, "not find uk");
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

int32_t GetAccessUkIdDiffAccountWithUserLevel(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    if (acl == nullptr || ukId == nullptr || time == nullptr) {
        LNN_LOGE(LNN_STATE, "find uk info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s",
            aclProfile.GetAccesser().dump().c_str(), aclProfile.GetAccessee().dump().c_str());
        if (!CompareAssetAclDiffAccountWithUserLevel(aclProfile, acl, true) &&
            !CompareAssetAclDiffAccountWithUserLevel(aclProfile, acl, false)) {
            continue;
        }
        GetLocalUkIdFromAccess(aclProfile, acl, ukId, time);
        if (!AuthIsUkExpired(*time)) {
            UpdateAccessProfileSessionKeyId(aclProfile, ukId);
        } else {
            InsertUserKeyToUKCache(acl, *ukId, *time,
                aclProfile.GetBindLevel() == (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER);
        }
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_STATE, "not find uk");
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

int32_t GetAccessUkIdDiffAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    if (acl == nullptr || ukId == nullptr || time == nullptr) {
        LNN_LOGE(LNN_STATE, "find uk info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s",
            aclProfile.GetAccesser().dump().c_str(), aclProfile.GetAccessee().dump().c_str());
        if (!CompareAssetAclDiffAccount(aclProfile, acl, true) && !CompareAssetAclDiffAccount(aclProfile, acl, false)) {
            continue;
        }
        GetLocalUkIdFromAccess(aclProfile, acl, ukId, time);
        if (!AuthIsUkExpired(*time)) {
            UpdateAccessProfileSessionKeyId(aclProfile, ukId);
        } else {
            InsertUserKeyToUKCache(acl, *ukId, *time,
                aclProfile.GetBindLevel() == (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER);
        }
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_STATE, "not find uk");
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

int32_t GetAccessUkByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    if (uk == nullptr) {
        LNN_LOGE(LNN_STATE, "uk is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    std::vector<uint8_t> sessionKey;
    int32_t accesserSessionKeyId = 0;
    int32_t accesseeSessionKeyId = 0;
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s",
            aclProfile.GetAccesser().dump().c_str(), aclProfile.GetAccessee().dump().c_str());
        accesserSessionKeyId = aclProfile.GetAccesser().GetAccesserSessionKeyId();
        accesseeSessionKeyId = aclProfile.GetAccessee().GetAccesseeSessionKeyId();
        if (accesserSessionKeyId != sessionKeyId && accesseeSessionKeyId != sessionKeyId) {
            continue;
        }
        uint32_t localUserId = aclProfile.GetAccesser().GetAccesserUserId();
        if (DpClient::GetInstance().GetSessionKey(localUserId, sessionKeyId, sessionKey) != OHOS::ERR_OK) {
            LNN_LOGE(LNN_STATE, "getOhosAccountInfo fail");
            return SOFTBUS_AUTH_ACL_NOT_FOUND;
        }
        if (ukLen < sessionKey.size()) {
            LNN_LOGE(LNN_STATE, "cannot memcpy uk, sessionKeyLen=%{public}u", (uint32_t)sessionKey.size());
            return SOFTBUS_MEM_ERR;
        }
        for (size_t i = 0; i < sessionKey.size(); ++i) {
            uk[i] = sessionKey[i];
        }
        sessionKey.clear();
        LNN_LOGI(LNN_STATE, "user key find");
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_STATE, "user key not found");
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

static UpdateDpAclResult UpdateDpAclByAuthAcl(
    AuthACLInfo *info, int32_t sessionKeyId, uint64_t currentTime, bool isSameAccount)
{
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return GET_ALL_ACL_FAIL;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return GET_ALL_ACL_IS_EMPTY;
    }
    UpdateDpAclResult updateResult = UPDATE_ACL_NOT_MATCH;
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s", aclProfile.GetAccesser().dump().c_str(),
            aclProfile.GetAccessee().dump().c_str());
        if ((CompareAssetAllAcl(aclProfile, info, true, isSameAccount) && info->isServer) ||
            (CompareAssetAllAcl(aclProfile, info, false, isSameAccount) && !info->isServer)) {
            OHOS::DistributedDeviceProfile::Accesser accesser(aclProfile.GetAccesser());
            accesser.SetAccesserSessionKeyId(sessionKeyId);
            accesser.SetAccesserSKTimeStamp(currentTime);
            aclProfile.SetAccesser(accesser);
            ret = DpClient::GetInstance().UpdateAccessControlProfile(aclProfile);
            LNN_LOGI(LNN_STATE, "UpdateAccessControlProfile set accesser ret=%{public}d", ret);
            updateResult = UPDATE_ACL_SUCC;
        } else if ((CompareAssetAllAcl(aclProfile, info, true, isSameAccount) && !info->isServer) ||
            (CompareAssetAllAcl(aclProfile, info, false, isSameAccount) && info->isServer)) {
            OHOS::DistributedDeviceProfile::Accessee accessee(aclProfile.GetAccessee());
            accessee.SetAccesseeSessionKeyId(sessionKeyId);
            accessee.SetAccesseeSKTimeStamp(currentTime);
            aclProfile.SetAccessee(accessee);
            ret = DpClient::GetInstance().UpdateAccessControlProfile(aclProfile);
            LNN_LOGI(LNN_STATE, "UpdateAccessControlProfile set accessee ret=%{public}d", ret);
            updateResult = UPDATE_ACL_SUCC;
        } else {
            continue;
        }
        InsertUserKeyToUKCache(info, sessionKeyId, currentTime,
            aclProfile.GetBindLevel() == (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER);
        LNN_LOGI(LNN_STATE, "find acl");
    }
    return updateResult;
}

void UpdateAssetSessionKeyByAcl(
    AuthACLInfo *info, const uint8_t *sessionKey, uint32_t sessionKeyLen, int32_t *sessionKeyId, bool isSameAccount)
{
    if (info == nullptr) {
        LNN_LOGE(LNN_STATE, "acl info is null");
        return;
    }
    UpdateDpAclResult ret = UPDATE_ACL_SUCC;
    uint64_t currentTime = SoftBusGetSysTimeMs();

    if (!info->isServer) {
        ret = PutDpAclUkByUserId(info->sinkUserId, sessionKey, sessionKeyLen, sessionKeyId);
    } else {
        ret = PutDpAclUkByUserId(info->sourceUserId, sessionKey, sessionKeyLen, sessionKeyId);
    }
    if (ret != UPDATE_ACL_SUCC) {
        LNN_LOGW(LNN_STATE, "PutDpAclUkByUserId failed, ret=%{public}d", ret);
        //fall-through: Possible failure, do not handle abnormal scenarios.
    }
    ret = UpdateDpAclByAuthAcl(info, *sessionKeyId, currentTime, isSameAccount);
    LNN_LOGW(LNN_STATE, "UpdateDpAclByAuthAcl result ret=%{public}d", ret);
    return;
}

static bool IsSKIdInvalidInner(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash,
    int32_t userId, OHOS::DistributedDeviceProfile::AccessControlProfile &aclProfile)
{
    std::string sourceDeviceId = aclProfile.GetAccesser().GetAccesserDeviceId();
    std::string sourceAccountId = aclProfile.GetAccesser().GetAccesserAccountId();
    std::string sinkDeviceId = aclProfile.GetAccessee().GetAccesseeDeviceId();
    std::string sinkAccountId = aclProfile.GetAccessee().GetAccesseeAccountId();
    char aclUdidShortHash[SHA_256_HEX_HASH_LEN] = { 0 };
    char aclAccountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (strcmp(DEFAULT_ACCOUNT_UID, sourceAccountId.c_str()) == 0) {
        (void)GetStringHash(DEFAULT_ACCOUNT_VALUE, aclAccountHash, SHA_256_HEX_HASH_LEN - 1);
        sourceAccountId = aclAccountHash;
    }
    if (strcmp(DEFAULT_ACCOUNT_UID, sinkAccountId.c_str()) == 0) {
        (void)GetStringHash(DEFAULT_ACCOUNT_VALUE, aclAccountHash, SHA_256_HEX_HASH_LEN - 1);
        sinkAccountId = aclAccountHash;
    }
    if (aclProfile.GetAccesser().GetAccesserSessionKeyId() == sessionKeyId) {
        if (GetStringHash(sinkDeviceId, aclUdidShortHash, CUST_UDID_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "GetStringHash fail");
            return false;
        }
        if (StrCmpIgnoreCase(aclUdidShortHash, udidShortHash) != 0 ||
            StrCmpIgnoreCase(sinkAccountId.c_str(), accountHash) != 0 ||
            userId != aclProfile.GetAccessee().GetAccesseeUserId()) {
            LNN_LOGE(LNN_STATE, "accountId/udid/userId error");
            return true;
        }
        return false;
    } else if (aclProfile.GetAccessee().GetAccesseeSessionKeyId() == sessionKeyId) {
        if (GetStringHash(sourceDeviceId, aclUdidShortHash, CUST_UDID_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "GetStringHash fail");
            return false;
        }
        if (StrCmpIgnoreCase(aclUdidShortHash, udidShortHash) != 0 ||
            StrCmpIgnoreCase(sourceAccountId.c_str(), accountHash) != 0 ||
            userId != aclProfile.GetAccesser().GetAccesserUserId()) {
            LNN_LOGE(LNN_STATE, "accountId/udid/userId error");
            return true;
        }
        return false;
    }
    LNN_LOGE(LNN_STATE, "skId not match!");
    return true;
}

bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash, int32_t userId)
{
    if (accountHash == nullptr || udidShortHash == nullptr || strlen(udidShortHash) < CUST_UDID_LEN ||
        strlen(accountHash) < SHA_256_HEX_HASH_LEN - 1) {
        LNN_LOGE(LNN_STATE, "param error");
        return false;
    }

    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return false;
    }
    if (aclProfiles.empty()) {
        LNN_LOGE(LNN_STATE, "aclProfiles is empty");
        return true;
    }
    int32_t accesserSessionKeyId = 0;
    int32_t accesseeSessionKeyId = 0;
    for (auto &aclProfile : aclProfiles) {
        LNN_LOGI(LNN_STATE, "GetAccesser=%{public}s, GetAccessee=%{public}s",
            aclProfile.GetAccesser().dump().c_str(), aclProfile.GetAccessee().dump().c_str());
        accesserSessionKeyId = aclProfile.GetAccesser().GetAccesserSessionKeyId();
        accesseeSessionKeyId = aclProfile.GetAccessee().GetAccesseeSessionKeyId();
        if (accesserSessionKeyId != sessionKeyId && accesseeSessionKeyId != sessionKeyId) {
            continue;
        }
        return IsSKIdInvalidInner(sessionKeyId, accountHash, udidShortHash, userId, aclProfile);
    }
    LNN_LOGE(LNN_STATE, "key not found");
    return true;
}

int32_t SelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num)
{
    if (num == nullptr || trustedInfoArray == nullptr) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> aclProfiles;
    int32_t ret = DpClient::GetInstance().GetAllAccessControlProfile(aclProfiles);
    if (ret != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        LNN_LOGE(LNN_STATE, "GetAllAccessControlProfile ret=%{public}d", ret);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    if (aclProfiles.empty()) {
        LNN_LOGI(LNN_STATE, "aclProfiles is empty");
        return SOFTBUS_OK;
    }
    int32_t localUserId = GetActiveOsAccountIds();
    std::unordered_set<std::string> matchAcl;
    for (auto &aclProfile : aclProfiles) {
        if (aclProfile.GetDeviceIdType() != (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID ||
            aclProfile.GetTrustDeviceId().empty() || GetAclLocalUserId(aclProfile) != localUserId ||
            aclProfile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
            continue;
        }
        char *anonyUdid = nullptr;
        Anonymize(aclProfile.GetTrustDeviceId().c_str(), &anonyUdid);
        LNN_LOGI(LNN_STATE, "trusted dev info, udid=%{public}s, localUserId=%{public}d",
            AnonymizeWrapper(anonyUdid), GetAclLocalUserId(aclProfile));
        AnonymizeFree(anonyUdid);
        matchAcl.insert(aclProfile.GetTrustDeviceId());
    }
    if (matchAcl.empty()) {
        LNN_LOGI(LNN_STATE, "matchAcl is empty");
        return SOFTBUS_OK;
    }
    *trustedInfoArray = (TrustedInfo *)SoftBusCalloc(matchAcl.size() * sizeof(TrustedInfo));
    if (*trustedInfoArray == nullptr) {
        LNN_LOGE(LNN_STATE, "malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    for (auto item : matchAcl)  {
        if (strcpy_s(((*trustedInfoArray) + (*num))->udid, UDID_BUF_LEN, item.c_str()) != EOK) {
            LNN_LOGE(LNN_STATE, "udid str cpy fail");
            SoftBusFree(*trustedInfoArray);
            return SOFTBUS_STRCPY_ERR;
        }
        ((*trustedInfoArray) + (*num))->userId = localUserId;
        (*num)++;
    }
    return SOFTBUS_OK;
}
