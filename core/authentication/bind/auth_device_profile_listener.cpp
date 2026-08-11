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

#include "auth_device_profile_listener.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_deviceprofile.h"
#include "auth_log.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_decision_db.h"
#include "lnn_device_info_struct.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_network_info.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account.h"

static const uint32_t SOFTBUS_SA_ID = 4700;
static DeviceProfileChangeListener g_deviceProfileChange = { 0 };

namespace OHOS {
namespace AuthToDeviceProfile {
using namespace OHOS::DistributedDeviceProfile;

AuthDeviceProfileListener::AuthDeviceProfileListener()
{
    AUTH_LOGI(AUTH_INIT, "construct!");
}

AuthDeviceProfileListener::~AuthDeviceProfileListener()
{
    AUTH_LOGI(AUTH_INIT, "destruct");
}

static bool IsSingleFrameCarDeviceExist(const char *udid)
{
    int32_t localDevTypeId = TYPE_UNKNOW_ID;
    int32_t localOsType = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) == SOFTBUS_OK &&
        LnnGetLocalNumInfo(NUM_KEY_OS_TYPE, &localOsType) == SOFTBUS_OK &&
        localDevTypeId == TYPE_CAR_ID && localOsType == OH_OS_TYPE) {
        return true;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, &nodeInfo) != SOFTBUS_OK) {
        return false;
    }
    if (nodeInfo.deviceInfo.deviceTypeId == TYPE_CAR_ID && nodeInfo.deviceInfo.osType == OH_OS_TYPE) {
        return true;
    }
    return false;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileAdd(const TrustDeviceProfile &profile)
{
    AUTH_LOGI(AUTH_INIT, "OnTrustDeviceProfileAdd start!");
    if (profile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
        AUTH_LOGI(AUTH_INIT, "ignore same account udid");
        return SOFTBUS_OK;
    }
    if (g_deviceProfileChange.onDeviceProfileAdd == nullptr) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileAdd failed!");
        return SOFTBUS_AUTH_DP_CHANGE_LISTENER_INVALID;
    }
    DelNotTrustDevice(profile.GetDeviceId().c_str());
    g_deviceProfileChange.onDeviceProfileAdd(profile.GetDeviceId().c_str(), nullptr);
    AUTH_LOGD(AUTH_INIT, "OnTrustDeviceProfileAdd success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileDelete(const TrustDeviceProfile &profile)
{
    std::string deviceId = profile.GetDeviceId();
    if (deviceId.empty()) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileDelete udid is empty!");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = deviceId.c_str();
    char *anonyUdid = nullptr;
    Anonymize(udid, &anonyUdid);
    AUTH_LOGI(AUTH_INIT, "OnTrustDeviceProfileDelete start! "
        "udid=%{public}s, localUserId=%{public}d, peerUserId=%{public}d",
        AnonymizeWrapper(anonyUdid), profile.GetLocalUserId(), profile.GetPeerUserId());
    AnonymizeFree(anonyUdid);
    if (IsSingleFrameCarDeviceExist(udid)) {
        AUTH_LOGI(AUTH_INIT, "single frame car skip");
        return SOFTBUS_OK;
    }
    if (g_deviceProfileChange.onDeviceProfileDeleted == nullptr) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileDelete failed!");
        return SOFTBUS_AUTH_DP_CHANGE_LISTENER_INVALID;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, &nodeInfo);
    if (ret == SOFTBUS_OK && nodeInfo.localUserId != 0 && profile.GetLocalUserId() != nodeInfo.localUserId) {
        AUTH_LOGE(AUTH_INIT, "delete deviceprofile not current user");
        if (!DpHasAccessControlProfile(udid, true, profile.GetLocalUserId())) {
            LnnDeleteSpecificTrustedDevInfo(udid);
        }
        return SOFTBUS_OK;
    }
    if (ret == SOFTBUS_OK && nodeInfo.userId != 0 &&
        nodeInfo.userId != profile.GetPeerUserId()) {
        AUTH_LOGE(AUTH_INIT, "no match peer user");
        return SOFTBUS_OK;
    }
    g_deviceProfileChange.onDeviceProfileDeleted(
        profile.GetDeviceId().c_str(), profile.GetLocalUserId(), DP_USER_TYPE);
    AUTH_LOGD(AUTH_INIT, "OnTrustDeviceProfileDelete success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileUpdate(
    const TrustDeviceProfile &oldProfile, const TrustDeviceProfile &newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    AUTH_LOGI(AUTH_INIT, "OnTrustDeviceProfileUpdate success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileActive(const TrustDeviceProfile &profile)
{
    std::string deviceId = profile.GetDeviceId();
    if (deviceId.empty()) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileActive udid is empty!");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = deviceId.c_str();
    char *anonyUdid = nullptr;
    Anonymize(udid, &anonyUdid);
    AUTH_LOGI(AUTH_INIT, "dp active callback enter! udid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    DelNotTrustDevice(udid);
    if (GetScreenState() == SOFTBUS_SCREEN_OFF && !LnnIsLocalSupportBurstFeature()) {
        AUTH_LOGI(AUTH_INIT, "screen off and not support burst. no need online");
        return SOFTBUS_OK;
    }
    if (IsHeartbeatEnable()) {
        if (LnnStartHbByTypeAndStrategy(
            HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_INIT, "start ble heartbeat fail");
            }
    }
    RestartCoapDiscovery();

    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileInactive(const TrustDeviceProfile &profile)
{
    std::string deviceId = profile.GetDeviceId();
    if (deviceId.empty()) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileInactive udid is empty!");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = deviceId.c_str();
    char *anonyUdid = nullptr;
    Anonymize(udid, &anonyUdid);
    AUTH_LOGI(AUTH_INIT, "dp inactive callback enter! udid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    if (IsSingleFrameCarDeviceExist(udid)) {
        AUTH_LOGI(AUTH_INIT, "single frame car skip");
        return SOFTBUS_OK;
    }
    int32_t userId = profile.GetPeerUserId();
    AUTH_LOGI(AUTH_INIT, "userId:%{public}d", userId);
    NotifyRemoteDevOffLineByUserId(userId, udid);

    return SOFTBUS_OK;
}

static bool GetUdidFromProfile(const TrustDeviceProfile &profile, const char *callbackName,
    std::string &deviceId)
{
    deviceId = profile.GetDeviceId();
    if (deviceId.empty()) {
        AUTH_LOGE(AUTH_INIT, "%{public}s udid is empty!", callbackName);
        return false;
    }
    char *anonyUdid = nullptr;
    Anonymize(deviceId.c_str(), &anonyUdid);
    AUTH_LOGI(AUTH_INIT, "%{public}s start! udid=%{public}s, localUserId=%{public}d, peerUserId=%{public}d",
        callbackName, AnonymizeWrapper(anonyUdid), profile.GetLocalUserId(), profile.GetPeerUserId());
    AnonymizeFree(anonyUdid);
    return true;
}

static void HandleDeviceAclInactive(const char *callbackName, const char *udid, int32_t localUserId)
{
    if (!IsSingleFrameCarDeviceExist(udid)) {
        AUTH_LOGI(AUTH_INIT, "%{public}s skip non-both-single-frame-car", callbackName);
        return;
    }
    if (g_deviceProfileChange.onDeviceProfileDeleted != nullptr) {
        g_deviceProfileChange.onDeviceProfileDeleted(udid, localUserId, DP_DEVICE_TYPE);
    }
    AUTH_LOGD(AUTH_INIT, "%{public}s success!", callbackName);
}

static void HandleAccountAclAvailable(const char *callbackName, const char *udid)
{
    DelNotTrustDevice(udid);
    if (g_deviceProfileChange.onDeviceProfileAdd != nullptr) {
        g_deviceProfileChange.onDeviceProfileAdd(udid, nullptr);
    }
    AUTH_LOGD(AUTH_INIT, "%{public}s success!", callbackName);
}

static void NotifyServiceIdListIfNeeded(const char *udid, const TrustDeviceProfile &profile)
{
    std::vector<int64_t> serviceIdList = profile.GetServiceIdList();
    if (!serviceIdList.empty()) {
        LnnNotifyAccountAclChangeEvent(udid, profile.GetLocalUserId(), profile.GetPeerUserId(),
            serviceIdList.data(), static_cast<uint32_t>(serviceIdList.size()));
    }
}

int32_t AuthDeviceProfileListener::OnDeviceAclInactiveByDelete(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnDeviceAclInactiveByDelete", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    HandleDeviceAclInactive("OnDeviceAclInactiveByDelete", deviceId.c_str(), profile.GetLocalUserId());
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnDeviceAclInactiveByUpdate(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnDeviceAclInactiveByUpdate", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    HandleDeviceAclInactive("OnDeviceAclInactiveByUpdate", deviceId.c_str(), profile.GetLocalUserId());
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnAccountAclDelete(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnAccountAclDelete", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsSingleFrameCarDeviceExist(deviceId.c_str())) {
        AUTH_LOGI(AUTH_INIT, "OnAccountAclDelete skip non-single-frame-car");
        return SOFTBUS_OK;
    }
    NotifyServiceIdListIfNeeded(deviceId.c_str(), profile);
    AUTH_LOGD(AUTH_INIT, "OnAccountAclDelete success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnAccountAclInactive(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnAccountAclInactive", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsSingleFrameCarDeviceExist(deviceId.c_str())) {
        AUTH_LOGI(AUTH_INIT, "OnAccountAclInactive skip non-single-frame-car");
        return SOFTBUS_OK;
    }
    NotifyServiceIdListIfNeeded(deviceId.c_str(), profile);
    AUTH_LOGD(AUTH_INIT, "OnAccountAclInactive success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnAccountAclAdd(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnAccountAclAdd", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (profile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
        AUTH_LOGI(AUTH_INIT, "OnAccountAclAdd skip same account");
        return SOFTBUS_OK;
    }
    HandleAccountAclAvailable("OnAccountAclAdd", deviceId.c_str());
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnAccountAclActive(const TrustDeviceProfile &profile)
{
    std::string deviceId;
    if (!GetUdidFromProfile(profile, "OnAccountAclActive", deviceId)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (profile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
        AUTH_LOGI(AUTH_INIT, "OnAccountAclActive skip same account");
        return SOFTBUS_OK;
    }
    HandleAccountAclAvailable("OnAccountAclActive", deviceId.c_str());
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnDeviceProfileAdd(const DeviceProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnDeviceProfileDelete(const DeviceProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnDeviceProfileUpdate(
    const DeviceProfile &oldProfile, const DeviceProfile &newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnServiceProfileAdd(const ServiceProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnServiceProfileDelete(const ServiceProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnServiceProfileUpdate(
    const ServiceProfile &oldProfile, const ServiceProfile &newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnCharacteristicProfileAdd(const CharacteristicProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnCharacteristicProfileDelete(const CharacteristicProfile &profile)
{
    (void)profile;
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnCharacteristicProfileUpdate(
    const CharacteristicProfile &oldProfile, const CharacteristicProfile &newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return SOFTBUS_OK;
}

static int32_t RegisterToDpHelper(void)
{
    AUTH_LOGD(AUTH_INIT, "RegistertoDpHelper start!");
    uint32_t saId = SOFTBUS_SA_ID;
    std::string subscribeKey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = { ProfileChangeType::TRUST_DEVICE_PROFILE_ADD,
        ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE, ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE,
        ProfileChangeType::TRUST_DEVICE_PROFILE_ACTIVE, ProfileChangeType::TRUST_DEVICE_PROFILE_INACTIVE,
        ProfileChangeType::DEVICE_ACL_INACTIVE_BY_DELETE, ProfileChangeType::DEVICE_ACL_INACTIVE_BY_UPDATE,
        ProfileChangeType::ACCOUNT_ACL_DELETE, ProfileChangeType::ACCOUNT_ACL_INACTIVE,
        ProfileChangeType::ACCOUNT_ACL_ADD, ProfileChangeType::ACCOUNT_ACL_ACTIVE, };

    sptr<IProfileChangeListener> subscribeDPChangeListener = new (std::nothrow) AuthDeviceProfileListener;
    if (subscribeDPChangeListener == nullptr) {
        AUTH_LOGE(AUTH_INIT, "new authDeviceProfileListener fail");
        return SOFTBUS_MEM_ERR;
    }
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);

    int32_t subscribeRes = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscribeInfo);
    if (subscribeRes != OHOS::DistributedDeviceProfile::DP_SUCCESS) {
        AUTH_LOGE(AUTH_INIT, "GetCharacteristicProfile subscribeRes failed, ret=%{public}d", subscribeRes);
        return SOFTBUS_AUTH_SUB_DP_FAILED;
    }
    return SOFTBUS_OK;
}
} // namespace AuthToDeviceProfile
} // namespace OHOS

int32_t RegisterToDp(DeviceProfileChangeListener *deviceProfilePara)
{
    if (deviceProfilePara == nullptr) {
        AUTH_LOGE(AUTH_INIT, "invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    g_deviceProfileChange = *deviceProfilePara;
    return OHOS::AuthToDeviceProfile::RegisterToDpHelper();
}
