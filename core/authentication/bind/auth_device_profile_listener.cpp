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

#include "auth_deviceprofile.h"
#include "auth_log.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "lnn_heartbeat_ctrl.h"
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

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileAdd(const TrustDeviceProfile &profile)
{
    AUTH_LOGI(AUTH_INIT, "OnTrustDeviceProfileAdd start!");
    if (profile.GetBindType() == (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT) {
        AUTH_LOGI(AUTH_INIT, "ignore same account udid");
        return SOFTBUS_OK;
    }
    if (g_deviceProfileChange.onDeviceProfileAdd == NULL) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileAdd failed!");
        return SOFTBUS_ERR;
    }
    DelNotTrustDevice(profile.GetDeviceId().c_str());
    g_deviceProfileChange.onDeviceProfileAdd(profile.GetDeviceId().c_str(), NULL);
    AUTH_LOGD(AUTH_INIT, "OnTrustDeviceProfileAdd success!");
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileListener::OnTrustDeviceProfileDelete(const TrustDeviceProfile &profile)
{
    AUTH_LOGI(AUTH_INIT, "OnTrustDeviceProfileDelete start!");
    if (g_deviceProfileChange.onDeviceProfileDeleted == NULL) {
        AUTH_LOGE(AUTH_INIT, "OnTrustDeviceProfileDelete failed!");
        return SOFTBUS_ERR;
    }
    g_deviceProfileChange.onDeviceProfileDeleted(profile.GetDeviceId().c_str());
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
    AUTH_LOGI(AUTH_INIT, "dp active callback enter!");
    DelNotTrustDevice(profile.GetDeviceId().c_str());
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
    AUTH_LOGI(AUTH_INIT, "dp inactive callback enter!");
    LnnUpdateOhosAccount(true);
    int32_t userId = profile.GetPeerUserId();
    AUTH_LOGI(AUTH_INIT, "userId:%{public}d", userId);
    NotifyRemoteDevOffLineByUserId(userId, profile.GetDeviceId().c_str());

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

static void RegisterToDpHelper(void)
{
    AUTH_LOGD(AUTH_INIT, "RegistertoDpHelper start!");
    uint32_t saId = SOFTBUS_SA_ID;
    std::string subscribeKey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = { ProfileChangeType::TRUST_DEVICE_PROFILE_ADD,
        ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE, ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE,
        ProfileChangeType::TRUST_DEVICE_PROFILE_ACTIVE, ProfileChangeType::TRUST_DEVICE_PROFILE_INACTIVE};

    sptr<IProfileChangeListener> subscribeDPChangeListener = new (std::nothrow) AuthDeviceProfileListener;
    if (subscribeDPChangeListener == nullptr) {
        AUTH_LOGE(AUTH_INIT, "new authDeviceProfileListener fail");
        return;
    }
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);

    int32_t subscribeRes = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscribeInfo);
    AUTH_LOGI(AUTH_INIT, "GetCharacteristicProfile subscribeRes=%{public}d", subscribeRes);
}
} // namespace AuthToDeviceProfile
} // namespace OHOS

void RegisterToDp(DeviceProfileChangeListener *deviceProfilePara)
{
    if (deviceProfilePara == nullptr) {
        AUTH_LOGE(AUTH_INIT, "invalid param!");
        return;
    }
    g_deviceProfileChange = *deviceProfilePara;
    OHOS::AuthToDeviceProfile::RegisterToDpHelper();
}

