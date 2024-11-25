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

#ifndef AUTH_DEVICE_PROFILE_LISTENER_H
#define AUTH_DEVICE_PROFILE_LISTENER_H

#include "softbus_error_code.h"

#include "distributed_device_profile_client.h"
#include "i_profile_change_listener.h"
#include "profile_change_listener_stub.h"
#include "service_profile.h"

namespace OHOS {
namespace AuthToDeviceProfile {
using namespace OHOS::DistributedDeviceProfile;

class AuthDeviceProfileListener : public ProfileChangeListenerStub {
public:
    AuthDeviceProfileListener();
    ~AuthDeviceProfileListener();
    int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile &profile);
    int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile &profile);
    int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile &oldProfile, const TrustDeviceProfile &newProfile);
    int32_t OnTrustDeviceProfileActive(const TrustDeviceProfile &profile);
    int32_t OnTrustDeviceProfileInactive(const TrustDeviceProfile &profile);
    int32_t OnDeviceProfileAdd(const DeviceProfile &profile);
    int32_t OnDeviceProfileDelete(const DeviceProfile &profile);
    int32_t OnDeviceProfileUpdate(const DeviceProfile &oldProfile, const DeviceProfile &newProfile);
    int32_t OnServiceProfileAdd(const ServiceProfile &profile);
    int32_t OnServiceProfileDelete(const ServiceProfile &profile);
    int32_t OnServiceProfileUpdate(const ServiceProfile &oldProfile, const ServiceProfile &newProfile);
    int32_t OnCharacteristicProfileAdd(const CharacteristicProfile &profile);
    int32_t OnCharacteristicProfileDelete(const CharacteristicProfile &prpfile);
    int32_t OnCharacteristicProfileUpdate(
        const CharacteristicProfile &oldProfile, const CharacteristicProfile &newProfile);
};
} // namespace AuthToDeviceProfile
} // namespace OHOS
#endif

