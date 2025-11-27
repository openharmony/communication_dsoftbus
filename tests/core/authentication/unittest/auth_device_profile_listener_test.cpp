/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "auth_device_profile_listener.h"
#include "auth_device_profile_listener_mock.h"
#include "auth_deviceprofile.h"
#include "auth_log.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "softbus_error_code.h"
#include "trust_device_profile.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
std::unique_ptr<AuthToDeviceProfile::AuthDeviceProfileListener> listener;
class AuthDeviceProfileListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthDeviceProfileListenerTest::SetUpTestCase()
{
    listener = std::make_unique<AuthToDeviceProfile::AuthDeviceProfileListener>();
}

void AuthDeviceProfileListenerTest::TearDownTestCase()
{
    listener.reset();
}

void AuthDeviceProfileListenerTest::SetUp() { }

void AuthDeviceProfileListenerTest::TearDown() { }

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)udid;
    (void)groupInfo;
}

static void OnDeviceNotTrusted(const char *udid, int32_t localUserId)
{
    (void)udid;
    (void)localUserId;
}

static DeviceProfileChangeListener g_deviceProfilePara = {
    .onDeviceProfileAdd = OnDeviceBound,
    .onDeviceProfileDeleted = OnDeviceNotTrusted,
};

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST_001
 * @tc.desc: Verify that OnTrustDeviceProfileAdd successfully handles adding a TrustDeviceProfile
 *           with a SAME_ACCOUNT bind type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_ADD_TEST_001, TestSize.Level1)
{
    AuthToDeviceProfile::TrustDeviceProfile profile;
    profile.SetBindType((uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT);
    int32_t ret = listener->OnTrustDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST_002
 * @tc.desc: Verify that OnTrustDeviceProfileAdd handles cases where onDeviceProfileAdd callback
 *           is null, returning an error.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_ADD_TEST_002, TestSize.Level1)
{
    AuthToDeviceProfile::TrustDeviceProfile profile;
    g_deviceProfilePara.onDeviceProfileAdd = nullptr;
    RegisterToDp(&g_deviceProfilePara);
    int32_t ret = listener->OnTrustDeviceProfileAdd(profile);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST_003
 * @tc.desc: Verify that OnTrustDeviceProfileAdd successfully handles adding a TrustDeviceProfile
 *           when a valid OnDeviceBound callback is registered.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_ADD_TEST_003, TestSize.Level1)
{
    g_deviceProfilePara.onDeviceProfileAdd = OnDeviceBound;
    RegisterToDp(&g_deviceProfilePara);
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = listener->OnTrustDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_DELETE_TEST_001
 * @tc.desc: Verify that OnTrustDeviceProfileDelete successfully handles deleting a
 *           TrustDeviceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_DELETE_TEST_001, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    AuthToDeviceProfile::TrustDeviceProfile profile;
    AuthDeviceProfileListenerInterfaceMock mocker;
    int32_t ret = listener->OnTrustDeviceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_DELETE_TEST_002
 * @tc.desc: Verify that OnTrustDeviceProfileDelete handles cases where onDeviceProfileDeleted
 *           callback is null, returning an error.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_DELETE_TEST_002, TestSize.Level1)
{
    RegisterToDp(nullptr);
    AuthToDeviceProfile::TrustDeviceProfile profile;
    g_deviceProfilePara.onDeviceProfileDeleted = nullptr;
    RegisterToDp(&g_deviceProfilePara);
    int32_t ret = listener->OnTrustDeviceProfileDelete(profile);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_UPDATE_TEST
 * @tc.desc: Verify that OnTrustDeviceProfileUpdate successfully handles updating a
 *           TrustDeviceProfile, including cases with null profiles.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_UPDATE_TEST, TestSize.Level1)
{
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = listener->OnTrustDeviceProfileUpdate(profile, profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_DEVICE_PROFILE_ADD_TEST
 * @tc.desc: Verify that OnDeviceProfileAdd successfully handles adding a DeviceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_DEVICE_PROFILE_ADD_TEST, TestSize.Level1)
{
    AuthToDeviceProfile::DeviceProfile profile;
    int32_t ret = listener->OnDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_DEVICE_PROFILE_DELETE_TEST
 * @tc.desc: Verify that OnDeviceProfileDelete successfully handles deleting a DeviceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_DEVICE_PROFILE_DELETE_TEST, TestSize.Level1)
{
    AuthToDeviceProfile::DeviceProfile profile;
    int32_t ret = listener->OnDeviceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_DEVICE_PROFILE_UPDATE_TEST
 * @tc.desc: Verify that OnDeviceProfileUpdate successfully handles updating a DeviceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_DEVICE_PROFILE_UPDATE_TEST, TestSize.Level1)
{
    AuthToDeviceProfile::DeviceProfile profile;
    int32_t ret = listener->OnDeviceProfileUpdate(profile, profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_SERVICE_PROFILE_ADD_TEST
 * @tc.desc: Verify that OnServiceProfileAdd successfully handles adding a ServiceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_SERVICE_PROFILE_ADD_TEST, TestSize.Level1)
{
    AuthToDeviceProfile::ServiceProfile profile;
    int32_t ret = listener->OnServiceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_SERVICE_PROFILE_DELETE_TEST
 * @tc.desc: Verify that OnServiceProfileDelete successfully handles deleting a ServiceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_SERVICE_PROFILE_DELETE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::ServiceProfile profile;
    int32_t ret = listener->OnServiceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_SERVICE_PROFILE_UPDATE_TEST
 * @tc.desc: Verify that OnServiceProfileUpdate successfully handles updating a ServiceProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_SERVICE_PROFILE_UPDATE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::ServiceProfile profile;
    int32_t ret = listener->OnServiceProfileUpdate(profile, profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_CHARACTERISTIC_PROFILE_ADD_TEST
 * @tc.desc: Verify that OnCharacteristicProfileAdd successfully handles adding a
 *           CharacteristicProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_CHARACTERISTIC_PROFILE_ADD_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::CharacteristicProfile profile;
    int32_t ret = listener->OnCharacteristicProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_CHARACTERISTIC_PROFILE_DELETE_TEST
 * @tc.desc: Verify that OnCharacteristicProfileDelete successfully handles deleting a
 *           CharacteristicProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_CHARACTERISTIC_PROFILE_DELETE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::CharacteristicProfile profile;
    int32_t ret = listener->OnCharacteristicProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_CHARACTERISTIC_PROFILE_UPDATE_TEST
 * @tc.desc: Verify that OnCharacteristicProfileUpdate successfully handles updating a
 *           CharacteristicProfile.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_CHARACTERISTIC_PROFILE_UPDATE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::CharacteristicProfile profile;
    int32_t ret = listener->OnCharacteristicProfileUpdate(profile, profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ACTIVE_TEST
 * @tc.desc: Verify that OnTrustDeviceProfileActive correctly handles device profile activation,
 *           including screen state and heartbeat feature checks.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_ACTIVE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::TrustDeviceProfile profile;
    AuthDeviceProfileListenerInterfaceMock mocker;
    EXPECT_CALL(mocker, GetScreenState).WillRepeatedly(Return(SOFTBUS_SCREEN_OFF));
    EXPECT_CALL(mocker, LnnIsLocalSupportBurstFeature).WillOnce(Return(false));
    int32_t ret = listener->OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, LnnIsLocalSupportBurstFeature).WillOnce(Return(true));
    EXPECT_CALL(mocker, IsHeartbeatEnable).WillOnce(Return(true));
    EXPECT_CALL(mocker, LnnStartHbByTypeAndStrategy).WillOnce(Return(SOFTBUS_NETWORK_POST_MSG_FAIL));
    ret = listener->OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_INACTIVE_TEST
 * @tc.desc: Verify that OnTrustDeviceProfileInactive correctly handles device profile
 *           deactivation.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_INACTIVE_TEST, TestSize.Level1)
{
    AuthDeviceProfileListenerInterfaceMock mocker;
    DistributedDeviceProfile::TrustDeviceProfile profile;
    EXPECT_CALL(mocker, LnnIsLocalSupportBurstFeature).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = listener->OnTrustDeviceProfileInactive(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
