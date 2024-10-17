/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "auth_device_profile_listener_mock.h"
#include "auth_device_profile_listener.h"
#include "auth_deviceprofile.h"
#include <gtest/gtest.h>

#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "auth_log.h"
#include "softbus_errcode.h"
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

static void OnDeviceNotTrusted(const char *udid)
{
    (void)udid;
}

static DeviceProfileChangeListener g_deviceProfilePara = {
    .onDeviceProfileAdd = OnDeviceBound,
    .onDeviceProfileDeleted = OnDeviceNotTrusted,
};

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST
 * @tc.desc: test bindType is SAME_ACCOUNT.
 * @tc.type: FUNC
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
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST
 * @tc.desc: test onDeviceProfileAdd is null
 * @tc.type: FUNC
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
 * @tc.name: ON_TRUST_DEVICE_PROFILE_ADD_TEST
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_ADD_TEST_003, TestSize.Level1)
{
    AuthDeviceProfileListenerInterfaceMock mocker;
    EXPECT_CALL(mocker, DelNotTrustDevice).Times(1);
    g_deviceProfilePara.onDeviceProfileAdd = OnDeviceBound;
    RegisterToDp(&g_deviceProfilePara);
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = listener->OnTrustDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}


/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_DELETE_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_TRUST_DEVICE_PROFILE_DELETE_TEST_001, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = listener->OnTrustDeviceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_TRUST_DEVICE_PROFILE_DELETE_TEST_002
 * @tc.desc: test onDeviceProfileDeleted is null
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
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
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileListenerTest, ON_CHARACTERISTIC_PROFILE_UPDATE_TEST, TestSize.Level1)
{
    DistributedDeviceProfile::CharacteristicProfile profile;
    int32_t ret = listener->OnCharacteristicProfileUpdate(profile, profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
