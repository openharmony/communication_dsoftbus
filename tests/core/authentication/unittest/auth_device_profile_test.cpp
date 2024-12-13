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

#include "auth_device_profile_listener.h"
#include "auth_deviceprofile.h"
#include <gtest/gtest.h>

#include "auth_log.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "softbus_error_code.h"
#include "trust_device_profile.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthDeviceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthDeviceProfileTest::SetUpTestCase() { }

void AuthDeviceProfileTest::TearDownTestCase() { }

void AuthDeviceProfileTest::SetUp() { }

void AuthDeviceProfileTest::TearDown() { }

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)udid;
    (void)groupInfo;
    AUTH_LOGI(AUTH_TEST, "deviceBound success!");
}

static void OnDeviceNotTrusted(const char *udid, int32_t localUserId)
{
    (void)udid;
    (void)localUserId;
    AUTH_LOGI(AUTH_TEST, "device is not trusted!");
}

static DeviceProfileChangeListener g_deviceProfilePara = {
    .onDeviceProfileAdd = OnDeviceBound,
    .onDeviceProfileDeleted = OnDeviceNotTrusted,
};

/*
 * @tc.name: TRUST_DEVICE_PROFILE_ADD_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, TRUST_DEVICE_PROFILE_ADD_TEST_001, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    std::unique_ptr<AuthToDeviceProfile::AuthDeviceProfileListener> myFunc_ =
        std::make_unique<AuthToDeviceProfile::AuthDeviceProfileListener>();
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = myFunc_->OnTrustDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TRUST_DEVICE_PROFILE_DELETE_TEST_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, TRUST_DEVICE_PROFILE_DELETE_TEST_002, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    std::unique_ptr<AuthToDeviceProfile::AuthDeviceProfileListener> myFunc_ =
        std::make_unique<AuthToDeviceProfile::AuthDeviceProfileListener>();
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = myFunc_->OnTrustDeviceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IS_POTENTIAL_TRUSTED_DEVCIE_TEST_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_POTENTIAL_DEVCIE_TEST_003, TestSize.Level1)
{
    const char *deviceIdHash = nullptr;
    bool ret = IsPotentialTrustedDeviceDp(deviceIdHash);
    EXPECT_TRUE(!ret);
    deviceIdHash = "dev/ice%Id()Hash()";
    ret = IsPotentialTrustedDeviceDp(deviceIdHash);
    EXPECT_TRUE(!ret);
}
} // namespace OHOS
