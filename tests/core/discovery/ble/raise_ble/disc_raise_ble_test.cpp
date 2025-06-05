/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <securec.h>
#include <unistd.h>

#include "disc_ble_dispatcher.h"
#include "disc_interface.h"
#include "disc_interface_struct.h"
#include "disc_log.h"
#include "disc_raise_ble.h"
#include "softbus_error_code.h"

using namespace testing::ext;
bool g_isDeviceFound = false;
void OnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    (void)device;
    (void)additions;
    g_isDeviceFound = true;
}

static DiscInnerCallback g_discInnerCallback = {
    .OnDeviceFound = OnDeviceFound,
};

static DiscoveryBleDispatcherInterface *g_dispatcherInterface = nullptr;

namespace OHOS {
class DiscRaiseBleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscRaiseBleTest::SetUpTestCase(void) { }

void DiscRaiseBleTest::TearDownTestCase(void) { }

/*
 * @tc.name: OnRaiseHandDeviceFound001
 * @tc.desc: test OnRaiseHandDeviceFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscRaiseBleTest, OnRaiseHandDeviceFound001, TestSize.Level1)
{
    g_dispatcherInterface = DiscRaiseBleInit(&g_discInnerCallback);
    RaiseHandDeviceInfo deviceInfo;
    deviceInfo.nowTimes = 1627072800;
    (void)strcpy_s(deviceInfo.bleMac, sizeof(deviceInfo.bleMac), "00:11:22:33:44:55");
    (void)strcpy_s(deviceInfo.accountHash, sizeof(deviceInfo.accountHash), "accountHash");
    (void)strcpy_s(deviceInfo.deviceIdHash, sizeof(deviceInfo.deviceIdHash), "deviceIdHash");
    for (int i = 0; i < HB_HEARTBEAT_VALUE_LEN; i++) {
        deviceInfo.heartbeatValue[i] = i;
    }
    deviceInfo.deviceTypeId = 1;
    deviceInfo.heartbeatVersion = 2;
    deviceInfo.heartbeatType = 3;
    int ret = OnRaiseHandDeviceFound(&deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(g_isDeviceFound);
    g_isDeviceFound = false;
}

/*
 * @tc.name: OnRaiseHandDeviceFound002
 * @tc.desc: test OnRaiseHandDeviceFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscRaiseBleTest, OnRaiseHandDeviceFound002, TestSize.Level1)
{
    RaiseHandDeviceInfo *deviceInfo = nullptr;
    int ret = OnRaiseHandDeviceFound(deviceInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS