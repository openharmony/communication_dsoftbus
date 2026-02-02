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

#include "lnn_init_monitor.c"
#include "lnn_init_monitor.h"
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

namespace OHOS {
using namespace testing::ext;

class LNNInitMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNInitMonitorTest::SetUpTestCase() { }

void LNNInitMonitorTest::TearDownTestCase() { }

void LNNInitMonitorTest::SetUp()
{
    LnnInitMonitorInit();
}

void LNNInitMonitorTest::TearDown() { }

void LNNTestSetMonitorInitSuc(void)
{
    for (uint32_t depModule = 0; depModule < INIT_DEPS_MODULE_BUTT; depModule++) {
        LnnInitModuleStatusSet(depModule, DEPS_STATUS_SUCCESS);
    }
    for (uint32_t depLeger = 0; depLeger < LEDGER_INFO_BUTT; depLeger++) {
        LnnInitDeviceInfoStatusSet(depLeger, DEPS_STATUS_SUCCESS);
    }
}

int32_t LnnInitMonitorCallbackSuc(void)
{
    return SOFTBUS_OK;
}

int32_t LnnInitMonitorCallbackFailed(void)
{
    return SOFTBUS_ERR;
}

/*
 * @tc.name: LnnInitMonitor_Test_001
 * @tc.desc: Verify LnnInitModuleStatusGet, LnnInitModuleStatusSet,
 *           LnnInitDeviceInfoStatusGet and LnnInitDeviceInfoStatusSet functions
 *           for status management
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNInitMonitorTest, LnnInitMonitor_Test_001, TestSize.Level0)
{
    InitDepsStatus status;

    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_NOT_INIT);
    status = LnnInitDeviceInfoStatusGet(LEDGER_INFO_DEVICE_NAME);
    EXPECT_EQ(status, DEPS_STATUS_NOT_INIT);

    LnnInitModuleReturnSet(INIT_DEPS_DEVICE_PROFILE, SOFTBUS_OK);
    LnnInitModuleStatusSet(INIT_DEPS_DEVICE_PROFILE, DEPS_STATUS_SUCCESS);
    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_SUCCESS);

    LnnInitDeviceInfoStatusSet(LEDGER_INFO_DEVICE_NAME, DEPS_STATUS_SUCCESS);
    status = LnnInitDeviceInfoStatusGet(LEDGER_INFO_DEVICE_NAME);
    EXPECT_EQ(status, DEPS_STATUS_SUCCESS);

    status = LnnInitDeviceInfoStatusGet(LEDGER_INFO_BUTT);
    EXPECT_EQ(status, DEPS_STATUS_NOT_INIT);
}

/*
 * @tc.name: LnnInitMonitor_Test_002
 * @tc.desc: Verify IsLnnInitCheckSucceed returns false before initialization
 *           and LnnModuleInitMonitorCheckStart updates module status correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNInitMonitorTest, LnnInitMonitor_Test_002, TestSize.Level0)
{
    InitDepsStatus status;
    uint32_t ret;

    ret = IsLnnInitCheckSucceed(MONITOR_WIFI_NET);
    EXPECT_EQ(ret, false);
    ret = IsLnnInitCheckSucceed(MONITOR_BLE_NET);
    EXPECT_EQ(ret, false);

    LNNTestSetMonitorInitSuc();
    LnnModuleInitMonitorCheckStart();

    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_SUCCESS);
}

/*
 * @tc.name: LnnModuleInitMonitorCheckStart_Test_001
 * @tc.desc: Verify LnnModuleInitMonitorCheckStart with failed status can be
 *           recovered to success and IsLnnInitCheckSucceed returns true
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNInitMonitorTest, LnnInitMonitor_Test_003, TestSize.Level0)
{
    InitDepsStatus status;
    bool ret;

    LNNTestSetMonitorInitSuc();
    LnnInitModuleStatusSet(INIT_DEPS_DEVICE_PROFILE, DEPS_STATUS_FAILED);
    LnnInitDeviceInfoStatusSet(LEDGER_INFO_DEVICE_NAME, DEPS_STATUS_FAILED);
    LnnModuleInitMonitorCheckStart();

    LnnInitModuleStatusSet(INIT_DEPS_DEVICE_PROFILE, DEPS_STATUS_SUCCESS);
    LnnInitDeviceInfoStatusSet(LEDGER_INFO_DEVICE_NAME, DEPS_STATUS_SUCCESS);
    SoftBusSleepMs(1000);
    LnnInitSetDeviceInfoReady();
    LnnInitMonitorInitComplete(nullptr);
    ret = IsLnnInitCheckSucceed(MONITOR_WIFI_NET);
    EXPECT_EQ(ret, true);

    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_SUCCESS);
}

/*
 * @tc.name: LnnModuleInitMonitorCheckStart_Test_002
 * @tc.desc: Verify LnnInitModuleNotifyWithRetryAsync with invalid parameters
 *           returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNInitMonitorTest, LnnInitMonitor_Test_004, TestSize.Level0)
{
    InitDepsStatus status;
    uint32_t ret;

    ret = LnnInitModuleNotifyWithRetryAsync(INIT_DEPS_MODULE_BUTT, nullptr, 0, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnInitModuleNotifyWithRetryAsync(INIT_DEPS_DEVICE_PROFILE, LnnInitMonitorCallbackFailed, 3, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnInitModuleNotifyWithRetryAsync(INIT_DEPS_DEVICE_PROFILE, LnnInitMonitorCallbackSuc, 0, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_FAILED);
}

/*
 * @tc.name: LnnModuleInitMonitorCheckStart_Test_003
 * @tc.desc: Verify LnnInitModuleNotifyWithRetrySync with invalid parameters
 *           returns SOFTBUS_INVALID_PARAM and with valid parameters returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNInitMonitorTest, LnnInitMonitor_Test_005, TestSize.Level0)
{
    InitDepsStatus status;
    uint32_t ret;

    ret = LnnInitModuleNotifyWithRetrySync(INIT_DEPS_MODULE_BUTT, nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnInitModuleNotifyWithRetrySync(INIT_DEPS_DEVICE_PROFILE, LnnInitMonitorCallbackFailed, 3, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_FAILED);

    ret = LnnInitModuleNotifyWithRetrySync(INIT_DEPS_DEVICE_PROFILE, LnnInitMonitorCallbackSuc, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    status = LnnInitModuleStatusGet(INIT_DEPS_DEVICE_PROFILE);
    EXPECT_EQ(status, DEPS_STATUS_SUCCESS);
}
} // namespace OHOS