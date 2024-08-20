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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <string>
#include <securec.h>
#include <cstdint>
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_device_info.h"
#include "softbus_bus_center.h"
#include "lnn_async_callback_utils.h"
#include "message_handler.h"
#include "softbus_error_code.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_devicename_info.h"
#include "softbus_def.h"
#include "softbus_bus_center.h"
#include "lnn_ohos_account_adapter.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "softbus_adapter_mem.h"
#include "lnn_settingdata_event_monitor_deps_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
constexpr char *DEVICE_NAME1 = nullptr;
const char *DEVICE_NAME2 = "ABCDEFG";
const char *NICK_NAME = "TEST_NICK_NAME";
const char *DEFAULT_NAME = "TEST_DEFAULT_NAME";

class LnnSettingdataEventMonitorTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void LnnSettingdataEventMonitorTest::SetUpTestCase(void)
{
}
void LnnSettingdataEventMonitorTest::TearDownTestCase(void)
{
}
void LnnSettingdataEventMonitorTest::SetUp(void)
{
}
void LnnSettingdataEventMonitorTest::TearDown(void)
{
}

/*
* @tc.name: LnnGetSettingDeviceNameTest001
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest001, TestSize.Level1)
{
    int ret = LnnGetSettingDeviceName(DEVICE_NAME1, DEVICE_NAME_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LnnGetSettingDeviceNameTest002
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest002, TestSize.Level1)
{
    LnnDeviceNameHandler handler = NULL;
    int ret = LnnInitGetDeviceName(handler);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LnnGetSettingDeviceNameTest003
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest003, TestSize.Level1)
{
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    strncpy_s(deviceName, sizeof(deviceName), "TEST_DEVICE_NAME", sizeof(deviceName) - 1);
    int32_t ret = LnnGetDeviceDisplayName(NICK_NAME, DEFAULT_NAME, deviceName, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
* @tc.name: LnnGetSettingDeviceNameTest004
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest004, TestSize.Level1)
{
    NiceMock<SettingDataEventMonitorDepsInterfaceMock> SettingDataEventMonitorMock;
    EXPECT_CALL(SettingDataEventMonitorMock, GetLooper(_)).WillOnce(Return(NULL));
    int32_t ret = LnnInitDeviceNameMonitorImpl();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LnnGetSettingDeviceNameTest005
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest005, TestSize.Level1)
{
    NiceMock<SettingDataEventMonitorDepsInterfaceMock> SettingDataEventMonitorMock;
    SoftBusLooper loop;
    EXPECT_CALL(SettingDataEventMonitorMock, GetLooper(_)).WillRepeatedly(Return(&loop));
    EXPECT_CALL(SettingDataEventMonitorMock, LnnAsyncCallbackHelper(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = LnnInitDeviceNameMonitorImpl();
    EXPECT_NE(ret, SOFTBUS_OK);
}
}