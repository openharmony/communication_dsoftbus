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
#include "softbus_errcode.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"
#include "lnn_service_mock.h"
#include "softbus_adapter_mem.h"

using namespace std;
using namespace testing::ext;
namespace OHOS {
constexpr char *DEVICE_NAME1 = nullptr;
const char *DEVICE_NAME2 = "ABCDEFG";

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
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest001, TestSize.Level0)
{
    int ret = LnnGetSettingDeviceName(DEVICE_NAME1, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    char* deviceName = (char*)malloc(sizeof(DEVICE_NAME2));
    memset_s(deviceName,sizeof(char*),0,sizeof(char*));
    ret = LnnGetSettingDeviceName(deviceName, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusFree(deviceName);
}
}