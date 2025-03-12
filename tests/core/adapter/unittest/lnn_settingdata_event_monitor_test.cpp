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
#include <cstdint>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "lnn_async_callback_utils.h"
#include "lnn_device_info.h"
#include "lnn_devicename_info.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_settingdata_event_monitor_deps_mock.h"
#include "locale_config.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
const char *NICK_NAME = "TEST_NICK_NAME";
const char *DEFAULT_NAME = "TEST_DEFAULT_NAME";
static constexpr const char *INTERNAL_NAME_CONCAT_STRING = "的";
static constexpr const char *EXTERNAL_NAME_CONCAT_STRING = "-";

class LnnSettingdataEventMonitorTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void LnnSettingdataEventMonitorTest::SetUpTestCase(void) { }
void LnnSettingdataEventMonitorTest::TearDownTestCase(void) { }
void LnnSettingdataEventMonitorTest::SetUp(void) { }
void LnnSettingdataEventMonitorTest::TearDown(void) { }

/*
* @tc.name: LnnGetSettingDeviceNameTest003
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest003, TestSize.Level1)
{
    char deviceName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetDeviceDisplayName(NICK_NAME, DEFAULT_NAME, deviceName, DEVICE_NAME_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK || ret == SOFTBUS_NOT_IMPLEMENT);
    if (ret != SOFTBUS_NOT_IMPLEMENT) {
        char devName[DEVICE_NAME_BUF_LEN] = {0};
        std::string language = OHOS::Global::I18n::LocaleConfig::GetSystemLanguage();
        if ("zh-Hans" == language || "zh-Hant" == language) {
            ASSERT_GT(sprintf_s(devName, DEVICE_NAME_BUF_LEN, "%s%s%s", NICK_NAME,
            INTERNAL_NAME_CONCAT_STRING, DEFAULT_NAME), 0);
            EXPECT_EQ(strncmp(devName, deviceName, DEVICE_NAME_BUF_LEN), 0);
        } else {
            ASSERT_GT(sprintf_s(devName, DEVICE_NAME_BUF_LEN, "%s%s%s", NICK_NAME,
            EXTERNAL_NAME_CONCAT_STRING, DEFAULT_NAME), 0);
            EXPECT_EQ(strncmp(devName, deviceName, DEVICE_NAME_BUF_LEN), 0);
        }
    }
}
} // namespace OHOS