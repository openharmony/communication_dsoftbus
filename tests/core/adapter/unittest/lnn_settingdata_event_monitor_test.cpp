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
#include "message_handler.h"
#include "parameter.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
#define DEVICE_NAME_BUF_LEN 128

const std::string CHINESE_LANGUAGE = "zh-Hans";
const std::string TRADITIONAL_CHINESE_LANGUAGE = "zh-Hant";
const char *NICK_NAME = "TEST_NICK_NAME";
const char *DEFAULT_NAME = "TEST_DEFAULT_NAME";
static constexpr const char *INTERNAL_NAME_CONCAT_STRING = "的";
static constexpr const char *EXTERNAL_NAME_CONCAT_STRING = "-";
static constexpr const char *LANGUAGE_KEY = "persist.global.language";
static constexpr const char *DEFAULT_LANGUAGE_KEY = "const.global.language";
static constexpr const int32_t CONFIG_LEN = 128;

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

static std::string ReadSystemParameter(const char *paramKey)
{
    char param[CONFIG_LEN + 1];
    (void)memset_s(param, CONFIG_LEN + 1, 0, CONFIG_LEN + 1);
    int32_t ret = GetParameter(paramKey, "", param, CONFIG_LEN);
    if (ret > 0) {
        return param;
    }
    return "";
}

static bool IsZHLanguage(void)
{
    std::string systemLanguage = ReadSystemParameter(LANGUAGE_KEY);
    if (!systemLanguage.empty()) {
        return CHINESE_LANGUAGE == systemLanguage || TRADITIONAL_CHINESE_LANGUAGE == systemLanguage;
    }
    systemLanguage = ReadSystemParameter(DEFAULT_LANGUAGE_KEY);
    if (!systemLanguage.empty()) {
        return CHINESE_LANGUAGE == systemLanguage || TRADITIONAL_CHINESE_LANGUAGE == systemLanguage;
    }
    // Default language is Chinese.
    return true;
}

/*
* @tc.name: LnnGetSettingDeviceNameTest003
* @tc.desc: Return SOFTBUS_OK or SOFTBUS_NOT_IMPLEMENT for LnnGetDeviceDisplayName
            verify concatenated device name with internal/external string based on Chinese language check
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
        if (IsZHLanguage()) {
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

/*
 * @tc.name: LnnGetSettingDeviceNameTest004
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when nickName parameter is nullptr for LnnGetDeviceDisplayName
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest004, TestSize.Level1)
{
    uint32_t len = DEVICE_NAME_BUF_LEN;
    char deviceName[] = "deviceName";
    int32_t ret = LnnGetDeviceDisplayName(nullptr, DEFAULT_NAME, deviceName, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetSettingDeviceNameTest005
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when defaultName parameter is nullptr for LnnGetDeviceDisplayName
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest005, TestSize.Level1)
{
    uint32_t len = DEVICE_NAME_BUF_LEN;
    char deviceName[] = "deviceName";
    int32_t ret = LnnGetDeviceDisplayName(NICK_NAME, nullptr, deviceName, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetSettingDeviceNameTest006
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when deviceName buffer is nullptr for LnnGetDeviceDisplayName
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest006, TestSize.Level1)
{
    uint32_t len = DEVICE_NAME_BUF_LEN;
    int32_t ret = LnnGetDeviceDisplayName(NICK_NAME, DEFAULT_NAME, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetSettingDeviceNameTest007
 * @tc.desc: Return SOFTBUS_STRCPY_ERR when len parameter is 0 for LnnGetDeviceDisplayName
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnSettingdataEventMonitorTest, LnnGetSettingDeviceNameTest007, TestSize.Level1)
{
    uint32_t len = 0;
    char deviceName[] = "deviceName";
    int32_t ret = LnnGetDeviceDisplayName(NICK_NAME, DEFAULT_NAME, deviceName, len);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
}
} // namespace OHOS