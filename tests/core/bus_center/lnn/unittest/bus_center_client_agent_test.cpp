/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "softbus_access_token_test.h"
#include "softbus_agent_communication.h"
#include "softbus_error_code.h"
#include "client_bus_center_manager.h"
 
namespace OHOS {
using namespace testing::ext;
using namespace testing;
 
static constexpr char TEST_BUNDLE_NAME[] = "ohos.test.buscenter";
static constexpr char TEST_ABILITY_NAME[] = "TestAbility";
static constexpr char TEST_NETWORK_ID[] = "1234567890123456789012345678901234567890123456789012345678901234";
static constexpr char TEST_DATA[] = "Test data for conversation";
 
static inline void InitConversationBusiness(ConversationBusiness *info)
{
    (void)memset_s(info, sizeof(ConversationBusiness), 0, sizeof(ConversationBusiness));
    (void)strncpy_s(info->bundleName, sizeof(info->bundleName), TEST_BUNDLE_NAME, strlen(TEST_BUNDLE_NAME));
    (void)strncpy_s(info->abilityName, sizeof(info->abilityName), TEST_ABILITY_NAME, strlen(TEST_ABILITY_NAME));
}
 
class BusCenterClientAgentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
void BusCenterClientAgentTest::SetUpTestCase()
{
    SetAccessTokenPermission("BusCenterClientAgentTest");
    BusCenterClientInit();
}
 
void BusCenterClientAgentTest::TearDownTestCase()
{
}
 
void BusCenterClientAgentTest::SetUp()
{
}
 
void BusCenterClientAgentTest::TearDown()
{
}
 
static void OnDataReceived(const char *networkId, const char *data, uint32_t len)
{
    (void)networkId;
    (void)data;
    (void)len;
}
 
HWTEST_F(BusCenterClientAgentTest, GetTrustedDevices_Test001, TestSize.Level1)
{
    DeviceNodeInfo *info = nullptr;
    int32_t nums = 0;
    int32_t ret = GetTrustedDevices(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = GetTrustedDevices(&info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = GetTrustedDevices(nullptr, &nums);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = GetTrustedDevices(&info, &nums);
    if (info != nullptr) {
        EXPECT_NO_FATAL_FAILURE(FreeDeviceNodeInfo(info));
    }
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationPost_Test001, TestSize.Level1)
{
    ConversationBusiness info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)strncpy_s(info.bundleName, sizeof(info.bundleName), TEST_BUNDLE_NAME, strlen(TEST_BUNDLE_NAME));
    (void)strncpy_s(info.abilityName, sizeof(info.abilityName), TEST_ABILITY_NAME, strlen(TEST_ABILITY_NAME));
 
    int32_t ret = PostConversationData(nullptr, &info, TEST_DATA, strlen(TEST_DATA));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = PostConversationData(TEST_NETWORK_ID, nullptr, TEST_DATA, strlen(TEST_DATA));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = PostConversationData(TEST_NETWORK_ID, &info, nullptr, strlen(TEST_DATA));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationPost_Test002, TestSize.Level1)
{
    ConversationBusiness info;
    InitConversationBusiness(&info);
 
    char shortNetworkId[] = "12345";
    int32_t ret = PostConversationData(shortNetworkId, &info, TEST_DATA, strlen(TEST_DATA));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationPost_Test003, TestSize.Level1)
{
    ConversationBusiness info;
    InitConversationBusiness(&info);
 
    int32_t ret = PostConversationData(TEST_NETWORK_ID, &info, TEST_DATA, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = PostConversationData(TEST_NETWORK_ID, &info, TEST_DATA, COMMUNICATION_DATA_MAX_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationRegisterListener_Test001, TestSize.Level1)
{
    ConversationBusiness info;
    InitConversationBusiness(&info);
 
    ConversationListener listener = {
        .OnDataReceived = OnDataReceived,
    };
 
    int32_t ret = RegisterConversationListener(nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
 
    ret = RegisterConversationListener(&info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationRegisterListener_Test002, TestSize.Level1)
{
    ConversationBusiness info;
    InitConversationBusiness(&info);
 
    ConversationListener listenerNullOnDataReceived = {
        .OnDataReceived = nullptr,
    };
 
    int32_t ret = RegisterConversationListener(&info, &listenerNullOnDataReceived);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
 
HWTEST_F(BusCenterClientAgentTest, ConversationRemoveListener_Test001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UnregisterConversationListener(nullptr));
}
 
HWTEST_F(BusCenterClientAgentTest, FreeDeviceNodeInfo_Test001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FreeDeviceNodeInfo(nullptr));
}
 
HWTEST_F(BusCenterClientAgentTest, FreeDeviceNodeInfo_Test002, TestSize.Level1)
{
    DeviceNodeInfo *info = (DeviceNodeInfo *)malloc(sizeof(DeviceNodeInfo));
    ASSERT_NE(info, nullptr);
 
    (void)memset_s(info, sizeof(DeviceNodeInfo), 0, sizeof(DeviceNodeInfo));
    EXPECT_NO_FATAL_FAILURE(FreeDeviceNodeInfo(info));
}
 
} // namespace OHOS