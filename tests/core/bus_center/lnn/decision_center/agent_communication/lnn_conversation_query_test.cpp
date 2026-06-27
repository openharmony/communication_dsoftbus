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
 
 
#include "lnn_conversation_query.h"
#include "softbus_error_code.h"
 
namespace OHOS {
using namespace testing;
using namespace testing::ext;
 
class LnnConversationQueryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
void LnnConversationQueryTest::SetUpTestCase() { }
 
void LnnConversationQueryTest::TearDownTestCase() { }
 
void LnnConversationQueryTest::SetUp() { }
 
void LnnConversationQueryTest::TearDown() { }
 
/*
 * @tc.name: ON_RECV_CLOUD_QUERY_INFO_TEST_001
 * @tc.desc: test OnRecvCloudQueryInfo with null parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, ON_RECV_CLOUD_QUERY_INFO_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(OnRecvCloudQueryInfo(nullptr, nullptr, 0));
}
 
/*
 * @tc.name: ON_RECV_CLOUD_QUERY_INFO_TEST_002
 * @tc.desc: test OnRecvCloudQueryInfo with valid udid but null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, ON_RECV_CLOUD_QUERY_INFO_TEST_002, TestSize.Level1)
{
    const char *udid = "test_udid";
    EXPECT_NO_FATAL_FAILURE(OnRecvCloudQueryInfo(udid, nullptr, 0));
}
 
/*
 * @tc.name: ON_RECV_CLOUD_QUERY_INFO_TEST_003
 * @tc.desc: test OnRecvCloudQueryInfo with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, ON_RECV_CLOUD_QUERY_INFO_TEST_003, TestSize.Level1)
{
    const char *udid = "test_udid";
    const char *data = "test_data";
    uint32_t length = strlen(data);
    EXPECT_NO_FATAL_FAILURE(OnRecvCloudQueryInfo(udid, data, length));
}
 
/*
 * @tc.name: LNN_GET_TRUSTED_DEVICES_TEST_001
 * @tc.desc: test LnnGetTrustedDevices with null parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_GET_TRUSTED_DEVICES_TEST_001, TestSize.Level1)
{
    int32_t nums = 0;
    int32_t ret = LnnGetTrustedDevices(nullptr, &nums);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: LNN_GET_TRUSTED_DEVICES_TEST_002
 * @tc.desc: test LnnGetTrustedDevices with null nums.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_GET_TRUSTED_DEVICES_TEST_002, TestSize.Level1)
{
    DeviceNodeInfo *info = nullptr;
    int32_t ret = LnnGetTrustedDevices(&info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: LNN_CONVERSATION_REGISTER_LISTENER_TEST_001
 * @tc.desc: test LnnRegisterConversationListener with null info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_CONVERSATION_REGISTER_LISTENER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnRegisterConversationListener(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: LNN_CONVERSATION_REMOVE_LISTENER_TEST_001
 * @tc.desc: test LnnUnregisterConversationListener with null info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_CONVERSATION_REMOVE_LISTENER_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnUnregisterConversationListener(nullptr));
}
 
/*
 * @tc.name: LNN_CONVERSATION_POST_TEST_001
 * @tc.desc: test LnnPostConversationData with null networkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_CONVERSATION_POST_TEST_001, TestSize.Level1)
{
    ConversationBusiness info;
    (void)memset_s(&info, sizeof(ConversationBusiness), 0, sizeof(ConversationBusiness));
    const char *data = "test_data";
    int32_t ret = LnnPostConversationData(nullptr, &info, data, strlen(data));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: LNN_CONVERSATION_POST_TEST_002
 * @tc.desc: test LnnPostConversationData with null info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_CONVERSATION_POST_TEST_002, TestSize.Level1)
{
    const char *networkId = "test_network_id";
    const char *data = "test_data";
    int32_t ret = LnnPostConversationData(networkId, nullptr, data, strlen(data));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: LNN_CONVERSATION_POST_TEST_003
 * @tc.desc: test LnnPostConversationData with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, LNN_CONVERSATION_POST_TEST_003, TestSize.Level1)
{
    const char *networkId = "test_network_id";
    ConversationBusiness info;
    (void)memset_s(&info, sizeof(ConversationBusiness), 0, sizeof(ConversationBusiness));
    int32_t ret = LnnPostConversationData(networkId, &info, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DESTORY_NEAR_FIELD_CHANNEL_TEST_001
 * @tc.desc: test DestroyNearFieldChannel with null udid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryTest, DESTORY_NEAR_FIELD_CHANNEL_TEST_001, TestSize.Level1)
{
    int32_t ret = DestroyNearFieldChannel(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // namespace OHOS