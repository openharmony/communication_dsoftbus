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

#include <cstring>
#include <memory>
#include <securec.h>

#include <gtest/gtest.h>

#include "lnn_conversation_query.h"
#include "lnn_conversation_query_deps_mock.h"
#include "lnn_cloud_query_fragment.h"
#include "lnn_device_info_struct.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace {
void FillLocalNodeInfo(NodeInfo *info, bool isPc)
{
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info->deviceInfo.deviceTypeId = isPc ? TYPE_2IN1_ID : 0x0A;
    (void)strcpy_s(info->networkId, sizeof(info->networkId), "LOCAL_NETWORK_ID");
    (void)strcpy_s(info->deviceInfo.deviceUdid, sizeof(info->deviceInfo.deviceUdid), "LOCAL_UDID");
}

constexpr int64_t PEER_ACCOUNT_ID = 12345;

void FillPeerNodeInfo(NodeInfo *info)
{
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info->deviceInfo.deviceTypeId = 0x0A;
    (void)strcpy_s(info->networkId, sizeof(info->networkId), "PEER_NETWORK_ID");
    (void)strcpy_s(info->deviceInfo.deviceUdid, sizeof(info->deviceInfo.deviceUdid), "PEER_UDID");
    info->aclState = ACL_CAN_WRITE;
    info->accountId = PEER_ACCOUNT_ID;
}

ConversationBusiness MakeBusiness()
{
    ConversationBusiness info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "test_bundle");
    (void)strcpy_s(info.abilityName, sizeof(info.abilityName), "test_ability");
    return info;
}
} // namespace

class LnnConversationQueryDepsTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        DataFragmentInit();
    }
    static void TearDownTestCase() {}
    void SetUp() override
    {
        mock_ = std::make_unique<LnnConvQueryDepsInterfaceMock>();
        ON_CALL(*mock_, LnnGetLocalNodeInfoSafe(_)).WillByDefault(Invoke([](NodeInfo *n) {
            FillLocalNodeInfo(n, false);
            return SOFTBUS_OK;
        }));
        ON_CALL(*mock_, LnnGetRemoteNodeInfoById(_, _, _)).WillByDefault(Return(SOFTBUS_NOT_FIND));
        ON_CALL(*mock_, LnnRetrieveDeviceInfoByNetworkIdPacked(_, _)).WillByDefault(Return(SOFTBUS_NOT_FIND));
        ON_CALL(*mock_, LnnRetrieveDeviceInfoByUdidPacked(_, _)).WillByDefault(Return(SOFTBUS_NOT_FIND));
        ON_CALL(*mock_, IsFeatureSupport(_, _)).WillByDefault(Return(true));
        ON_CALL(*mock_, LnnGetOnlineStateById(_, _)).WillByDefault(Return(false));
        ON_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).WillByDefault(Return(0));
    }
    void TearDown() override { mock_.reset(); }
    std::unique_ptr<LnnConvQueryDepsInterfaceMock> mock_;
};

/*
 * @tc.name: POST_DATA_PC_NODE_FOUND_ENTER_FAR_FIELD_001
 * @tc.desc: Local PC, peer node found, near field unsupported: far field must be entered.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryDepsTest, POST_DATA_PC_NODE_FOUND_ENTER_FAR_FIELD_001, TestSize.Level1)
{
    ON_CALL(*mock_, LnnGetLocalNodeInfoSafe(_)).WillByDefault(Invoke([](NodeInfo *n) {
        FillLocalNodeInfo(n, true);
        return SOFTBUS_OK;
    }));
    EXPECT_CALL(*mock_, LnnGetRemoteNodeInfoById(_, _, _)).WillRepeatedly(Invoke(
        [](const char *, IdCategory, NodeInfo *n) { FillPeerNodeInfo(n); return SOFTBUS_OK; }));
    EXPECT_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).Times(1);

    auto info = MakeBusiness();
    const char *data = "hello";
    int32_t ret = LnnPostConversationData("PEER_NETWORK_ID", &info, data, strlen(data));
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: POST_DATA_PC_NODE_NOT_FOUND_ENTER_FAR_FIELD_001
 * @tc.desc: Local PC, peer node not found: far field must be entered as last resort.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryDepsTest, POST_DATA_PC_NODE_NOT_FOUND_ENTER_FAR_FIELD_001, TestSize.Level1)
{
    ON_CALL(*mock_, LnnGetLocalNodeInfoSafe(_)).WillByDefault(Invoke([](NodeInfo *n) {
        FillLocalNodeInfo(n, true);
        return SOFTBUS_OK;
    }));
    EXPECT_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).Times(1);

    auto info = MakeBusiness();
    const char *data = "hello";
    int32_t ret = LnnPostConversationData("PEER_NOTFOUND", &info, data, strlen(data));
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: POST_DATA_PC_NEAR_FAILED_NO_FAR_FIELD_001
 * @tc.desc: Local PC, near field attempted but failed: far field must NOT be entered, return failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryDepsTest, POST_DATA_PC_NEAR_FAILED_NO_FAR_FIELD_001, TestSize.Level1)
{
    ON_CALL(*mock_, LnnGetLocalNodeInfoSafe(_)).WillByDefault(Invoke([](NodeInfo *n) {
        FillLocalNodeInfo(n, true);
        return SOFTBUS_OK;
    }));
    EXPECT_CALL(*mock_, LnnGetRemoteNodeInfoById(_, _, _)).WillRepeatedly(Invoke(
        [](const char *, IdCategory, NodeInfo *n) { FillPeerNodeInfo(n); return SOFTBUS_OK; }));
    ON_CALL(*mock_, LnnGetOnlineStateById(_, _)).WillByDefault(Return(true));
    ON_CALL(*mock_, LnnGetLocalNum64Info(_, _)).WillByDefault(Invoke([](InfoKey, int64_t *account) {
        *account = PEER_ACCOUNT_ID;
        return SOFTBUS_OK;
    }));
    ON_CALL(*mock_, LnnIsDefaultOhosAccount()).WillByDefault(Return(false));
    EXPECT_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).Times(0);

    auto info = MakeBusiness();
    const char *data = "hello";
    int32_t ret = LnnPostConversationData("PEER_NETWORK_ID", &info, data, strlen(data));
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: POST_DATA_NONPC_NODE_FOUND_ENTER_FAR_FIELD_001
 * @tc.desc: Non-PC local, peer node found, near unsupported but far supported: far field must be entered.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryDepsTest, POST_DATA_NONPC_NODE_FOUND_ENTER_FAR_FIELD_001, TestSize.Level1)
{
    EXPECT_CALL(*mock_, LnnGetRemoteNodeInfoById(_, _, _)).WillRepeatedly(Invoke(
        [](const char *, IdCategory, NodeInfo *n) { FillPeerNodeInfo(n); return SOFTBUS_OK; }));
    EXPECT_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).Times(1);

    auto info = MakeBusiness();
    const char *data = "hello";
    int32_t ret = LnnPostConversationData("PEER_NETWORK_ID", &info, data, strlen(data));
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: POST_DATA_NONPC_NODE_NOT_FOUND_ENTER_FAR_FIELD_001
 * @tc.desc: Non-PC local, peer node not found: far field must be entered as last resort.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnConversationQueryDepsTest, POST_DATA_NONPC_NODE_NOT_FOUND_ENTER_FAR_FIELD_001, TestSize.Level1)
{
    EXPECT_CALL(*mock_, JudgeDeviceTypeAndGetOsAccountIds()).Times(1);

    auto info = MakeBusiness();
    const char *data = "hello";
    int32_t ret = LnnPostConversationData("PEER_NOTFOUND", &info, data, strlen(data));
    EXPECT_NE(SOFTBUS_OK, ret);
}
