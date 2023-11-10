/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "lnn_sync_info_manager.h"
#include "lnn_trans_mock.h"
#include "lnn_service_mock.h"
#include "message_handler.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char NETWORLID[65] = "abcdefg";
constexpr uint8_t MSG[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
constexpr uint32_t LEN = 10;
constexpr uint32_t LENGTH = 8192;
class LNNSyncInfoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSyncInfoManagerTest::SetUpTestCase()
{
    LooperInit();
    NiceMock<LnnTransInterfaceMock> transMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener).WillRepeatedly(
        DoAll(LnnTransInterfaceMock::ActionOfTransRegister, Return(SOFTBUS_OK)));
    int32_t ret = LnnInitSyncInfoManager();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void LNNSyncInfoManagerTest::TearDownTestCase()
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    LnnDeinitSyncInfoManager();
    LooperDeinit();
}

void LNNSyncInfoManagerTest::SetUp()
{
}

void LNNSyncInfoManagerTest::TearDown()
{
}

void Handler(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
}

void Complete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
}

/*
* @tc.name: LNN_REG_SYNC_INFO_HANDLER_TEST_001
* @tc.desc: invalid parameter
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNSyncInfoManagerTest, LNN_REG_SYNC_INFO_HANDLER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_COUNT, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_UNREG_SYNC_INFO_HANDLER_TEST_001
* @tc.desc: invalid parameter
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNSyncInfoManagerTest, LNN_UNREG_SYNC_INFO_HANDLER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_COUNT, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_OFFLINE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_SYNC_INFO_MSG_TEST_001
* @tc.desc: invalid parameter
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_SYNC_INFO_MSG_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_COUNT, NETWORLID, MSG, LEN, Complete);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_ROUTE_LSU, NETWORLID, MSG, LENGTH, Complete);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
} // namespace OHOS
