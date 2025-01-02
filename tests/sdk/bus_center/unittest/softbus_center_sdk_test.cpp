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

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

constexpr char PKG_NAME[] = "com.softbus.test";
constexpr char NETWORK_ID[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
constexpr uint16_t DATA_CHANGE_FLAG = 65535;
constexpr int32_t DATA_CHANGE_FLAG_BUF_NUM = 2;

namespace OHOS {
using namespace testing::ext;

class ClientBusCenterSdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void AddPermission();
};

void ClientBusCenterSdkTest::SetUpTestCase()
{
    SetAccessTokenPermission("busCenterTest");
}

void ClientBusCenterSdkTest::TearDownTestCase() { }

void ClientBusCenterSdkTest::SetUp() { }

void ClientBusCenterSdkTest::TearDown() { }

/*
 * @tc.name: SOFTBUS_CENTER_SDK_TEST_001
 * @tc.desc: test set dataChangeFlag and get dataChangeFlag
 * @tc.type: FUNC
 * @tc.require: I5TQW0
 */
HWTEST_F(ClientBusCenterSdkTest, SOFTBUS_CENTER_SDK_TEST_001, TestSize.Level0)
{
    NodeBasicInfo info;
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(SetNodeDataChangeFlag(PKG_NAME, info.networkId, DATA_CHANGE_FLAG) == SOFTBUS_OK);
    uint16_t dataChangeFlag = 0;
    EXPECT_TRUE(GetNodeKeyInfo(PKG_NAME, info.networkId, NODE_KEY_DATA_CHANGE_FLAG, (uint8_t *)&dataChangeFlag,
                    DATA_CHANGE_FLAG_BUF_NUM) == SOFTBUS_OK);
    EXPECT_TRUE(dataChangeFlag == DATA_CHANGE_FLAG);
}

/*
 * @tc.name: SOFTBUS_CENTER_SDK_TEST_002
 * @tc.desc: test SetNodeDataChangeFlag fail
 * @tc.type: FUNC
 * @tc.require: I5TQW0
 */
HWTEST_F(ClientBusCenterSdkTest, SOFTBUS_CENTER_SDK_TEST_002, TestSize.Level0)
{
    NodeBasicInfo info;
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(SetNodeDataChangeFlag(nullptr, info.networkId, DATA_CHANGE_FLAG) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(SetNodeDataChangeFlag(PKG_NAME, NETWORK_ID, DATA_CHANGE_FLAG) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SOFTBUS_CENTER_SDK_TEST_003
 * @tc.desc: after joinLNN test get remote dataChangeFlag
 * @tc.type: FUNC
 * @tc.require: I5TQW0
 */
HWTEST_F(ClientBusCenterSdkTest, SOFTBUS_CENTER_SDK_TEST_003, TestSize.Level0)
{
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    uint16_t dataChangeFlag = 1;
    EXPECT_TRUE(GetAllNodeDeviceInfo(PKG_NAME, &info, &infoNum) == SOFTBUS_OK);
    if (info != nullptr && infoNum != 0) {
        EXPECT_TRUE(GetNodeKeyInfo(PKG_NAME, info->networkId, NODE_KEY_DATA_CHANGE_FLAG, (uint8_t *)&dataChangeFlag,
                        DATA_CHANGE_FLAG_BUF_NUM) == SOFTBUS_OK);
        EXPECT_TRUE(dataChangeFlag == DATA_CHANGE_FLAG);
    }
}
} // namespace OHOS
