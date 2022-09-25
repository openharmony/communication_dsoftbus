/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing::ext;

static constexpr char TEST_PKG_NAME[] = "com.softbus.test";

class BusCenterMetaNodeSdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterMetaNodeSdkTest::SetUpTestCase()
{
    SetAceessTokenPermission("busCenterTest");
}

void BusCenterMetaNodeSdkTest::TearDownTestCase()
{
}

void BusCenterMetaNodeSdkTest::SetUp()
{
}

void BusCenterMetaNodeSdkTest::TearDown()
{
}

/*
* @tc.name: BUS_CENTER_SDK_META_NODE_Test_001
* @tc.desc: meta node interface test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterMetaNodeSdkTest, BUS_CENTER_SDK_META_NODE_Test_001, TestSize.Level0)
{
    char udid[] = "0123456789987654321001234567899876543210012345678998765432100123";
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t infoNum = MAX_META_NODE_NUM;
    MetaNodeConfigInfo configInfo;

    configInfo.addrNum = 1;
    EXPECT_TRUE(DeactiveMetaNode(TEST_PKG_NAME, metaNodeId) != SOFTBUS_OK);
    EXPECT_TRUE(strncpy_s(configInfo.udid, UDID_BUF_LEN, udid, UDID_BUF_LEN) == EOK);
    EXPECT_TRUE(ActiveMetaNode(TEST_PKG_NAME, &configInfo, metaNodeId) == SOFTBUS_OK);
    EXPECT_EQ((int32_t)strlen(metaNodeId), NETWORK_ID_BUF_LEN - 1);
    EXPECT_TRUE(ActiveMetaNode(TEST_PKG_NAME, &configInfo, metaNodeId) == SOFTBUS_OK);
    EXPECT_TRUE(GetAllMetaNodeInfo(TEST_PKG_NAME, infos, &infoNum) == SOFTBUS_OK);
    EXPECT_EQ(infoNum, 1);
    EXPECT_FALSE(infos[0].isOnline);
    EXPECT_TRUE(strcmp(infos[0].metaNodeId, metaNodeId) == 0);
    EXPECT_TRUE(strcmp(infos[0].configInfo.udid, udid) == 0);
    EXPECT_EQ(infos[0].configInfo.addrNum, 1);
    EXPECT_TRUE(DeactiveMetaNode(TEST_PKG_NAME, metaNodeId) == SOFTBUS_OK);
    EXPECT_TRUE(GetAllMetaNodeInfo(TEST_PKG_NAME, infos, &infoNum) == SOFTBUS_OK);
    EXPECT_EQ(infoNum, 0);
}

/*
* @tc.name: BUS_CENTER_SDK_META_NODE_Test_002
* @tc.desc: meta node interface test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterMetaNodeSdkTest, BUS_CENTER_SDK_META_NODE_Test_002, TestSize.Level0)
{
    char udid[] = "0123456789987654321001234567899876543210012345678998765432100123";
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t infoNum = MAX_META_NODE_NUM;
    MetaNodeConfigInfo configInfo;
    int i;

    configInfo.addrNum = 1;
    EXPECT_TRUE(strncpy_s(configInfo.udid, UDID_BUF_LEN, udid, UDID_BUF_LEN) == EOK);
    for (i = 0; i <= MAX_META_NODE_NUM; ++i) {
        configInfo.udid[0] += 1;
        if (i < MAX_META_NODE_NUM) {
            EXPECT_TRUE(ActiveMetaNode(TEST_PKG_NAME, &configInfo, metaNodeId) == SOFTBUS_OK);
        } else {
            EXPECT_TRUE(ActiveMetaNode(TEST_PKG_NAME, &configInfo, metaNodeId) != SOFTBUS_OK);
        }
    }
    EXPECT_TRUE(GetAllMetaNodeInfo(TEST_PKG_NAME, infos, &infoNum) == SOFTBUS_OK);
    EXPECT_EQ(infoNum, MAX_META_NODE_NUM);
    for (i = 0; i < MAX_META_NODE_NUM; ++i) {
        EXPECT_FALSE(infos[i].isOnline);
        EXPECT_TRUE(DeactiveMetaNode(TEST_PKG_NAME, infos[i].metaNodeId) == SOFTBUS_OK);
    }
}
} // namespace OHOS
