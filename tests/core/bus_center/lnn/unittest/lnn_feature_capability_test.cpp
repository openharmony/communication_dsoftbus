/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_feature_capability.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

class LNNFeatureCapabilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNFeatureCapabilityTest::SetUpTestCase() { }

void LNNFeatureCapabilityTest::TearDownTestCase() { }

void LNNFeatureCapabilityTest::SetUp() { }

void LNNFeatureCapabilityTest::TearDown() { }

/*
 * @tc.name: LnnSetFeatureCapability_Test_001
 * @tc.desc: Verify LnnSetFeatureCapability with valid feature pointer and
 *           valid capability bit returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnSetFeatureCapability_Test_001, TestSize.Level1)
{
    uint64_t feature = 0;
    FeatureCapability capaBit = BIT_WIFI_P2P_REUSE;
    int32_t ret = LnnSetFeatureCapability(&feature, capaBit);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetFeatureCapability_Test_002
 * @tc.desc: Verify LnnSetFeatureCapability with nullptr feature pointer returns
 *           SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnSetFeatureCapability_Test_002, TestSize.Level1)
{
    FeatureCapability capaBit = BIT_WIFI_P2P_REUSE;
    int32_t ret = LnnSetFeatureCapability(nullptr, capaBit);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnSetFeatureCapability_Test_003
 * @tc.desc: Verify LnnSetFeatureCapability with invalid capability bit
 *           BIT_FEATURE_COUNT returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnSetFeatureCapability_Test_003, TestSize.Level1)
{
    uint64_t feature = 0;
    FeatureCapability capaBit = BIT_FEATURE_COUNT;
    int32_t ret = LnnSetFeatureCapability(&feature, capaBit);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnClearFeatureCapability_Test_001
 * @tc.desc: Verify LnnClearFeatureCapability with valid feature pointer and
 *           valid capability bit returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnClearFeatureCapability_Test_001, TestSize.Level1)
{
    uint64_t feature = 0;
    FeatureCapability capaBit = BIT_WIFI_P2P_REUSE;
    int32_t ret = LnnClearFeatureCapability(&feature, capaBit);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnClearFeatureCapability_Test_002
 * @tc.desc: Verify LnnClearFeatureCapability with nullptr feature pointer returns
 *           SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnClearFeatureCapability_Test_002, TestSize.Level1)
{
    FeatureCapability capaBit = BIT_FEATURE_COUNT;
    int32_t ret = LnnClearFeatureCapability(nullptr, capaBit);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnClearFeatureCapability_Test_003
 * @tc.desc: Verify LnnClearFeatureCapability with invalid capability bit
 *           BIT_FEATURE_COUNT returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnClearFeatureCapability_Test_003, TestSize.Level1)
{
    uint64_t feature = 0;
    FeatureCapability capaBit = BIT_FEATURE_COUNT;
    int32_t ret = LnnClearFeatureCapability(&feature, capaBit);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnNodeInfo_Test_001
 * @tc.desc: Verify LnnSetUserIdCheckSum with valid nodeInfo but nullptr data
 *           returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = LnnSetUserIdCheckSum(&info, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnNodeInfo_Test_002
 * @tc.desc: Verify LnnSetUserIdCheckSum with nullptr nodeInfo returns
 *           SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_002, TestSize.Level1)
{
    uint8_t data = 0;
    uint32_t len = 1;
    int32_t ret = LnnSetUserIdCheckSum(nullptr, &data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnNodeInfo_Test_003
 * @tc.desc: Verify LnnSetUserIdCheckSum with valid nodeInfo and valid data
 *           returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_003, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(USERID_CHECKSUM_LEN)));
    (void)memset_s(data, USERID_CHECKSUM_LEN, 0, USERID_CHECKSUM_LEN);
    uint32_t len = USERID_CHECKSUM_LEN;
    int32_t ret = LnnSetUserIdCheckSum(&info, data, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(data);
}

/*
 * @tc.name: LnnNodeInfo_Test_004
 * @tc.desc: Verify LnnGetUserIdCheckSum with valid nodeInfo but nullptr data
 *           returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_004, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = LnnGetUserIdCheckSum(&info, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnNodeInfo_Test_005
 * @tc.desc: Verify LnnGetUserIdCheckSum with nullptr nodeInfo returns
 *           SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_005, TestSize.Level1)
{
    uint8_t data = 0;
    uint32_t len = 1;
    int32_t ret = LnnGetUserIdCheckSum(nullptr, &data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnNodeInfo_Test_006
 * @tc.desc: Verify LnnGetUserIdCheckSum with valid nodeInfo and valid data
 *           returns SOFTBUS_OK and retrieves correct checksum value
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5RHYE
 */
HWTEST_F(LNNFeatureCapabilityTest, LnnNodeInfo_Test_006, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(info.userIdCheckSum, USERID_CHECKSUM_LEN, 1, USERID_CHECKSUM_LEN);
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(USERID_CHECKSUM_LEN)));
    (void)memset_s(data, USERID_CHECKSUM_LEN, 1, USERID_CHECKSUM_LEN);
    uint32_t len = USERID_CHECKSUM_LEN;
    int32_t ret = LnnGetUserIdCheckSum(&info, data, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(data);
}
} // namespace OHOS