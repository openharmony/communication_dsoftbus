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
 
#include "lnn_cloud_query_fragment.h"
#include "lnn_device_cloud_convergence_struct.h"
#include "softbus_error_code.h"
 
namespace OHOS {
using namespace testing;
using namespace testing::ext;
 
class LnnCloudQueryFragmentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
void LnnCloudQueryFragmentTest::SetUpTestCase() { }
 
void LnnCloudQueryFragmentTest::TearDownTestCase() { }
 
void LnnCloudQueryFragmentTest::SetUp() { }
 
void LnnCloudQueryFragmentTest::TearDown() { }
 
/*
 * @tc.name: DATA_SLICE_TEST_001
 * @tc.desc: test DataSlice with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_SLICE_TEST_001, TestSize.Level1)
{
    const uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    uint32_t sliceLen = MAX_SLICE_LEN;
    const char *networkId = "test_network_id";
    uint32_t msgId = 0;
    int32_t ret = DataSlice(data, dataLen, sliceLen, networkId, msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_SLICE_TEST_002
 * @tc.desc: test DataSlice with zero sliceLen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_SLICE_TEST_002, TestSize.Level1)
{
    const uint8_t data[] = "test_data";
    uint32_t dataLen = sizeof(data);
    uint32_t sliceLen = 0;
    const char *networkId = "test_network_id";
    uint32_t msgId = 0;
    int32_t ret = DataSlice(data, dataLen, sliceLen, networkId, msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_SLICE_TEST_003
 * @tc.desc: test DataSlice with sliceLen too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_SLICE_TEST_003, TestSize.Level1)
{
    const uint8_t data[] = "test_data";
    uint32_t dataLen = sizeof(data);
    uint32_t sliceLen = MAX_SLICE_LEN + 1;
    const char *networkId = "test_network_id";
    uint32_t msgId = 0;
    int32_t ret = DataSlice(data, dataLen, sliceLen, networkId, msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_SLICE_TEST_004
 * @tc.desc: test DataSlice with dataLen too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_SLICE_TEST_004, TestSize.Level1)
{
    uint32_t dataLen = 11 * 1024 * 1024; // > MAX_ASSEMBLED_LEN (10MB)
    uint8_t *data = (uint8_t *)malloc(dataLen);
    ASSERT_NE(data, nullptr);
    memset_s(data, dataLen, 'a', dataLen);
    uint32_t sliceLen = MAX_SLICE_LEN;
    const char *networkId = "test_network_id";
    uint32_t msgId = 0;
    int32_t ret = DataSlice(data, dataLen, sliceLen, networkId, msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    free(data);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_001
 * @tc.desc: test DataAggregate with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_001, TestSize.Level1)
{
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(nullptr, 100, &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_002
 * @tc.desc: test DataAggregate with dataLen less than FRAGMENT_HEADER_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_002, TestSize.Level1)
{
    uint8_t data[10] = {0};
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_003
 * @tc.desc: test DataAggregate with null assembledData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_003, TestSize.Level1)
{
    uint8_t data[100] = {0};
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), nullptr, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_004
 * @tc.desc: test DataAggregate with null assembledLen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_004, TestSize.Level1)
{
    uint8_t data[100] = {0};
    uint8_t *assembledData = nullptr;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, nullptr, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_005
 * @tc.desc: test DataAggregate with invalid fragment header - sliceTotal too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_005, TestSize.Level1)
{
    uint8_t data[32] = {0};
    // Set sliceTotal to MAX_FRAGMENT_NUM + 1 (1025)
    *((uint32_t *)(data + 8)) = 1025;
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_006
 * @tc.desc: test DataAggregate with invalid fragment header - sliceIndex >= sliceTotal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_006, TestSize.Level1)
{
    uint8_t data[32] = {0};
    uint32_t sliceTotal = 5;
    uint32_t sliceIndex = 10; // > sliceTotal
    *((uint32_t *)(data + 4)) = sliceIndex;
    *((uint32_t *)(data + 8)) = sliceTotal;
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_007
 * @tc.desc: test DataAggregate with invalid fragment header - fragmentDataLen > MAX_SLICE_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_007, TestSize.Level1)
{
    uint8_t data[32] = {0};
    uint32_t fragmentDataLen = MAX_SLICE_LEN + 1; // > MAX_SLICE_LEN
    *((uint32_t *)(data + 12)) = fragmentDataLen;
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
 
/*
 * @tc.name: DATA_AGGREGATE_TEST_008
 * @tc.desc: test DataAggregate with mismatched fragmentDataLen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DATA_AGGREGATE_TEST_008, TestSize.Level1)
{
    uint8_t data[32] = {0};
    uint32_t sliceTotal = 1;
    uint32_t sliceIndex = 0;
    uint32_t fragmentDataLen = 100; // but actual data is only 16 bytes
    *((uint32_t *)(data + 0)) = 1; // msgId
    *((uint32_t *)(data + 4)) = sliceIndex;
    *((uint32_t *)(data + 8)) = sliceTotal;
    *((uint32_t *)(data + 12)) = fragmentDataLen; // 100 != (32 - 16)
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // namespace OHOS