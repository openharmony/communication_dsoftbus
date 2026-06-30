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
#include <arpa/inet.h>

#include "lnn_cloud_query_fragment.h"
#include "lnn_device_cloud_convergence_struct.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

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

void LnnCloudQueryFragmentTest::SetUpTestCase()
{
    DataFragmentInit();
}

void LnnCloudQueryFragmentTest::TearDownTestCase() {}

void LnnCloudQueryFragmentTest::SetUp() {}

void LnnCloudQueryFragmentTest::TearDown() {}

/* ==================== 初始化测试 ==================== */

/*
 * @tc.name: DATA_FRAGMENT_INIT_TEST_001
 * @tc.desc: test DataFragmentInit multiple init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataFragmentInit_MultipleInit_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DataFragmentInit());
    EXPECT_NO_FATAL_FAILURE(DataFragmentInit());
    EXPECT_NO_FATAL_FAILURE(DataFragmentInit());
}

/* ==================== GenerateMsgId测试 ==================== */

/*
 * @tc.name: GENERATE_MSG_ID_TEST_001
 * @tc.desc: test GenerateMsgId success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, GenerateMsgId_Success_Test, TestSize.Level1)
{
    uint32_t msgId1 = GenerateMsgId();
    EXPECT_NE(msgId1, 0);
    
    uint32_t msgId2 = GenerateMsgId();
    EXPECT_NE(msgId2, 0);
    EXPECT_NE(msgId1, msgId2);
    
    uint32_t msgId3 = GenerateMsgId();
    EXPECT_NE(msgId3, 0);
}

/* ==================== WriteFragmentHeader测试 ==================== */

/*
 * @tc.name: WRITE_FRAGMENT_HEADER_TEST_001
 * @tc.desc: test WriteFragmentHeader buffer too small.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, WriteFragmentHeader_BufferTooSmall_Test, TestSize.Level1)
{
    uint8_t buffer[10] = {0};
    DataFragmentInfo header = {1, 100, 0, 1000};
    
    EXPECT_NO_FATAL_FAILURE(WriteFragmentHeader(buffer, sizeof(buffer), &header));
}

/*
 * @tc.name: WRITE_FRAGMENT_HEADER_TEST_002
 * @tc.desc: test WriteFragmentHeader success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, WriteFragmentHeader_Success_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    DataFragmentInfo header = {12345, 100, 0, 1000};
    
    WriteFragmentHeader(buffer, FRAGMENT_HEADER_LEN, &header);
    
    uint32_t msgId = ntohl(*reinterpret_cast<uint32_t *>(buffer));
    EXPECT_EQ(msgId, 12345);
    
    uint32_t size = ntohl(*reinterpret_cast<uint32_t *>(buffer + 4));
    EXPECT_EQ(size, 100);
    
    uint32_t offset = ntohl(*reinterpret_cast<uint32_t *>(buffer + 8));
    EXPECT_EQ(offset, 0);
    
    uint32_t total = ntohl(*reinterpret_cast<uint32_t *>(buffer + 12));
    EXPECT_EQ(total, 1000);
}

/*
 * @tc.name: WRITE_FRAGMENT_HEADER_TEST_003
 * @tc.desc: test WriteFragmentHeader with large values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, WriteFragmentHeader_LargeValues_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    DataFragmentInfo header = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    
    WriteFragmentHeader(buffer, FRAGMENT_HEADER_LEN, &header);
    
    uint32_t msgId = ntohl(*reinterpret_cast<uint32_t *>(buffer));
    EXPECT_EQ(msgId, 0xFFFFFFFF);
}

/*
 * @tc.name: WRITE_FRAGMENT_HEADER_TEST_004
 * @tc.desc: test WriteFragmentHeader with zero values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, WriteFragmentHeader_ZeroValues_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    DataFragmentInfo header = {0, 0, 0, 0};
    
    WriteFragmentHeader(buffer, FRAGMENT_HEADER_LEN, &header);
    
    uint32_t msgId = ntohl(*reinterpret_cast<uint32_t *>(buffer));
    EXPECT_EQ(msgId, 0);
}

/* ==================== ParseFragmentHeader测试 ==================== */

/*
 * @tc.name: PARSE_FRAGMENT_HEADER_TEST_001
 * @tc.desc: test ParseFragmentHeader with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, ParseFragmentHeader_NullData_Test, TestSize.Level1)
{
    DataFragmentInfo header = {0};
    int32_t ret = ParseFragmentHeader(nullptr, FRAGMENT_HEADER_LEN, &header);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: PARSE_FRAGMENT_HEADER_TEST_002
 * @tc.desc: test ParseFragmentHeader with null header.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, ParseFragmentHeader_NullHeader_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    int32_t ret = ParseFragmentHeader(buffer, FRAGMENT_HEADER_LEN, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: PARSE_FRAGMENT_HEADER_TEST_003
 * @tc.desc: test ParseFragmentHeader data len too small.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, ParseFragmentHeader_DataLenTooSmall_Test, TestSize.Level1)
{
    uint8_t buffer[10] = {0};
    DataFragmentInfo header = {0};
    int32_t ret = ParseFragmentHeader(buffer, sizeof(buffer), &header);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: PARSE_FRAGMENT_HEADER_TEST_004
 * @tc.desc: test ParseFragmentHeader success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, ParseFragmentHeader_Success_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    *reinterpret_cast<uint32_t *>(buffer) = htonl(12345);
    *reinterpret_cast<uint32_t *>(buffer + 4) = htonl(100);
    *reinterpret_cast<uint32_t *>(buffer + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(buffer + 12) = htonl(1000);
    
    DataFragmentInfo header = {0};
    int32_t ret = ParseFragmentHeader(buffer, FRAGMENT_HEADER_LEN, &header);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(header.msgId, 12345);
    EXPECT_EQ(header.size, 100);
    EXPECT_EQ(header.offset, 0);
    EXPECT_EQ(header.total, 1000);
}

/*
 * @tc.name: PARSE_FRAGMENT_HEADER_TEST_005
 * @tc.desc: test ParseFragmentHeader with all zeros.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, ParseFragmentHeader_AllZeros_Test, TestSize.Level1)
{
    uint8_t buffer[FRAGMENT_HEADER_LEN] = {0};
    DataFragmentInfo header = {0};
    
    int32_t ret = ParseFragmentHeader(buffer, FRAGMENT_HEADER_LEN, &header);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(header.msgId, 0);
    EXPECT_EQ(header.size, 0);
    EXPECT_EQ(header.offset, 0);
    EXPECT_EQ(header.total, 0);
}

/* ==================== DataSlice测试 ==================== */

/*
 * @tc.name: DATA_SLICE_TEST_001
 * @tc.desc: test DataSlice with null info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_NullInfo_Test, TestSize.Level1)
{
    int32_t ret = DataSlice("test_udid", nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_002
 * @tc.desc: test DataSlice with null udid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_NullUdid_Test, TestSize.Level1)
{
    uint8_t data[] = "test_data";
    DataFragmentMsgInfo info = {data, sizeof(data), MAX_SLICE_LEN, 1};
    int32_t ret = DataSlice(nullptr, &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_003
 * @tc.desc: test DataSlice with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_NullData_Test, TestSize.Level1)
{
    DataFragmentMsgInfo info = {nullptr, 100, MAX_SLICE_LEN, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_004
 * @tc.desc: test DataSlice with zero data len.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_ZeroDataLen_Test, TestSize.Level1)
{
    uint8_t data[] = "test";
    DataFragmentMsgInfo info = {data, 0, MAX_SLICE_LEN, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_005
 * @tc.desc: test DataSlice with zero slice len.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_ZeroSliceLen_Test, TestSize.Level1)
{
    uint8_t data[] = "test_data";
    DataFragmentMsgInfo info = {data, sizeof(data), 0, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_006
 * @tc.desc: test DataSlice slice len too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_SliceLenTooLarge_Test, TestSize.Level1)
{
    uint8_t data[] = "test_data";
    DataFragmentMsgInfo info = {data, sizeof(data), MAX_SLICE_LEN + 1, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_SLICE_TEST_007
 * @tc.desc: test DataSlice data len too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_DataLenTooLarge_Test, TestSize.Level1)
{
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(11 * 1024 * 1024));
    ASSERT_NE(data, nullptr);
    
    DataFragmentMsgInfo info = {data, 11 * 1024 * 1024, MAX_SLICE_LEN, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    SoftBusFree(data);
}

/*
 * @tc.name: DATA_SLICE_TEST_008
 * @tc.desc: test DataSlice slice total too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataSlice_SliceTotalTooLarge_Test, TestSize.Level1)
{
    uint32_t dataLen = 1024 * 1024 * 10;
    uint32_t sliceLen = 100;
    
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(dataLen));
    ASSERT_NE(data, nullptr);
    memset_s(data, dataLen, 'a', dataLen);
    
    DataFragmentMsgInfo info = {data, dataLen, sliceLen, 1};
    int32_t ret = DataSlice("test_udid", &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    SoftBusFree(data);
}

/* ==================== DataAggregate测试 ==================== */

/*
 * @tc.name: DATA_AGGREGATE_TEST_001
 * @tc.desc: test DataAggregate with null param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_NullParam_Test, TestSize.Level1)
{
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(nullptr, 100, &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_002
 * @tc.desc: test DataAggregate with null assembledData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_NullAssembledData_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), nullptr, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_003
 * @tc.desc: test DataAggregate with null assembledLen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_NullAssembledLen_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    uint8_t *assembledData = nullptr;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, nullptr, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_004
 * @tc.desc: test DataAggregate with null msgId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_NullMsgId_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_005
 * @tc.desc: test DataAggregate data len too small.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_DataLenTooSmall_Test, TestSize.Level1)
{
    uint8_t data[10] = {0};
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_006
 * @tc.desc: test DataAggregate total too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_TotalTooLarge_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(11 * 1024 * 1024);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_007
 * @tc.desc: test DataAggregate size too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_SizeTooLarge_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(MAX_SLICE_LEN + 1);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_008
 * @tc.desc: test DataAggregate offset overflow.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_OffsetOverflow_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(1000);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(100);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_009
 * @tc.desc: test DataAggregate size mismatch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_SizeMismatch_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(100);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_010
 * @tc.desc: test DataAggregate offset size overflow.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_OffsetSizeOverflow_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(95);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(100);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_011
 * @tc.desc: test DataAggregate valid fragment.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_ValidFragment_Test, TestSize.Level1)
{
    uint32_t totalSize = 100;
    uint32_t fragSize = 10;
    uint8_t data[FRAGMENT_HEADER_LEN + fragSize];
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(fragSize);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(totalSize);
    
    for (uint32_t i = 0; i < fragSize; i++) {
        data[FRAGMENT_HEADER_LEN + i] = 'a' + i;
    }
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(msgId, 1);
    EXPECT_EQ(assembledLen, 0);
    
    if (assembledData != nullptr) {
        SoftBusFree(assembledData);
    }
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_012
 * @tc.desc: test DataAggregate multiple fragments.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_MultipleFragments_Test, TestSize.Level1)
{
    uint32_t totalSize = 30;
    uint32_t fragSize = 10;
    uint32_t msgId = 12345;
    
    for (uint32_t i = 0; i < 3; i++) {
        uint8_t data[FRAGMENT_HEADER_LEN + fragSize];
        (void)memset_s(data, sizeof(data), 0, sizeof(data));
        *reinterpret_cast<uint32_t *>(data) = htonl(msgId);
        *reinterpret_cast<uint32_t *>(data + 4) = htonl(fragSize);
        *reinterpret_cast<uint32_t *>(data + 8) = htonl(i * fragSize);
        *reinterpret_cast<uint32_t *>(data + 12) = htonl(totalSize);
        
        for (uint32_t j = 0; j < fragSize; j++) {
            data[FRAGMENT_HEADER_LEN + j] = 'a' + i * fragSize + j;
        }
        
        uint8_t *assembledData = nullptr;
        uint32_t assembledLen = 0;
        uint32_t recvMsgId = 0;
        
        int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &recvMsgId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        EXPECT_EQ(recvMsgId, msgId);
        
        if (i == 2) {
            EXPECT_EQ(assembledLen, totalSize);
            if (assembledData != nullptr) {
                SoftBusFree(assembledData);
            }
        } else {
            EXPECT_EQ(assembledLen, 0);
        }
    }
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_013
 * @tc.desc: test DataAggregate same msgId fragments.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_SameMsgIdFragments_Test, TestSize.Level1)
{
    uint32_t totalSize = 20;
    uint32_t fragSize = 10;
    uint32_t msgId = 999;
    
    uint8_t data1[FRAGMENT_HEADER_LEN + fragSize];
    (void)memset_s(data1, sizeof(data1), 0, sizeof(data1));
    *reinterpret_cast<uint32_t *>(data1) = htonl(msgId);
    *reinterpret_cast<uint32_t *>(data1 + 4) = htonl(fragSize);
    *reinterpret_cast<uint32_t *>(data1 + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data1 + 12) = htonl(totalSize);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t recvMsgId = 0;
    
    int32_t ret = DataAggregate(data1, sizeof(data1), &assembledData, &assembledLen, &recvMsgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(recvMsgId, msgId);
    
    uint8_t data2[FRAGMENT_HEADER_LEN + fragSize];
    (void)memset_s(data2, sizeof(data2), 0, sizeof(data2));
    *reinterpret_cast<uint32_t *>(data2) = htonl(msgId);
    *reinterpret_cast<uint32_t *>(data2 + 4) = htonl(fragSize);
    *reinterpret_cast<uint32_t *>(data2 + 8) = htonl(fragSize);
    *reinterpret_cast<uint32_t *>(data2 + 12) = htonl(totalSize);
    
    assembledData = nullptr;
    assembledLen = 0;
    recvMsgId = 0;
    
    ret = DataAggregate(data2, sizeof(data2), &assembledData, &assembledLen, &recvMsgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(recvMsgId, msgId);
    EXPECT_EQ(assembledLen, totalSize);
    
    if (assembledData != nullptr) {
        SoftBusFree(assembledData);
    }
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_014
 * @tc.desc: test DataAggregate complete assembly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_CompleteAssembly_Test, TestSize.Level1)
{
    uint32_t totalSize = 10;
    uint32_t fragSize = 10;
    
    uint8_t data[FRAGMENT_HEADER_LEN + fragSize];
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    *reinterpret_cast<uint32_t *>(data) = htonl(888);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(fragSize);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(totalSize);
    
    for (uint32_t i = 0; i < fragSize; i++) {
        data[FRAGMENT_HEADER_LEN + i] = 'X';
    }
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(msgId, 888);
    EXPECT_EQ(assembledLen, totalSize);
    
    if (assembledData != nullptr) {
        for (uint32_t i = 0; i < assembledLen; i++) {
            EXPECT_EQ(assembledData[i], 'X');
        }
        SoftBusFree(assembledData);
    }
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_015
 * @tc.desc: test DataAggregate fragment offset not zero.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_FragmentOffsetNotZero_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(20);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(msgId, 1);
    EXPECT_EQ(assembledLen, 0);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_016
 * @tc.desc: test DataAggregate different msgId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_DifferentMsgId_Test, TestSize.Level1)
{
    uint8_t data1[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data1) = htonl(100);
    *reinterpret_cast<uint32_t *>(data1 + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data1 + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data1 + 12) = htonl(20);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data1, sizeof(data1), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(msgId, 100);
    
    uint8_t data2[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data2) = htonl(200);
    *reinterpret_cast<uint32_t *>(data2 + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data2 + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data2 + 12) = htonl(20);
    
    assembledData = nullptr;
    assembledLen = 0;
    msgId = 0;
    
    ret = DataAggregate(data2, sizeof(data2), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(msgId, 200);
}

/*
 * @tc.name: DATA_AGGREGATE_TEST_017
 * @tc.desc: test DataAggregate large slice size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnCloudQueryFragmentTest, DataAggregate_LargeSliceSize_Test, TestSize.Level1)
{
    uint8_t data[FRAGMENT_HEADER_LEN + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(MAX_SLICE_LEN);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + 12) = htonl(MAX_SLICE_LEN);
    
    uint8_t *assembledData = nullptr;
    uint32_t assembledLen = 0;
    uint32_t msgId = 0;
    
    int32_t ret = DataAggregate(data, sizeof(data), &assembledData, &assembledLen, &msgId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

} // namespace OHOS