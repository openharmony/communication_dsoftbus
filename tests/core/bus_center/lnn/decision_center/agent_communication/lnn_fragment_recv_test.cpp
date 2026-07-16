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

#include "lnn_fragment_recv.h"
#include "lnn_cloud_query_fragment.h"
#include "lnn_device_cloud_convergence_struct.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

static void TestCallback(const char *udid, const char *data, uint32_t dataLen,
    ConversationChannelType channelType, FarFieldBusiness businessType)
{
    (void)udid;
    (void)data;
    (void)dataLen;
    (void)channelType;
    (void)businessType;
}

class LnnFragmentRecvTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnFragmentRecvTest::SetUpTestCase()
{
    FragmentRecvInit();
}

void LnnFragmentRecvTest::TearDownTestCase()
{
    FragmentRecvDeinit();
}

void LnnFragmentRecvTest::SetUp() {}

void LnnFragmentRecvTest::TearDown() {}

/*
 * @tc.name: FRAGMENT_RECV_INIT_TEST_001
 * @tc.desc: test FragmentRecvInit multiple init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvInit_MultipleInit_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
}

/*
 * @tc.name: FRAGMENT_RECV_DEINIT_TEST_001
 * @tc.desc: test FragmentRecvDeinit multiple deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvDeinit_MultipleDeinit_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FragmentRecvDeinit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvDeinit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_001
 * @tc.desc: test FragmentRecvProcess with null udid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_NullUdid_Test, TestSize.Level1)
{
    uint8_t data[100] = {0};
    int32_t ret = FragmentRecvProcess(nullptr, data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_002
 * @tc.desc: test FragmentRecvProcess with null data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_NullData_Test, TestSize.Level1)
{
    int32_t ret = FragmentRecvProcess("test_udid", nullptr, 100, CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_003
 * @tc.desc: test FragmentRecvProcess with null callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_NullCallback_Test, TestSize.Level1)
{
    uint8_t data[100] = {0};
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_004
 * @tc.desc: test FragmentRecvProcess with zero dataLen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_ZeroDataLen_Test, TestSize.Level1)
{
    uint8_t data[100] = {0};
    int32_t ret = FragmentRecvProcess("test_udid", data, 0, CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_005
 * @tc.desc: test FragmentRecvProcess dataLen too large.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_DataLenTooLarge_Test, TestSize.Level1)
{
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(MAX_MSG_LEN + 1));
    ASSERT_NE(data, nullptr);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, MAX_MSG_LEN + 1, CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    SoftBusFree(data);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_006
 * @tc.desc: test FragmentRecvProcess invalid magic.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_InvalidMagic_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    uint32_t invalidMagic = 0x12345678;
    *reinterpret_cast<uint32_t *>(data) = htonl(invalidMagic);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_007
 * @tc.desc: test FragmentRecvProcess invalid module type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_InvalidModuleType_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(FAR_FIELD_BUSINESS_MAX);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_008
 * @tc.desc: test FragmentRecvProcess fast offline type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_FastOfflineType_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[FAR_FIELD_PKT_HEAD_SIZE + i] = 'a' + i;
    }
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_009
 * @tc.desc: test FragmentRecvProcess fast offline data too short.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_FastOfflineDataTooShort_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(0);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_010
 * @tc.desc: test FragmentRecvProcess agent communication type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_AgentCommunicationType_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint8_t data[totalHeaderSize + 10];
    memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[totalHeaderSize + i] = 'a' + i;
    }
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_011
 * @tc.desc: test FragmentRecvProcess data too short for header.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_DataTooShortForHeader_Test, TestSize.Level1)
{
    uint8_t data[10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_012
 * @tc.desc: test FragmentRecvProcess data too short for fragment.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_DataTooShortForFragment_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint8_t data[totalHeaderSize + 5];
    memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FRAGMENT_RECV_CLEAR_TEST_001
 * @tc.desc: test FragmentRecvClear success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvClear_Success_Test, TestSize.Level1)
{
    uint32_t msgId = 12345;
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(msgId));
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(msgId));
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(0));
}

/*
 * @tc.name: FRAGMENT_RECV_CLEAR_ALL_TEST_001
 * @tc.desc: test FragmentRecvClearAll success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvClearAll_Success_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClearAll());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClearAll());
}

/*
 * @tc.name: FRAGMENT_RECV_PROCESS_TEST_013
 * @tc.desc: test FragmentRecvProcess watch wechat type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_WatchWechatType_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint8_t data[totalHeaderSize + 10];
    memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(WATCH_WECHAT);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[totalHeaderSize + i] = 'w' + i;
    }
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_MultipleFragments_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint32_t totalDataSize = 30;
    
    uint8_t data[totalHeaderSize * 2 + 20];
    memset_s(data, sizeof(data), 0, sizeof(data));
    uint32_t offset = 0;
    
    *reinterpret_cast<uint32_t *>(data + offset) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + offset + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + offset + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE) = htonl(100);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(totalDataSize);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[offset + totalHeaderSize + i] = 'a' + i;
    }
    
    offset += totalHeaderSize + 10;
    
    *reinterpret_cast<uint32_t *>(data + offset) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + offset + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + offset + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE) = htonl(100);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + offset + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(totalDataSize);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[offset + totalHeaderSize + i] = 'b' + i;
    }
    
    int32_t ret = FragmentRecvProcess("test_udid", data, offset + totalHeaderSize + 10,
        CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_InvalidFragmentHeader_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint8_t data[totalHeaderSize + 10];
    memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(MAX_SLICE_LEN + 1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_EmptyData_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(0);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, FAR_FIELD_PKT_HEAD_SIZE,
        CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_MaxMsgLen_Test, TestSize.Level1)
{
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(MAX_MSG_LEN));
    ASSERT_NE(data, nullptr);
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(MAX_MSG_LEN - FAR_FIELD_PKT_HEAD_SIZE);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, MAX_MSG_LEN, CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    SoftBusFree(data);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvInit_AfterDeinit_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FragmentRecvDeinit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvClearAll_AfterProcess_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    for (uint32_t i = 0; i < 10; i++) {
        data[FAR_FIELD_PKT_HEAD_SIZE + i] = 'a' + i;
    }
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClearAll());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClearAll());
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_DifferentMsgId_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    
    uint8_t data1[totalHeaderSize + 10];
    memset_s(data1, sizeof(data1), 0, sizeof(data1));
    *reinterpret_cast<uint32_t *>(data1) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data1 + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data1 + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data1 + FAR_FIELD_PKT_HEAD_SIZE) = htonl(111);
    *reinterpret_cast<uint32_t *>(data1 + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data1 + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data1 + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data1, sizeof(data1), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    uint8_t data2[totalHeaderSize + 10];
    memset_s(data2, sizeof(data2), 0, sizeof(data2));
    *reinterpret_cast<uint32_t *>(data2) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data2 + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data2 + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data2 + FAR_FIELD_PKT_HEAD_SIZE) = htonl(222);
    *reinterpret_cast<uint32_t *>(data2 + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data2 + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(0);
    *reinterpret_cast<uint32_t *>(data2 + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    ret = FragmentRecvProcess("test_udid", data2, sizeof(data2), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(111));
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(222));
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_MemcpyFailedInParse_Test, TestSize.Level1)
{
    uint8_t data[5] = {0};
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_OffsetOutOfRange_Test, TestSize.Level1)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    uint8_t data[totalHeaderSize + 10];
    memset_s(data, sizeof(data), 0, sizeof(data));
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_AGENT_COMMUNICATION);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(totalHeaderSize + 10);
    
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE) = htonl(1);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 4) = htonl(10);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 8) = htonl(1000);
    *reinterpret_cast<uint32_t *>(data + FAR_FIELD_PKT_HEAD_SIZE + 12) = htonl(10);
    
    EXPECT_NO_FATAL_FAILURE(FragmentRecvProcess("test_udid", data, sizeof(data),
        CONVERSATION_FAR_FIELD_PUSH, TestCallback));
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_MagicValidation_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE + 1);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(TYPE_LNN_FAST_OFFLINE);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE - 1);
    ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvProcess_ModuleTypeBoundary_Test, TestSize.Level1)
{
    uint8_t data[FAR_FIELD_PKT_HEAD_SIZE + 10] = {0};
    
    *reinterpret_cast<uint32_t *>(data) = htonl(0xBABEFACE);
    *reinterpret_cast<uint32_t *>(data + 4) = htonl(FAR_FIELD_BUSINESS_MAX - 1);
    *reinterpret_cast<uint32_t *>(data + 8) = htonl(10);
    
    int32_t ret = FragmentRecvProcess("test_udid", data, sizeof(data), CONVERSATION_FAR_FIELD_PUSH, TestCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(LnnFragmentRecvTest, FragmentRecvDeinit_AfterClear_Test, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClear(12345));
    EXPECT_NO_FATAL_FAILURE(FragmentRecvClearAll());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvDeinit());
    EXPECT_NO_FATAL_FAILURE(FragmentRecvInit());
}

} // namespace OHOS