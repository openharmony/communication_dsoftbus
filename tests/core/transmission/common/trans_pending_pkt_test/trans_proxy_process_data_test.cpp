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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_def.h"
#include "trans_common_mock.h"
#include "trans_proxy_process_data.c"

using namespace testing::ext;

static constexpr int32_t testChannelId = 1314;
static constexpr uint32_t testLen = 18;

namespace OHOS {
class TransProxyProcessDataTest : public testing::Test {
public:
    TransProxyProcessDataTest() { }
    ~TransProxyProcessDataTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransProxyProcessDataTest::SetUpTestCase(void)
{
    std::cout << "test begin in" << std::endl;
}

void TransProxyProcessDataTest::TearDownTestCase(void)
{
    std::cout << "test end out" << std::endl;
}

/*
 * @tc.name: TransGetProxyDataBufMaxSize001
 * @tc.desc: TransGetProxyDataBufMaxSize test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransGetProxyDataBufMaxSize001, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftbusGetConfig)
    .Times(4)
    .WillOnce(testing::Return(SOFTBUS_GET_CONFIG_VAL_ERR))
    .WillOnce(testing::Return(SOFTBUS_GET_CONFIG_VAL_ERR))
    .WillOnce(testing::Return(SOFTBUS_GET_CONFIG_VAL_ERR))
    .WillOnce(testing::Return(SOFTBUS_GET_CONFIG_VAL_ERR));
    EXPECT_NO_FATAL_FAILURE(TransGetProxyDataBufMaxSize());
}

/*
 * @tc.name: TransUnPackTlvPackHead001
 * @tc.desc: TransUnPackTlvPackHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransUnPackTlvPackHead001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(TransUnPackTlvPackHead(nullptr));
}

/*
 * @tc.name: TransPackSliceHead001
 * @tc.desc: TransPackSliceHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransPackSliceHead001, TestSize.Level1)
{
    SliceHead sliceHead = { 1, 2, 3, 4 };
    EXPECT_NO_FATAL_FAILURE(TransPackSliceHead(&sliceHead));
}

/*
 * @tc.name: TransPackPacketHead001
 * @tc.desc: TransPackPacketHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransPackPacketHead001, TestSize.Level1)
{
    PacketHead packetHead = { 4, 3, 2, 1 };
    EXPECT_NO_FATAL_FAILURE(TransPackPacketHead(&packetHead));
}

/*
 * @tc.name: TransUnPackPacketHead001
 * @tc.desc: TransUnPackPacketHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransUnPackPacketHead001, TestSize.Level1)
{
    PacketHead packetHead = { 6, 6, 6, 6 };
    EXPECT_NO_FATAL_FAILURE(TransUnPackPacketHead(&packetHead));
}

/*
 * @tc.name: TransProxyPackBytes001
 * @tc.desc: TransProxyPackBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackBytes001, TestSize.Level1)
{
    const char *sessionKey = "initial_sessionKey_value";
    int32_t ret = TransProxyPackBytes(testChannelId, nullptr, sessionKey, TRANS_SESSION_BYTES, 26);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyPackBytes002
 * @tc.desc: TransProxyPackBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackBytes002, TestSize.Level1)
{
    ProxyDataInfo proxyDataInfo;
    int32_t ret = TransProxyPackBytes(testChannelId, &proxyDataInfo, nullptr, TRANS_SESSION_BYTES, 12);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyPackBytes003
 * @tc.desc: TransProxyPackBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackBytes003, TestSize.Level1)
{
    ProxyDataInfo proxyDataInfo;
    const char *sessionKey = "test_sessionKey_value";

    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusCalloc).WillOnce(testing::Return(nullptr));
    int32_t ret = TransProxyPackBytes(testChannelId, &proxyDataInfo, sessionKey, TRANS_SESSION_BYTES, 66);
    EXPECT_EQ(proxyDataInfo.outData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
}

/*
 * @tc.name: ProxyBuildTlvDataHead001
 * @tc.desc: ProxyBuildTlvDataHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, ProxyBuildTlvDataHead001, TestSize.Level1)
{
    int32_t tlvBufferSize;
    int32_t ret = ProxyBuildTlvDataHead(nullptr, 1, 1, 12, &tlvBufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ProxyBuildTlvDataHead002
 * @tc.desc: ProxyBuildTlvDataHead test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, ProxyBuildTlvDataHead002, TestSize.Level1)
{
    int32_t tlvBufferSize;
    DataHead pktHead;

    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusCalloc).WillOnce(testing::Return(nullptr));
    int32_t ret = ProxyBuildTlvDataHead(&pktHead, 1, 1, 12, &tlvBufferSize);
    EXPECT_EQ(pktHead.tlvElement, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
}

/*
 * @tc.name: TransProxyPackTlvBytes001
 * @tc.desc: TransProxyPackTlvBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackTlvBytes001, TestSize.Level1)
{
    const char *sessionKey = "test_session_key";
    DataHeadTlvPacketHead info;
    int32_t ret = TransProxyPackTlvBytes(nullptr, sessionKey, TRANS_SESSION_MESSAGE, 3, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyPackTlvBytes002
 * @tc.desc: TransProxyPackTlvBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackTlvBytes002, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    DataHeadTlvPacketHead info;
    int32_t ret = TransProxyPackTlvBytes(&dataInfo, nullptr, TRANS_SESSION_MESSAGE, 3, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyPackTlvBytes003
 * @tc.desc: TransProxyPackTlvBytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackTlvBytes003, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    const char *sessionKey = "test_session_key";
    int32_t ret = TransProxyPackTlvBytes(&dataInfo, sessionKey, TRANS_SESSION_MESSAGE, 3, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyPackData001
 * @tc.desc: TransProxyPackData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackData001, TestSize.Level1)
{
    ProxyDataInfo dataInfo;

    uint8_t *ret = TransProxyPackData(&dataInfo, 1, TRANS_SESSION_BYTES, 16, nullptr);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: TransProxyPackData002
 * @tc.desc: TransProxyPackData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackData002, TestSize.Level1)
{
    uint32_t dataLen;

    uint8_t *ret = TransProxyPackData(nullptr, 1, TRANS_SESSION_BYTES, 16, &dataLen);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: TransProxyPackData003
 * @tc.desc: TransProxyPackData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyPackData003, TestSize.Level1)
{
    uint32_t dataLen;
    ProxyDataInfo dataInfo;

    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusCalloc).WillOnce(testing::Return(nullptr));
    uint8_t *ret = TransProxyPackData(&dataInfo, 1, TRANS_SESSION_BYTES, 2, &dataLen);
    EXPECT_EQ(dataLen, SLICE_LEN);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: TransProxyNoSubPacketProc001
 * @tc.desc: TransProxyNoSubPacketProc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyNoSubPacketProc001, TestSize.Level1)
{
    PacketHead head;
    int32_t ret = TransProxyNoSubPacketProc(&head, testLen, nullptr, testChannelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyNoSubPacketProc002
 * @tc.desc: TransProxyNoSubPacketProc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyNoSubPacketProc002, TestSize.Level1)
{
    const char *data = "jhejfu3ewmnf2-2jfg-2-jkfkw[w]";
    int32_t ret = TransProxyNoSubPacketProc(nullptr, testLen, data, testChannelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyNoSubPacketProc003
 * @tc.desc: TransProxyNoSubPacketProc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyProcessDataTest, TransProxyNoSubPacketProc003, TestSize.Level1)
{
    PacketHead head;
    const char *data = "jhejfu3ewmnf2-2jfg-2-jkfkw[w]";
    int32_t ret = TransProxyNoSubPacketProc(&head, 15, data, testChannelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // OHOS
