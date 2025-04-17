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

#include "trans_proxy_process_data.h"
#include "trans_proxy_process_data.c"
#include "trans_tcp_process_data.h"
#include "trans_tcp_process_data.c"

using namespace testing::ext;

namespace OHOS {
#define TEST_CHANNEL_ID 1124

class TransProcessDataTest : public testing::Test {
public:
    TransProcessDataTest()
    {}
    ~TransProcessDataTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProcessDataTest::SetUpTestCase(void) {}

void TransProcessDataTest::TearDownTestCase(void) {}

/**
 * @tc.name: TransProcessDataTest001
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest001, TestSize.Level1)
{
    TransUnPackTlvPackHead(nullptr);
    TransUnPackSliceHead(nullptr);

    int32_t channelId = TEST_CHANNEL_ID;
    SessionPktType flag = TRANS_SESSION_BYTES;
    int32_t seq = 1;
    int32_t ret = TransProxyPackBytes(channelId, nullptr, nullptr, flag, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ProxyDataInfo *dataInfo = static_cast<ProxyDataInfo *>(SoftBusCalloc(sizeof(ProxyDataInfo)));
    EXPECT_NE(nullptr, dataInfo);
    const char *sessionkey = "testSessionKey";
    ret = TransProxyPackBytes(channelId, dataInfo, sessionkey, flag, seq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR, ret);

    SoftBusFree(dataInfo);
}

/**
 * @tc.name: TransProcessDataTest002
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest002, TestSize.Level1)
{
    int32_t finalSeq = 1;
    int32_t flagTest = 1;
    uint32_t dataLen = 1;
    int32_t tlvBufferSize = 1;
    int32_t ret = ProxyBuildTlvDataHead(nullptr, finalSeq, flagTest, dataLen, &tlvBufferSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ProxyDataInfo *dataInfo = static_cast<ProxyDataInfo *>(SoftBusCalloc(sizeof(ProxyDataInfo)));
    EXPECT_NE(nullptr, dataInfo);
    DataHeadTlvPacketHead *info = static_cast<DataHeadTlvPacketHead *>(SoftBusCalloc(sizeof(DataHeadTlvPacketHead)));
    EXPECT_NE(nullptr, info);
    const char *sessionKey = "testSessionKey";
    SessionPktType flag = TRANS_SESSION_BYTES;
    int32_t seq = 1;
    ret = TransProxyPackTlvBytes(nullptr, sessionKey, flag, seq, info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPackTlvBytes(dataInfo, nullptr, flag, seq, info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPackTlvBytes(dataInfo, sessionKey, flag, seq, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPackTlvBytes(dataInfo, sessionKey, flag, seq, info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR, ret);

    SoftBusFree(dataInfo);
    SoftBusFree(info);
}

/**
 * @tc.name: TransProcessDataTest003
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest003, TestSize.Level1)
{
    uint32_t sliceNum = 1;
    SessionPktType pktType = TRANS_SESSION_BYTES;
    uint32_t cnt = 1;
    uint32_t dataLen = 1;

    EXPECT_EQ(nullptr, TransProxyPackData(nullptr, sliceNum, pktType, cnt, &dataLen));

    ProxyDataInfo *dataInfo = static_cast<ProxyDataInfo *>(SoftBusCalloc(sizeof(ProxyDataInfo)));
    EXPECT_NE(nullptr, dataInfo);
    EXPECT_EQ(nullptr, TransProxyPackData(nullptr, sliceNum, pktType, cnt, &dataLen));

    dataInfo->outLen = SLICE_LEN;
    EXPECT_EQ(nullptr, TransProxyPackData(nullptr, sliceNum, pktType, cnt, &dataLen));
    SoftBusFree(dataInfo);
}

/**
 * @tc.name: TransProcessDataTest004
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest004, TestSize.Level1)
{
    uint32_t len = 1;
    const char *data = "12121212";
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransProxyNoSubPacketProc(nullptr, len, data, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    PacketHead *head = static_cast<PacketHead *>(SoftBusCalloc(sizeof(PacketHead)));
    EXPECT_NE(nullptr, head);
    ret = TransProxyNoSubPacketProc(head, len, nullptr, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyNoSubPacketProc(head, len, data, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    len = 1000; // test value
    ret = TransProxyNoSubPacketProc(head, len, data, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
    SoftBusFree(head);
}

/**
 * @tc.name: TransProcessDataTest005
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest005, TestSize.Level1)
{
    const char *data = "121212"; // test value
    PacketHead dataHead;
    (void)memset_s(&dataHead, sizeof(PacketHead), 0, sizeof(PacketHead));
    int32_t ret = TransProxyProcessSessionData(nullptr, &dataHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ProxyDataInfo *dataInfo = static_cast<ProxyDataInfo *>(SoftBusCalloc(sizeof(ProxyDataInfo)));
    EXPECT_NE(nullptr, dataInfo);
    ret = TransProxyProcessSessionData(dataInfo, nullptr, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyProcessSessionData(dataInfo, &dataHead, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransProxyClearProcessor(nullptr);
    SliceProcessor *processor = static_cast<SliceProcessor *>(SoftBusCalloc(sizeof(SliceProcessor)));
    EXPECT_NE(nullptr, processor);
    processor->data = static_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_NE(nullptr, processor->data);
    TransProxyClearProcessor(processor);
    SoftBusFree(dataInfo);
    SoftBusFree(processor->data);
    SoftBusFree(processor);
}

/**
 * @tc.name: TransProcessDataTest006
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest006, TestSize.Level1)
{
    int32_t seq = 1;
    ProxyDataInfo *dataInfo = static_cast<ProxyDataInfo *>(SoftBusCalloc(sizeof(ProxyDataInfo)));
    EXPECT_NE(nullptr, dataInfo);

    const char *sessionKey = "1111"; // test value
    int32_t ret = TransProxyDecryptPacketData(seq, nullptr, sessionKey);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyDecryptPacketData(seq, dataInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyDecryptPacketData(seq, dataInfo, sessionKey);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    SoftBusFree(dataInfo);
}

/**
 * @tc.name: TransProcessDataTest007
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest007, TestSize.Level1)
{
    SliceProcessor *processor = static_cast<SliceProcessor *>(SoftBusCalloc(sizeof(SliceProcessor)));
    EXPECT_NE(nullptr, processor);
    SliceHead *head = static_cast<SliceHead *>(SoftBusCalloc(sizeof(SliceHead)));
    EXPECT_NE(nullptr, head);

    const char *data = "121212"; // test value
    uint32_t len = 1;
    bool supportTlv = true;
    int32_t ret = TransProxyFirstSliceProcess(nullptr, head, data, len, supportTlv);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyFirstSliceProcess(processor, nullptr, data, len, supportTlv);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyFirstSliceProcess(processor, head, nullptr, len, supportTlv);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    head->priority = PROXY_CHANNEL_PRORITY_MESSAGE;
    head->sliceNum = -1; // test value
    ret = TransProxyFirstSliceProcess(processor, head, data, len, supportTlv);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    head->sliceNum = 1;
    ret = TransProxyFirstSliceProcess(processor, head, data, len, supportTlv);
    EXPECT_EQ(SOFTBUS_OK, ret);

    supportTlv = false;
    ret = TransProxyFirstSliceProcess(processor, head, data, len, supportTlv);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(processor);
    SoftBusFree(head);
}

/**
 * @tc.name: TransProcessDataTest008
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest008, TestSize.Level1)
{
    SliceProcessor *processor = static_cast<SliceProcessor *>(SoftBusCalloc(sizeof(SliceProcessor)));
    EXPECT_NE(nullptr, processor);
    SliceHead *head = static_cast<SliceHead *>(SoftBusCalloc(sizeof(SliceHead)));
    EXPECT_NE(nullptr, head);

    const char *data = "121212";
    uint32_t len = 1;
    int32_t ret = TransProxySliceProcessChkPkgIsValid(nullptr, head, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxySliceProcessChkPkgIsValid(processor, nullptr, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    head->sliceNum = 1;
    processor->sliceNumber = 1;
    head->sliceSeq = 1;
    processor->expectedSeq = 1;
    processor->dataLen = 5; // test value
    processor->bufLen = 10; // test value
    processor->data = static_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_NE(nullptr, processor->data);

    ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(processor->data);
    SoftBusFree(processor);
    SoftBusFree(head);
}

/**
 * @tc.name: TransProcessDataTest009
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest009, TestSize.Level1)
{
    uint32_t len = 1;
    int32_t ret = TransGetActualDataLen(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyNormalSliceProcess(nullptr, nullptr, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SliceProcessor *processor = static_cast<SliceProcessor *>(SoftBusCalloc(sizeof(SliceProcessor)));
    EXPECT_NE(nullptr, processor);
    SliceHead *head = static_cast<SliceHead *>(SoftBusCalloc(sizeof(SliceHead)));
    EXPECT_NE(nullptr, head);

    const char *data = "121212";
    head->sliceNum = 1;
    processor->sliceNumber = 1;
    head->sliceSeq = 1;
    processor->expectedSeq = 1;
    processor->dataLen = 5; // test value
    processor->bufLen = 10; // test value
    processor->data = static_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_NE(nullptr, processor->data);

    TransProxyNormalSliceProcess(processor, head, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(processor->data);
    SoftBusFree(processor);
    SoftBusFree(head);
}

/**
 * @tc.name: TransProcessDataTest010
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest010, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    const char *data = "121212"; // test value
    uint32_t len = 1;
    uint32_t newPktHeadSize = 1;

    int32_t ret = TransProxyNoSubPacketTlvProc(channelId, data, len, nullptr, newPktHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProcessDataTest011
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest011, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t dataLen = 1;
    int32_t pkgHeadSize = 1;

    DataBuf *node = static_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    EXPECT_NE(nullptr, node);
    node->data = static_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_NE(nullptr, node->data);
    node->w = static_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_NE(nullptr, node->w);

    int32_t ret = MoveNode(channelId, nullptr, dataLen, pkgHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = MoveNode(channelId, node, dataLen, pkgHeadSize);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    SoftBusFree(node->w);
    SoftBusFree(node->data);
    SoftBusFree(node);
}

/**
 * @tc.name: TransProcessDataTest012
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest012, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t fd = 0;
    size_t len = 1;

    int32_t ret = TransTdcRecvFirstData(channelId, nullptr, nullptr, fd, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransTdcUnPackAllData(channelId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProcessDataTest013
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest013, TestSize.Level1)
{
    bool supportTlv = true;
    int32_t fd = 0;
    uint32_t len = 1;
    int32_t ret = TransTdcSendData(nullptr, supportTlv, fd, len, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    DataLenInfo *lenInfo = static_cast<DataLenInfo *>(SoftBusCalloc(sizeof(DataLenInfo)));
    EXPECT_NE(nullptr, lenInfo);
    lenInfo->outLen = 1;
    char buf[64] = "1212"; // test value
    ret = TransTdcSendData(lenInfo, supportTlv, fd, len, buf);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);

    lenInfo->outLen = 29; // test value
    ret = TransTdcSendData(lenInfo, supportTlv, fd, len, buf);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_SOCKET, ret);
    SoftBusFree(lenInfo);
}

/**
 * @tc.name: TransProcessDataTest014
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest014, TestSize.Level1)
{
    int32_t flag = FLAG_ACK;
    EXPECT_EQ(nullptr, TransTdcPackAllData(nullptr, nullptr, nullptr, flag, nullptr));

    TransTdcPackDataInfo *info = static_cast<TransTdcPackDataInfo *>(SoftBusCalloc(sizeof(TransTdcPackDataInfo)));
    EXPECT_NE(nullptr, info);
    info->len = 1;
    info->seq = 1;
    info->supportTlv = true;
    const char *sessionKey = "121212"; // test value
    const char *data = "1111"; // test value
    DataLenInfo *lenInfo = static_cast<DataLenInfo *>(SoftBusCalloc(sizeof(DataLenInfo)));
    EXPECT_NE(nullptr, lenInfo);
    EXPECT_NE(nullptr, TransTdcPackAllData(info, sessionKey, data, flag, lenInfo));

    int32_t finalSeq = 1;
    int32_t flags = 1;
    uint32_t dataLen = 1;
    int32_t ret = BuildDataHead(nullptr, finalSeq, flags, dataLen, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
    SoftBusFree(lenInfo);
}

/**
 * @tc.name: TransProcessDataTest015
 * @tc.desc: Transmission session manager initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProcessDataTest, TransProcessDataTest015, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransTdcUnPackAllTlvData(channelId, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint32_t bufLen = 0;
    uint32_t headSize = 1;
    ret = CheckBufLenAndCopyData(bufLen, headSize, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_DATA_NOT_ENOUGH, ret);

    ret = TransTdcUnPackData(channelId, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
}
