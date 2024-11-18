/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_INVALID_DATA_LEN (70 * 1024)
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_BUFFER_SIZE 100
#define TEST_CONN_HEAD_SIZE 24
#define TEST_MAGIC_NUMBER 0xBABEFACE

#define TEST_DEFAULT_DATA_LEN 10
#define TEST_VALID_DATA_LEN 20
#define TEST_VALID_LARGE_DATA_LEN 60
#define TEST_VALID_NO_SLICE_DATALEN 40
#define TEST_VALID_NO_SLICE_DEFAULT_LEN 30
#define TEST_INVALID_NO_SLICE_DATASLEN 20
#define TEST_ACK_DATA_LEN 32
#define TEST_ACK_DATA_LEN_ONE_BYTES 8

#define TEST_INVALID_PRIORITY 3
#define TEST_VALID_PRIORITY 2
#define TEST_SLICENUM_TWO 2
#define TEST_SLICESEQ_TWO 2
#define TEST_SLICESEQ_THREE 3

#define TEST_VALID_CHANNELIDA 50
#define TEST_VALID_CHANNELIDB 51
#define TEST_VALID_CHANNELIDC 2

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} TestSliceHead;

typedef struct  {
    int32_t magicNumber;
    int32_t seq;
    int32_t flags;
    int32_t dataLen;
} TestPacketHead;

class SoftbusProxySessionTest : public testing::Test {
public:
    SoftbusProxySessionTest()
    {}
    ~SoftbusProxySessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

int32_t TestSessionDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    printf("test session data received.\n");
    return SOFTBUS_OK;
}

void SoftbusProxySessionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    callBack.OnDataReceived = TestSessionDataReceived;
    ASSERT_NE(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void SoftbusProxySessionTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestAddProxyChannel(int32_t channelId, AppType appType, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authHandle.authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, std::to_string(channelId).c_str());
    chan->status = status;
    appInfo.appType = appType;
    TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
}

/**
 * @tc.name: TransProxyPostSessionDataTest001
 * @tc.desc: test proxy post session data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransProxyPostSessionDataTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = SOFTBUS_INVALID_PARAM;

    for (uint32_t flags = TRANS_SESSION_BYTES; flags <= TRANS_SESSION_FILE_ACK_RESPONSE_SENT; ++flags) {
        ret = TransProxyPostSessionData(channelId, NULL, 0, (SessionPktType)flags);
        EXPECT_NE(SOFTBUS_OK, ret);
    }

    const char *data = "test data";
    uint32_t len = strlen(data);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPostSessionDataTest002
 * @tc.desc: test proxy post session data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransProxyPostSessionDataTest002, TestSize.Level1)
{
    int32_t channelId = TEST_VALID_CHANNELIDA;
    TestAddProxyChannel(channelId, APP_TYPE_AUTH, PROXY_CHANNEL_STATUS_COMPLETED);

    const char *data = "test data";
    uint32_t len = strlen(data);

    int32_t ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_BYTES);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyPostSessionDataTest003
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND when given invalid Channid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransProxyPostSessionDataTest003, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_VALID_CHANNELIDB;
    TestAddProxyChannel(channelId, APP_TYPE_NORMAL, PROXY_CHANNEL_STATUS_COMPLETED);

    const char *data = "test data";
    uint32_t len = strlen(data);

    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);

    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_ALLFILE_SENT);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_CRC_CHECK_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_ACK_REQUEST_SENT);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_FILE_ACK_RESPONSE_SENT);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
    ret = TransProxyPostSessionData(channelId, (const unsigned char *)data, len, TRANS_SESSION_ASYNC_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest001
 * @tc.desc: test proxy on normal msg received input wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransOnNormalMsgReceivedTest001, TestSize.Level1)
{
    const char *pkgName = "com.test.trans.proxysession";
    int32_t pid = 0;
    int32_t channelId = -1;
    char buf[TEST_BUFFER_SIZE] = {0};
    TestSliceHead head;
    uint32_t len = TEST_DEFAULT_DATA_LEN;
    int32_t ret = TransOnNormalMsgReceived(pkgName, pid, channelId, NULL, len);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    head.priority  = -1;
    len = TEST_VALID_LARGE_DATA_LEN;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    head.priority  = TEST_INVALID_PRIORITY;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    head.priority  = TEST_VALID_PRIORITY;
    head.sliceNum = TEST_SLICENUM_TWO;
    head.sliceSeq = TEST_SLICESEQ_TWO;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest002
 * @tc.desc: test proxy on normal msg received, and test no sub packet proc with worng param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransOnNormalMsgReceivedTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    char data[TEST_BUFFER_SIZE] = {0};
    char *buf = data;
    int32_t channelId = TEST_VALID_CHANNELIDC;
    int32_t pid = 0;
    int32_t len = sizeof(TestSliceHead) + sizeof(TestPacketHead) + TEST_VALID_NO_SLICE_DEFAULT_LEN;
    const char *pkgName = "com.test.trans.proxysession";
    TestSliceHead head;
    head.priority  = TEST_VALID_PRIORITY;
    head.sliceNum = 1;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    buf += sizeof(TestSliceHead);

    TestPacketHead packHead;
    /* test msgicNum error */
    packHead.magicNumber = 1;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test packet head len is zero */
    packHead.magicNumber = TEST_MAGIC_NUMBER;
    packHead.dataLen = 0;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test packet head len invalid */
    packHead.dataLen = TEST_INVALID_NO_SLICE_DATASLEN;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test dataHead dataLen <= OVERHEAD_LEN */
    packHead.dataLen = TEST_INVALID_NO_SLICE_DATASLEN;
    len -= TEST_DEFAULT_DATA_LEN;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test proxy channel not exists */
    len  += TEST_INVALID_NO_SLICE_DATASLEN;
    packHead.dataLen = TEST_VALID_NO_SLICE_DATALEN;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test decrypt fail */
    ret = TransOnNormalMsgReceived(pkgName, 0, TEST_VALID_CHANNELIDA, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest003
 * @tc.desc: test proxy on normal msg received, and test no sub packet proc.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransOnNormalMsgReceivedTest003, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_VALID_CHANNELIDA;
    char data[TEST_BUFFER_SIZE] = {0};
    char *buf = data;
    int32_t len = sizeof(TestSliceHead) + sizeof(TestPacketHead) + TEST_VALID_NO_SLICE_DATALEN;
    const char *pkgName = "com.test.trans.proxysession";

    TestSliceHead head;
    head.priority  = TEST_VALID_PRIORITY;
    head.sliceNum = 1;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    buf += sizeof(TestSliceHead);
    TestPacketHead packHead;
    packHead.magicNumber = TEST_MAGIC_NUMBER;
    packHead.dataLen = TEST_VALID_NO_SLICE_DATALEN;

    /* test flag=bytes success */
    packHead.flags = PROXY_FLAG_BYTES;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, 0, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test flag=async message success */
    packHead.flags = PROXY_FLAG_ASYNC_MESSAGE;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, 0, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test flag=message success */
    packHead.flags = PROXY_FLAG_MESSAGE;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, 0, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* pending status need multi thread, so test flag=ack fail */
    len -= TEST_ACK_DATA_LEN_ONE_BYTES;
    packHead.dataLen = TEST_ACK_DATA_LEN;
    packHead.flags = PROXY_FLAG_ACK;
    (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
    ret = TransOnNormalMsgReceived(pkgName, 0, channelId, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest004
 * @tc.desc: test proxy on normal msg received, and test no sub packet proc.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransOnNormalMsgReceivedTest004, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_VALID_CHANNELIDA;
    char data[TEST_BUFFER_SIZE] = {0};
    char *buf = data;
    int32_t len = sizeof(TestSliceHead) + sizeof(TestPacketHead) + TEST_VALID_NO_SLICE_DATALEN;
    const char *pkgName = "com.test.trans.proxysession";
    TestSliceHead head;
    head.priority  = TEST_VALID_PRIORITY;
    head.sliceNum = 1;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    buf += sizeof(TestSliceHead);
    TestPacketHead packHead;
    packHead.magicNumber = TEST_MAGIC_NUMBER;
    packHead.dataLen = TEST_VALID_NO_SLICE_DATALEN;

    /* test flag = PROXY_FILE_FIRST_FRAME to PROXY_FILE_ACK_RESPONSE_SENT */
    for (uint32_t flag = PROXY_FILE_FIRST_FRAME; flag <= PROXY_FILE_ACK_RESPONSE_SENT; ++flag) {
        packHead.flags = (ProxyPacketType)flag;
        (void)memcpy_s(buf, (TEST_BUFFER_SIZE - sizeof(TestSliceHead)), &packHead, sizeof(TestPacketHead));
        ret = TransOnNormalMsgReceived(pkgName, 0, channelId, data, len);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
}

/**
 * @tc.name: TransOnNormalMsgReceivedTest005
 * @tc.desc: test proxy on normal msg received, and test sub packet proc.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, TransOnNormalMsgReceivedTest005, TestSize.Level1)
{
    char buf[TEST_BUFFER_SIZE] = {0};
    int32_t channelId = 1;
    int32_t pid = 0;
    int32_t len = sizeof(TestSliceHead) + TEST_VALID_DATA_LEN;
    const char *pkgName = "com.test.trans.proxysession";
    TestSliceHead head;
    head.priority  = TEST_VALID_PRIORITY;
    head.sliceNum = TEST_SLICENUM_TWO;

    /* test first slice process */
    head.sliceSeq = 0;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    int32_t ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test last slice process */
    head.sliceSeq = 1;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test normal slice process */
    head.sliceSeq = TEST_SLICESEQ_THREE;
    (void)memcpy_s(buf, TEST_BUFFER_SIZE, &head, sizeof(TestSliceHead));
    ret = TransOnNormalMsgReceived(pkgName, pid, channelId, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: NotifyClientMsgReceivedTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid paramters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxySessionTest, NotifyClientMsgReceivedTest001, TestSize.Level1)
{
    const char *pkgName = "com.test.trans.proxysession";
    int32_t channelId = -1;
    int32_t pid = 1;
    TransReceiveData receiveData;
    memset_s(&receiveData, sizeof(TransReceiveData), 0, sizeof(TransReceiveData));
    int32_t ret = NotifyClientMsgReceived(pkgName, pid, channelId, &receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
