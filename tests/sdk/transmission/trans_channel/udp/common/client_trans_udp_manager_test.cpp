/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_udp_manager.h"
#include "securec.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_udp_channel_manager.h"

using namespace std;
using namespace testing::ext;

const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";

namespace OHOS {
#define TEST_ERR_PID (-1)
#define TEST_LEN 10
#define TEST_DATA_TYPE 2
#define TEST_PID 2
#define TEST_STATE 1
#define TEST_ERR_CODE 1
#define TEST_CHANNELID 5
#define TEST_SESSIONID 100
#define TEST_CHANNELTYPE 2
#define TEST_REMOTE_TYPE 0
#define TEST_EVENT_ID 2
#define TEST_COUNT 2
#define TEST_ERR_COUNT (-2)
#define TEST_ERRCODE 0
#define TEST_FILE_NAME "test.filename.01"
#define STREAM_DATA_LENGTH 10
#define TEST_ERR_CHANNELID (-1)
#define FILE_PRIORITY_TEST 0x06

class ClientTransUdpManagerTest : public testing::Test {
public:
    ClientTransUdpManagerTest() {}
    ~ClientTransUdpManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

static int32_t OnSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    return SOFTBUS_OK;
}

static int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    return SOFTBUS_OK;
}

static int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

static int32_t OnDataReceived(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}
static IClientSessionCallBack g_sessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
};

void ClientTransUdpManagerTest::SetUpTestCase(void)
{
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void ClientTransUdpManagerTest::TearDownTestCase(void) {}

static ChannelInfo InitChannelInfo()
{
    ChannelInfo channel;
    char strTmp[] = "ABCDEFG";
    char strSessionName[] = "ohos.distributedschedule.dms.test";
    channel.channelId = TEST_CHANNELID;
    channel.businessType = BUSINESS_TYPE_STREAM;
    channel.channelType = TEST_CHANNELTYPE;
    channel.fd = TEST_DATA_TYPE;
    channel.isServer = true;
    channel.isEnabled = true;
    channel.peerUid = TEST_CHANNELID;
    channel.peerPid = TEST_CHANNELID;
    channel.groupId = strTmp;
    channel.sessionKey = strTmp;
    channel.keyLen = sizeof(channel.sessionKey);
    channel.peerSessionName = strSessionName;
    channel.peerDeviceId = strTmp;
    channel.myIp = strTmp;
    channel.streamType = TEST_COUNT;
    channel.isUdpFile = true;
    channel.peerPort = TEST_COUNT;
    channel.peerIp = strTmp;
    channel.routeType = TEST_DATA_TYPE;
    return channel;
}

/**
 * @tc.name: TransOnUdpChannelOpenedTest001
 * @tc.desc: trans on udp channel opened test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest001, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;

    ret = TransOnUdpChannelOpened(NULL, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransOnUdpChannelOpened(g_sessionName, NULL, &udpPort);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransOnUdpChannelOpenedTest002
 * @tc.desc: trans on udp channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest002, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    char strSessionName[] = "ohos.distributedschedule.dms.test";

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransOnUdpChannelClosed(channel.channelId, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    channel.businessType = BUSINESS_TYPE_FILE;
    ret = TransOnUdpChannelOpened(strSessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    channel.businessType = BUSINESS_TYPE_FILE;
    channel.channelId = TEST_CHANNELID + 1;
    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    channel.businessType = TEST_COUNT;
    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH, ret);
}

/**
 * @tc.name: TransOnUdpChannelOpenedTest003
 * @tc.desc: trans on udp channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest003, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    QosTv tvList;

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransOnUdpChannelQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    channel.businessType = BUSINESS_TYPE_BUTT;
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnUdpChannelOpenFailedTest001
 * @tc.desc: trans on udp channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenFailedTest001, TestSize.Level0)
{
    int32_t ret;
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnUdpChannelOpenFailed(0, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnUdpChannelClosedTest001
 * @tc.desc: trans on udp channel closed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelClosedTest001, TestSize.Level0)
{
    int32_t ret;
    ret = TransOnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransOnUdpChannelClosedTest002
 * @tc.desc: trans on udp channel closed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelClosedTest002, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    channel.businessType = BUSINESS_TYPE_FILE;

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransOnUdpChannelClosed(channel.channelId, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransOnUdpChannelClosed(channel.channelId, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransOnUdpChannelClosed(channel.channelId, SHUTDOWN_REASON_SEND_FILE_ERR);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransOnUdpChannelClosed(TEST_CHANNELID + TEST_CHANNELID, SHUTDOWN_REASON_SEND_FILE_ERR);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransOnUdpChannelQosEventTest001
 * @tc.desc: trans on udp channel qos event test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelQosEventTest001, TestSize.Level0)
{
    int32_t ret;
    QosTv tvList;
    ret = TransOnUdpChannelQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: ClientTransCloseUdpChannelTest001
 * @tc.desc: client trans close udp channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransCloseUdpChannelTest001, TestSize.Level0)
{
    int32_t ret;
    ret = ClientTransCloseUdpChannel(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransUdpChannelSendStreamTest001
 * @tc.desc: trans udp channel send stream test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendStreamTest001, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;

    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    StreamData tmpData = {
        sendStringData,
        STREAM_DATA_LENGTH,
    };
    char str[STREAM_DATA_LENGTH] = "oohoohooh";
    StreamData tmpData2 = {
        str,
        STREAM_DATA_LENGTH,
    };

    StreamFrameInfo tmpf = {};
    ret = TransUdpChannelSendStream(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransUdpChannelSendStream(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransUdpChannelSendFileTest001
 * @tc.desc: trans udp channel send file test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendFileTest001, TestSize.Level0)
{
    int32_t ret;
    const char *sFileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    ret = TransUdpChannelSendFile(TEST_CHANNELID, NULL, NULL, 1);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransUdpChannelSendFile(TEST_CHANNELID, sFileList, NULL, 0);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = TransUdpChannelSendFile(TEST_CHANNELID, sFileList, NULL, 1);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransGetUdpChannelByFileIdTest001
 * @tc.desc: trans get udp channel by fileid test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelByFileIdTest001, TestSize.Level0)
{
    int32_t ret;
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    ret = TransGetUdpChannelByFileId(TEST_DATA_TYPE, &udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);

    ClientTransUdpMgrDeinit();
    ret = TransGetUdpChannelByFileId(TEST_DATA_TYPE, &udpChannel);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: ClientTransAddUdpChannelTest001
 * @tc.desc: client trans add udp channel test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransAddUdpChannelTest001, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED, ret);

    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED, ret);

    ClientTransUdpMgrDeinit();
    ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: ClientTransUdpManagerTest001
 * @tc.desc: client trans udp manager test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransUdpManagerTest001, TestSize.Level0)
{
    int32_t ret;

    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientEmitFileEventTest001
 * @tc.desc: client emit file event test, use the invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientEmitFileEventTest001, TestSize.Level0)
{
    int32_t channelId = TEST_ERR_CHANNELID;
    int32_t ret = ClientEmitFileEvent(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientEmitFileEventTest002
 * @tc.desc: client emit file event test, use the invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientEmitFileEventTest002, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientEmitFileEvent(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransSetUdpChanelSessionId(TEST_CHANNELID, TEST_SESSIONID);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);

    ret = TransSetUdpChannelRenameHook(TEST_CHANNELID, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransLimitChangeTest
 * @tc.desc: trans limit change test, use the invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest, TestSize.Level0)
{
    int32_t channelId = TEST_ERR_CHANNELID;
    int32_t ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);

    channelId = TEST_CHANNELID;
    ret = TransLimitChange(channelId, FILE_PRIORITY_BE);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);

    ret = TransLimitChange(channelId, FILE_PRIORITY_TEST);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransSetUdpChannelTosTest
 * @tc.desc: trans set udp channel tos test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelTosTest, TestSize.Level0)
{
    int32_t channelId = TEST_ERR_CHANNELID;
    int32_t ret = TransSetUdpChannelTos(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND);
}

/**
 * @tc.name: TransGetUdpChannelTosTest
 * @tc.desc: trans get udp channel tos test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelTosTest, TestSize.Level0)
{
    int32_t channelId = TEST_ERR_CHANNELID;
    bool isTosSet = false;
    int32_t ret = TransGetUdpChannelTos(channelId, &isTosSet);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND);
    EXPECT_FALSE(isTosSet);
    ret = TransGetUdpChannelTos(TEST_CHANNELID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
