/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_udp_manager.c"
#include "client_trans_udp_manager.h"
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
#define TEST_ERR_PID       (-1)
#define TEST_LEN           10
#define TEST_DATA_TYPE     2
#define TEST_PID           2
#define TEST_STATE         1
#define TEST_ERR_CODE      1
#define TEST_CHANNELID     5
#define TEST_SESSIONID     100
#define TEST_CHANNELTYPE   2
#define TEST_REMOTE_TYPE   0
#define TEST_EVENT_ID      2
#define TEST_COUNT         2
#define TEST_ERR_COUNT     (-2)
#define TEST_ERRCODE       0
#define TEST_FILE_NAME     "test.filename.01"
#define STREAM_DATA_LENGTH 10
#define TEST_ERR_CHANNELID (-1)
#define TEST_ERR_SESSIONID (-1)
#define FILE_PRIORITY_TEST 0x06

class ClientTransUdpManagerTest : public testing::Test {
public:
    ClientTransUdpManagerTest(void) { }
    ~ClientTransUdpManagerTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

static int32_t OnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
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

static int32_t OnDataReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
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
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ClientTransUdpManagerTest::TearDownTestCase(void) { }

static ChannelInfo InitChannelInfo(void)
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

/*
 * @tc.name: TransOnUdpChannelOpenedTest001
 * @tc.desc: trans on udp channel opened with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest001, TestSize.Level1)
{
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    int32_t ret = TransOnUdpChannelOpened(nullptr, &channel, &udpPort, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnUdpChannelOpened(g_sessionName, nullptr, &udpPort, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOnUdpChannelOpened(g_sessionName, &channel, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOnUdpChannelOpenedTest002
 * @tc.desc: trans on udp channel opened with stream business type returns error when stream not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest002, TestSize.Level1)
{
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    SocketAccessInfo accessInfo = { 0 };
    int32_t ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort, &accessInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransOnUdpChannelOpenedTest003
 * @tc.desc: trans on udp channel opened with file business type returns node not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest003, TestSize.Level1)
{
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    SocketAccessInfo accessInfo = { 0 };
    channel.businessType = BUSINESS_TYPE_FILE;
    int32_t ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/*
 * @tc.name: TransOnUdpChannelOpenedTest004
 * @tc.desc: trans on udp channel opened with invalid business type returns not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenedTest004, TestSize.Level1)
{
    ChannelInfo channel = InitChannelInfo();
    int32_t udpPort;
    SocketAccessInfo accessInfo = { 0 };
    channel.businessType = TEST_COUNT;
    int32_t ret = TransOnUdpChannelOpened(g_sessionName, &channel, &udpPort, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH, ret);
}

/*
 * @tc.name: TransOnUdpChannelOpenFailedTest001
 * @tc.desc: trans on udp channel open failed returns ok when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOnUdpChannelOpenFailed(TEST_ERR_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnUdpChannelClosedTest001
 * @tc.desc: trans on udp channel closed returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelClosedTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransOnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransOnUdpChannelClosed(TEST_CHANNELID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransOnUdpChannelClosed(TEST_ERR_CHANNELID, SHUTDOWN_REASON_SEND_FILE_ERR);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: TransOnUdpChannelQosEventTest001
 * @tc.desc: trans on udp channel qos event returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransOnUdpChannelQosEventTest001, TestSize.Level1)
{
    QosTv tvList;
    int32_t ret = TransOnUdpChannelQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransOnUdpChannelQosEvent(TEST_ERR_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: ClientTransCloseUdpChannelTest001
 * @tc.desc: client trans close udp channel returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransCloseUdpChannelTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = ClientTransCloseUdpChannel(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = ClientTransCloseUdpChannel(TEST_ERR_CHANNELID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: ClientTransCloseReserveUdpChannelTest001
 * @tc.desc: client trans close reserve udp channel returns channel not found when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransCloseReserveUdpChannelTest001, TestSize.Level1)
{
    RouteType routeType = WIFI_P2P;
    int32_t ret = ClientTransCloseReserveUdpChannel(TEST_CHANNELID, SHUTDOWN_REASON_UNKNOWN, routeType, false);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ret = ClientTransCloseReserveUdpChannel(TEST_ERR_CHANNELID, SHUTDOWN_REASON_PEER, routeType, true);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransUdpChannelSendStreamTest001
 * @tc.desc: trans udp channel send stream returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendStreamTest001, TestSize.Level1)
{
    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    StreamData tmpData = { sendStringData, STREAM_DATA_LENGTH };
    char str[STREAM_DATA_LENGTH] = "oohoohooh";
    StreamData tmpData2 = { str, STREAM_DATA_LENGTH };
    StreamFrameInfo tmpf = { };
    int32_t ret = TransUdpChannelSendStream(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: TransUdpChannelSetStreamMultiLayerTest001
 * @tc.desc: trans udp channel set stream multi layer returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSetStreamMultiLayerTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransUdpChannelSetStreamMultiLayer(TEST_ERR_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: TransUdpChannelSendFileTest001
 * @tc.desc: trans udp channel send file returns get channel failed when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendFileTest001, TestSize.Level1)
{
    const char *sFileList[] = { "/data/big.tar", "/data/richu.jpg" };
    int32_t ret = TransUdpChannelSendFile(TEST_CHANNELID, nullptr, nullptr, 1);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransUdpChannelSendFile(TEST_CHANNELID, sFileList, nullptr, 0);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ret = TransUdpChannelSendFile(TEST_CHANNELID, sFileList, nullptr, 1);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/*
 * @tc.name: TransGetUdpChannelByFileIdTest001
 * @tc.desc: trans get udp channel by file id returns channel not found when no matching channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelByFileIdTest001, TestSize.Level1)
{
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    int32_t ret = TransGetUdpChannelByFileId(TEST_DATA_TYPE, &udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ret = TransGetUdpChannelByFileId(TEST_ERR_SESSIONID, &udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransGetUdpChannelByFileIdTest002
 * @tc.desc: trans get udp channel by file id returns no init when manager uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelByFileIdTest002, TestSize.Level1)
{
    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    ClientTransUdpMgrDeinit();
    int32_t ret = TransGetUdpChannelByFileId(TEST_DATA_TYPE, &udpChannel);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransUdpMgrInitTest001
 * @tc.desc: client trans udp mgr init returns ok when first initialized after deinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransUdpMgrInitTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrInit(&g_sessionCb);
}

/*
 * @tc.name: ClientTransUdpMgrInitTest002
 * @tc.desc: client trans udp mgr init returns ok when re-init on already initialized manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientTransUdpMgrInitTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientEmitFileEventTest001
 * @tc.desc: client emit file event returns error when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientEmitFileEventTest001, TestSize.Level1)
{
    int32_t ret = ClientEmitFileEvent(TEST_ERR_CHANNELID);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = ClientEmitFileEvent(TEST_CHANNELID);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = ClientEmitFileEvent(0);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransLimitChangeTest001
 * @tc.desc: trans limit change returns channel not found when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest001, TestSize.Level1)
{
    int32_t channelId = TEST_ERR_CHANNELID;
    int32_t ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    channelId = TEST_CHANNELID;
    ret = TransLimitChange(channelId, FILE_PRIORITY_BE);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransLimitChangeTest002
 * @tc.desc: trans limit change returns invalid param when tos is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    ret = TransLimitChange(channelId, FILE_PRIORITY_TEST);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransLimitChange(TEST_ERR_CHANNELID, 0xFF);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSetUdpChannelTosTest001
 * @tc.desc: trans set udp channel tos returns channel not found when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelTosTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransSetUdpChannelTos(TEST_ERR_CHANNELID);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ret = TransSetUdpChannelTos(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransGetUdpChannelTosTest001
 * @tc.desc: trans get udp channel tos returns invalid param when isTosSet is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelTosTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    ret = TransGetUdpChannelTos(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetUdpChannelTos(TEST_ERR_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetUdpChannelTosTest002
 * @tc.desc: trans get udp channel tos returns channel not found when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelTosTest002, TestSize.Level1)
{
    bool isTosSet = false;
    int32_t ret = TransGetUdpChannelTos(TEST_ERR_CHANNELID, &isTosSet);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    EXPECT_FALSE(isTosSet);
    ret = TransGetUdpChannelTos(TEST_CHANNELID, &isTosSet);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransSetUdpChannelExtraInfoTest001
 * @tc.desc: trans set udp channel extra info returns no init when addr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelExtraInfoTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    ret = TransSetUdpChannelExtraInfo(channelId, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = TransSetUdpChannelExtraInfo(TEST_ERR_CHANNELID, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransGetUdpChannelExtraInfoTest001
 * @tc.desc: trans get udp channel extra info returns invalid param when params are null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelExtraInfoTest001, TestSize.Level1)
{
    struct sockaddr_storage addr;
    socklen_t addrLen = 0;
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = TransGetUdpChannelExtraInfo(channelId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetUdpChannelExtraInfo(channelId, &addr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetUdpChannelExtraInfo(channelId, nullptr, &addrLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransUdpChannelSendStreamTest002
 * @tc.desc: trans udp channel send stream returns channel disable when channel is disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendStreamTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->isEnable = false;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    StreamData tmpData1 = { sendStringData, STREAM_DATA_LENGTH };
    char str[STREAM_DATA_LENGTH] = "ooooooood";
    StreamData tmpData2 = { str, STREAM_DATA_LENGTH };
    StreamFrameInfo tmpf = { };
    ret = TransUdpChannelSendStream(channelId, &tmpData1, &tmpData2, &tmpf);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_DISABLE, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransUdpChannelSendStreamTest003
 * @tc.desc: trans udp channel send stream returns invalid param when stream data is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendStreamTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->isEnable = true;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StreamFrameInfo tmpf = { };
    ret = TransUdpChannelSendStream(channelId, nullptr, nullptr, &tmpf);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransUdpChannelSendFileTest002
 * @tc.desc: trans udp channel send file returns channel disable when channel is disabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendFileTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    const char *sFileList[] = { "/data/big.tar", "/data/richu.jpg" };
    const char *dFileList[] = { "/data/big.tar", "/data/richu.jpg" };
    uint32_t fileCnt = 0;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->isEnable = false;
    newChannel->dfileId = TEST_ERR_SESSIONID;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUdpChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_DISABLE, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransUdpChannelSendFileTest003
 * @tc.desc: trans udp channel send file returns error when channel enabled but send fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransUdpChannelSendFileTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    const char *sFileList[] = { "/data/big.tar", "/data/richu.jpg" };
    const char *dFileList[] = { "/data/big.tar", "/data/richu.jpg" };
    uint32_t fileCnt = 0;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->isEnable = true;
    newChannel->dfileId = TEST_SESSIONID;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUdpChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransLimitChangeTest003
 * @tc.desc: trans limit change returns not need update when channel is server side file channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_FILE;
    newChannel->info.isServer = true;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_NOT_NEED_UPDATE, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransLimitChangeTest004
 * @tc.desc: trans limit change returns not need update when channel is non-file business type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_BYTE;
    newChannel->info.isServer = false;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_NOT_NEED_UPDATE, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransLimitChangeTest005
 * @tc.desc: trans limit change returns ok when client file channel with tos not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest005, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_FILE;
    newChannel->info.isServer = false;
    newChannel->isTosSet = false;
    newChannel->dfileId = TEST_ERR_SESSIONID;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransLimitChangeTest006
 * @tc.desc: trans limit change returns not need update when client file channel with tos already set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransLimitChangeTest006, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_FILE;
    newChannel->info.isServer = false;
    newChannel->isTosSet = true;
    newChannel->dfileId = TEST_ERR_SESSIONID;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLimitChange(channelId, FILE_PRIORITY_BK);
    EXPECT_EQ(SOFTBUS_NOT_NEED_UPDATE, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: ClientEmitFileEventTest002
 * @tc.desc: client emit file event returns not no init when file channel exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, ClientEmitFileEventTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_FILE;
    newChannel->dfileId = TEST_ERR_SESSIONID;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientEmitFileEvent(channelId);
    EXPECT_NE(SOFTBUS_NO_INIT, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransSetUdpChannelSessionIdTest001
 * @tc.desc: trans set udp channel session id returns no init when manager uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelSessionIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
    ret = TransSetUdpChannelSessionId(channelId, sessionId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSetUdpChannelSessionIdTest002
 * @tc.desc: trans set udp channel session id returns ok when channel found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelSessionIdTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelSessionId(channelId, sessionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

static void OnRenameFileCb(RenameParam *renameParam)
{
    return;
}

/*
 * @tc.name: TransSetUdpChannelRenameHookTest001
 * @tc.desc: trans set udp channel rename hook returns invalid param when callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelRenameHookTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    ret = TransSetUdpChannelRenameHook(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransSetUdpChannelRenameHook(TEST_ERR_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSetUdpChannelRenameHookTest002
 * @tc.desc: trans set udp channel rename hook returns no init when manager uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelRenameHookTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    OnRenameFileCallback onRenameFile = OnRenameFileCb;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
    ret = TransSetUdpChannelRenameHook(channelId, onRenameFile);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSetUdpChannelRenameHookTest003
 * @tc.desc: trans set udp channel rename hook returns channel not found when channel not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelRenameHookTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    OnRenameFileCallback onRenameFile = OnRenameFileCb;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelRenameHook(channelId, onRenameFile);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransSetUdpChannelRenameHookTest004
 * @tc.desc: trans set udp channel rename hook returns ok when file channel found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelRenameHookTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    OnRenameFileCallback onRenameFile = OnRenameFileCb;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    newChannel->businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelRenameHook(channelId, onRenameFile);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransSetUdpChannelTosTest002
 * @tc.desc: trans set udp channel tos returns no init when manager uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelTosTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
    ret = TransSetUdpChannelTos(channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSetUdpChannelTosTest003
 * @tc.desc: trans set udp channel tos returns ok when channel found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransSetUdpChannelTosTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelTos(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransGetUdpChannelTosTest003
 * @tc.desc: trans get udp channel tos returns no init when manager uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelTosTest003, TestSize.Level1)
{
    bool isTosSet = false;
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
    ret = TransGetUdpChannelTos(channelId, &isTosSet);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetUdpChannelTosTest004
 * @tc.desc: trans get udp channel tos returns ok when channel found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerTest, TransGetUdpChannelTosTest004, TestSize.Level1)
{
    bool isTosSet = false;
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = ClientTransUdpMgrInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    UdpChannel *newChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_NE(newChannel, nullptr);
    newChannel->channelId = channelId;
    ret = ClientTransAddUdpChannel(newChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetUdpChannelTos(channelId, &isTosSet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteUdpChannel(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
}
} // namespace OHOS
