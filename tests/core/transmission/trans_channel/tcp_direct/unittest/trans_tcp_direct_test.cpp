/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 
#include <arpa/inet.h>
#include <unistd.h>
#include <securec.h>

#include "auth_interface.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"

#include "trans_channel_callback.c"
#include "trans_channel_manager.h"
#include "trans_tcp_direct_listener.c"
#include "trans_tcp_direct_manager.c"
#include "trans_tcp_direct_message.c"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_wifi.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_TRANS_UDID "1234567"
#define TRANS_SEQ_STEP 2
#define AUTH_TRANS_DATA_LEN 32
#define DEVICE_ID_SIZE_MAX_LEN 65
#define DC_MSG_PACKET_HEAD_SIZE_LEN 24
#define MODULE_P2P_LISTEN 16
#define MSG_FLAG_REQUEST 0
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

class TransTcpDirectTest : public testing::Test {
public:
    TransTcpDirectTest()
    {}
    ~TransTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectTest::SetUpTestCase(void)
{}

void TransTcpDirectTest::TearDownTestCase(void)
{}

/**
 * @tc.name: StartSessionListenerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StartSessionListenerTest001, TestSize.Level1)
{
    int32_t ret = 0;
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = 6000,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(UNUSE_BUTT, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LocalListenerInfo info2 = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "192.168.8.119",
            .port = -1,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info2);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LocalListenerInfo info3 = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = -1,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info3);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: StoptSessionListenerTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StoptSessionListenerTest001, TestSize.Level1)
{
    int32_t ret = 0;
    ret = TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_WIFI);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenTcpDirectChannelTest001
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenTcpDirectChannelTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo appInfo;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = 6000,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), "192.168.8.1") != EOK) {
        return;
    }
    int32_t fd = 1;

    ret = TransOpenDirectChannel(NULL, &connInfo, &fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(&appInfo, NULL, &fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenTcpDirectChannelTest002
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenTcpDirectChannelTest002, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = 6000,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), "192.168.8.1") != EOK) {
        return;
    }
    int32_t channelId = 0;

    ret = OpenTcpDirectChannel(&appInfo, &connInfo, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcPostBytesTest001
 * @tc.desc: TransTdcPostBytesTest, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcPostBytesTest001, TestSize.Level1)
{
    int32_t ret = 0;
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t channelId = 0;

    ret = TransTdcPostBytes(channelId, NULL, bytes);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcPostBytes(channelId, &packetHead, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    packetHead.dataLen = 0;
    ret = TransTdcPostBytes(channelId, &packetHead, bytes);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest001
 * @tc.desc: GetCipherFlagByAuthId, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, GetCipherFlagByAuthIdTest001, TestSize.Level1)
{
    int64_t authId = 0;
    uint32_t flag = 0;

    int32_t ret = GetCipherFlagByAuthId(authId, &flag, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: SessionConnListTest001
 * @tc.desc: SessionConnListTest001, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SessionConnListTest001, TestSize.Level1)
{
    SessionConn conn;
    ListInit(&conn.node);

    int32_t ret = CreatSessionConnList();
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcAddSessionConn(&conn);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    AppInfo appInfo;
    ret = GetAppInfoById(conn.channelId, &appInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = SetAuthIdByChanId(conn.channelId, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    int32_t authId = GetAuthIdByChanId(conn.channelId);
    EXPECT_TRUE(authId != AUTH_INVALID_ID);

    DestroySoftBusList(GetSessionConnList());
}

/**
 * @tc.name: StartVerifySessionTest001
 * @tc.desc: start verify session, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StartVerifySessionTest001, TestSize.Level1)
{
    int32_t ret = StartVerifySession(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: PackBytesTest001
 * @tc.desc: validate packaging with error parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, PackBytesTest001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = -1;
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    const char *data = "data";
    char buffer[DC_MSG_PACKET_HEAD_SIZE_LEN] = {0};
    ret = PackBytes(channelId, data, &packetHead, buffer, DC_MSG_PACKET_HEAD_SIZE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    channelId = 0;
    ret = PackBytes(channelId, data, &packetHead, buffer, DC_MSG_PACKET_HEAD_SIZE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenAuthConnTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
 
HWTEST_F(TransTcpDirectTest, OpenAuthConnTest001, TestSize.Level1)
{
    const char* uuid = TEST_TRANS_UDID;
    uint32_t reqId = 1;

    int32_t ret = OpenAuthConn(uuid, reqId, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}
/**
 * @tc.name: OpenDataBusReplyTest002
 * @tc.desc: Open the data channel for reply with error parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenDataBusReplyTest002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    uint64_t seq = 0;
    const char* msg = "ProcessMessage";
    cJSON *reply = cJSON_Parse(msg);
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenDataBusRequestErrorTest003
 * @tc.desc: open dsofutbus data erro request with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenDataBusRequestErrorTest003, TestSize.Level1)
{
    int32_t ret;
    int32_t chnanelId = 0;
    uint64_t seq = 0;
    int32_t errCode = 0;
    uint32_t flags = 0;
    ret = OpenDataBusRequestError(chnanelId, seq, NULL, errCode, flags);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetUuidByChanIdTest004
 * @tc.desc: get uuid by channelId with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, GetUuidByChanIdTest004, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    uint32_t len = 0;
    ret = GetUuidByChanId(channelId, NULL, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenDataBusRequestTest005
 * @tc.desc: OpenDataBusRequestTest005, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenDataBusRequestTest005, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    uint32_t flags = 0;
    uint64_t seq = 0;
    ret = OpenDataBusRequest(channelId, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: ProcessMessageTest006
 * @tc.desc: ProcessMessageTest006, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ProcessMessageTest006, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t flags = 0;
    uint64_t seq = 0;
    int32_t ret = ProcessMessage(channelId, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest007
 * @tc.desc: GetAuthIdByChannelInfoTest007, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, GetAuthIdByChannelInfoTest007, TestSize.Level1)
{
    int32_t channelId = 111;
    uint64_t seq = 0;
    uint32_t cipherFlag = 0;
    int32_t ret = GetAuthIdByChannelInfo(channelId, seq, cipherFlag);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: DecryptMessageTest008
 * @tc.desc: DecryptMessageTest008, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, DecryptMessageTest008, TestSize.Level1)
{
    int32_t channelId = 0;
    uint8_t* outData = nullptr;
    uint32_t dataLen = DC_MSG_PACKET_HEAD_SIZE_LEN;
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t ret = DecryptMessage(channelId, &packetHead, NULL, &outData, &dataLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: ProcessReceivedDataTest009
 * @tc.desc: The process of receiving data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ProcessReceivedDataTest009, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = ProcessReceivedData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: SendAuthDataTest001
 * @tc.desc: sending authentication data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendAuthDataTest001, TestSize.Level1)
{
    int64_t authId = 0;
    int64_t seq = 0;
    const char *data = "message";
    int32_t ret = SendAuthData(authId, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, seq, data);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OnAuthDataRecvTest002
 * @tc.desc: receiving authentication data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OnAuthDataRecvTest002, TestSize.Level1)
{
    AuthTransData dataInfo = {
        .module = 0,
        .flag = 0,
        .seq = 0,
        .len = 1,
        .data = NULL,
    };
    int64_t authId = 0;
    OnAuthDataRecv(authId, &dataInfo);

    AuthTransData dataInfo1 = {
        .module = 0,
        .flag = 0,
        .seq = 0,
        .len = 0,
        .data = (const uint8_t*)"reveive data",
    };
    OnAuthDataRecv(authId, &dataInfo1);
    OnAuthDataRecv(authId, NULL);

    AuthTransData dataInfo2 = {
        .module = 0,
        .flag = 0,
        .seq = 0,
        .len = 0,
        .data = (const uint8_t*)"reveive data",
    };
    OnAuthDataRecv(authId, &dataInfo2);
}

/**
 * @tc.name: TransDelSessionConnByIdTest001
 * @tc.desc: delete the session by channelId, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransDelSessionConnByIdTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnSessionOpenFailProcTest001
 * @tc.desc: delete the session by channelId, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OnSessionOpenFailProcTest001, TestSize.Level1)
{
    OnSessionOpenFailProc(NULL, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
}

/**
 * @tc.name: UnpackReplyErrCodeTest001
 * @tc.desc: UnpackReplyErrCodeTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, UnpackReplyErrCodeTest001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_ERR;
    int32_t ret = UnpackReplyErrCode(NULL, &errCode);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackReplyErrCode(NULL, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    string str = "testData";
    cJSON *msg = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(msg, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    string errDesc = "testDesc";
    str = PackError(SOFTBUS_ERR, errDesc.c_str());
    cJSON *json = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(json, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransServerOnChannelOpenFailedTest001
 * @tc.desc: TransServerOnChannelOpenFailedTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransServerOnChannelOpenFailedTest001, TestSize.Level1)
{
    (void)TransChannelInit();
    const char *pkgName = TEST_PKG_NAME;
    int32_t ret = TransServerOnChannelOpenFailed(pkgName, 0, -1, 0, SOFTBUS_ERR);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransServerOnChannelOpenFailed(NULL, 0, -1, 0, SOFTBUS_ERR);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/**
 * @tc.name: TransGetAuthTypeByNetWorkIdTest001
 * @tc.desc: TransGetAuthTypeByNetWorkIdTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetAuthTypeByNetWorkIdTest001, TestSize.Level1)
{
    (void)TransChannelInit();
    string networkId = "testNetworkId";
    bool ret = TransGetAuthTypeByNetWorkId(networkId.c_str());
    EXPECT_NE(true, ret);
    TransChannelDeinit();
}

} // namespace OHOS