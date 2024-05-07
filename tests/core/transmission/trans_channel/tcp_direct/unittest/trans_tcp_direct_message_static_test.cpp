/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <securec.h>

#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "lnn_lane_interface.h"
#include "lnn_decision_db.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_server_frame.h"
#include "softbus_trans_def.h"
#include "softbus_proxychannel_message.h"
#include "wifi_direct_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_socket.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "data_bus_native.h"
#include "lnn_lane_link.h"
#include "lnn_net_builder.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_message.c"
#include "trans_session_service.h"
#include "disc_event_manager.h"
#include "softbus_conn_ble_direct.h"
#include "message_handler.h"
#include "trans_channel_manager.h"

using namespace testing::ext;

namespace OHOS {
#define PKG_NAME_SIZE_MAX_LEN 65
#define NETWORK_ID_BUF_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 256
#define TEST_GROUP_ID_LEN 64
#define IP_LEN 46
#define ERRMOUDLE 13
#define INVALID_VALUE (-1)
#define EOK 0

static const char *g_pkgName = "dms";
static int32_t g_netWorkId = 100;

class TransTcpDirectMessageStaticTest : public testing::Test {
public:
    TransTcpDirectMessageStaticTest()
    {}
    ~TransTcpDirectMessageStaticTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectMessageStaticTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
    TransChannelInit();
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTdcSetCallBack(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TransTcpDirectMessageStaticTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
    TransChannelDeinit();
}

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authHandle.authId = 1;
    conn->requestId = 1;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.fd = g_netWorkId;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    return conn;
}

AppInfo *TestSetAppInfo()
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return nullptr;
    }
    
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    return appInfo;
}

/**
 * @tc.name: SwitchCipherTypeToAuthLinkType0001
 * @tc.desc: SwitchCipherTypeToAuthLinkType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SwitchCipherTypeToAuthLinkType0001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        return;
    }

    conn->appInfo.routeType = WIFI_STA;
    uint32_t cipherFlagBr = FLAG_BR;
    uint32_t cipherFlagBle = FLAG_BLE;
    uint32_t cipherFlagP2p = FLAG_P2P;
    uint32_t cipherFlagWifi = FLAG_WIFI;

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlagBr);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BR);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagBle);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BLE);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagP2p);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_P2P);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagWifi);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_WIFI);

    SendFailToFlushDevice(conn);
    SoftBusFree(conn);
    conn = nullptr;
}

/**
 * @tc.name: NotifyChannelOpened0002
 * @tc.desc: NotifyChannelOpened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelOpened0002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;

    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: TransTdcPostFisrtData0003
 * @tc.desc: TransTdcPostFisrtData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostFisrtData0003, TestSize.Level1)
{
    int32_t ret;
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        return;
    }

    ret = TransTdcPostFisrtData(conn);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);

    SoftBusFree(conn);
    conn = nullptr;
}

/**
 * @tc.name: TransGetLocalConfig0004
 * @tc.desc: TransGetLocalConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransGetLocalConfig0004, TestSize.Level1)
{
    int32_t ret;
    uint32_t localDataConfig = 0;
    int32_t businessTypeByte = BUSINESS_TYPE_BYTE;
    int32_t businessTypeMsg = BUSINESS_TYPE_MESSAGE;

    ret = TransGetLocalConfig(CHANNEL_TYPE_TCP_DIRECT, businessTypeByte, &localDataConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetLocalConfig(CHANNEL_TYPE_TCP_DIRECT, businessTypeMsg, &localDataConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcProcessDataConfig0005
 * @tc.desc: TransTdcProcessDataConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcProcessDataConfig0005, TestSize.Level1)
{
    AppInfo *appInfo = TestSetAppInfo();

    appInfo->peerData.dataConfig = 1;
    int32_t ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_FILE;
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
    appInfo = nullptr;
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: ProcessMessage0006
 * @tc.desc: ProcessMessage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, ProcessMessage0006, TestSize.Level1)
{
    int32_t channelId = 1;
    uint8_t *data = nullptr;
    int32_t ret;
    uint32_t flagReply = FLAG_REPLY;
    uint32_t flagRequst = FLAG_REQUEST;
    uint64_t seq = 1;
    char *dataTmp = reinterpret_cast<char *>(data);

    ret = ProcessMessage(channelId, flagReply, seq, dataTmp);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    ret = ProcessMessage(channelId, flagRequst, seq, dataTmp);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/**
 * @tc.name: OpenDataBusRequestReply0007
 * @tc.desc: OpenDataBusRequestReply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestReply0007, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    uint64_t seq = 1;
    uint32_t flags = FLAG_REPLY;
    AppInfo *appInfo = TestSetAppInfo();

    ret = OpenDataBusRequestReply(appInfo, channelId, seq, flags);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/**
 * @tc.name: GetUuidByChanId0008
 * @tc.desc: GetUuidByChanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, GetUuidByChanId0008, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    AppInfo *appInfo = TestSetAppInfo();

    ret = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    channelId = 0;

    ret = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}


/**
 * @tc.name: TransTdcFillDataConfig0009
 * @tc.desc: TransTdcFillDataConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcFillDataConfig0009, TestSize.Level1)
{
    int32_t ret;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));

    appInfo->businessType = BUSINESS_TYPE_FILE;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->peerData.dataConfig = 0;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->peerData.dataConfig = 1;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/**
 * @tc.name: TransSrvGetDataBufNodeById0010
 * @tc.desc: TransSrvGetDataBufNodeById.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransSrvGetDataBufNodeById0010, TestSize.Level1)
{
    int32_t channelId = 1;
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    EXPECT_TRUE(node == NULL || node->data == NULL);
}

/**
 * @tc.name: ProcessReceivedData0011
 * @tc.desc: ProcessReceivedData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, ProcessReceivedData0011, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    ret = TransSrvDataListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ProcessReceivedData(channelId, 0);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransTdcSrvProcData0012
 * @tc.desc: TransTdcSrvProcData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcSrvProcData0012, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;

    ret = TransSrvDataListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcSrvProcData(DIRECT_CHANNEL_SERVER_P2P, channelId, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);
    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransTdcUpdateDataBufWInfo0013
 * @tc.desc: TransTdcUpdateDataBufWInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcUpdateDataBufWInfo0013, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    char *recvBufNull = nullptr;
    string recvStr = "testrecvBuf";
    int32_t recvLen = 10;
    void *tmp = SoftBusCalloc(recvLen);
    if (tmp == nullptr) {
        return;
    }

    char *recvBuf = reinterpret_cast<char *>(tmp);
    ret = TransTdcUpdateDataBufWInfo(channelId, recvBufNull, recvLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    strcpy_s(recvBuf, recvLen, recvStr.c_str());
    ret = TransTdcUpdateDataBufWInfo(channelId, recvBuf, recvLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(tmp);
    tmp = nullptr;
}

/**
 * @tc.name: PackTdcPacketHeadTest001
 * @tc.desc: PackTdcPacketHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, PackTdcPacketHeadTest001, TestSize.Level1)
{
    TdcPacketHead data;
    PackTdcPacketHead(&data);
    EXPECT_TRUE(1);
}

/**
 * @tc.name: UnpackTdcPacketHeadTest001
 * @tc.desc: UnpackTdcPacketHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, UnpackTdcPacketHeadTest001, TestSize.Level1)
{
    TdcPacketHead data;
    UnpackTdcPacketHead(&data);
    EXPECT_TRUE(1);
}

/**
 * @tc.name: SwitchCipherTypeToAuthLinkTypeTest001
 * @tc.desc: SwitchCipherTypeToAuthLinkType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SwitchCipherTypeToAuthLinkTypeTest001, TestSize.Level1)
{
    uint32_t cipherFlag = FLAG_BR;
    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BR);

    cipherFlag = FLAG_BLE;
    linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BLE);

    cipherFlag = FLAG_P2P;
    linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_P2P);

    cipherFlag = FLAG_WIFI;
    linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_WIFI);
}

/**
 * @tc.name: NotifyChannelClosedTest001
 * @tc.desc: NotifyChannelClosed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelClosedTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = NotifyChannelClosed(appInfo, 1);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: NotifyChannelOpenedTest001
 * @tc.desc: NotifyChannelOpened, wrong input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: SendFailToFlushDeviceTest001
 * @tc.desc: SendFailToFlushDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SendFailToFlushDeviceTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_STA;
    conn->appInfo.peerData.deviceId[0] = '\0';
    SendFailToFlushDevice(conn);
    SoftBusFree(conn);
}

/**
 * @tc.name: TransTdcPostFisrtDataTest001
 * @tc.desc: TransTdcPostFisrtData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostFisrtDataTest001, TestSize.Level1)
{
    SessionConn *con = TestSetSessionConn();
    EXPECT_NE(con, NULL);

    int32_t ret = TransTdcPostFisrtData(con);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(con);
}

/**
 * @tc.name: FindConfigTypeTest001
 * @tc.desc: FindConfigType, normal input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, FindConfigTypeTest001, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t bussinessType = BUSINESS_TYPE_BYTE;
    int32_t ret = FindConfigType(channelType, bussinessType);
    EXPECT_EQ(ret, SOFTBUS_INT_MAX_BYTES_NEW_LENGTH);
}

/**
 * @tc.name: FindConfigTypeTest002
 * @tc.desc: FindConfigType, wrong input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, FindConfigTypeTest002, TestSize.Level1)
{
    int32_t channelType = -1;
    int32_t bussinessType = BUSINESS_TYPE_BYTE;
    int32_t ret = FindConfigType(channelType, bussinessType);
    EXPECT_EQ(ret, SOFTBUS_CONFIG_TYPE_MAX);
}

/**
 * @tc.name: TransTdcProcessDataConfigTest001
 * @tc.desc: TransTdcProcessDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcProcessDataConfigTest001, TestSize.Level1)
{
    int32_t ret = TransTdcProcessDataConfig(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AppInfo *appInfo = TestSetAppInfo();
    ASSERT_TRUE(appInfo != nullptr);

    appInfo->businessType = BUSINESS_TYPE_BUTT;
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    appInfo->myData.dataConfig = 2;
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->myData.dataConfig = 0;
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransTdcPostReplyMsgTest001
 * @tc.desc: TransTdcPostReplyMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostReplyMsgTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;

    int32_t ret = TransTdcPostReplyMsg(channelId, seq, flags, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: OpenDataBusRequestReplyTest001
 * @tc.desc: OpenDataBusRequestReply
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestReplyTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;

    int32_t ret = OpenDataBusRequestReply(NULL, channelId, seq, flags);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: OpenDataBusRequestErrorTest001
 * @tc.desc: OpenDataBusRequestError
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestErrorTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;
    int32_t errCode = -1;

    int32_t ret = OpenDataBusRequestError(channelId, seq, NULL, errCode, flags);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: OpenDataBusRequestOutSessionNameTest001
 * @tc.desc: OpenDataBusRequestOutSessionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestOutSessionNameTest001, TestSize.Level1)
{
    char *mySessionName = nullptr;
    char *peerSessionName = nullptr;
    OpenDataBusRequestOutSessionName(mySessionName, peerSessionName);
}

/**
 * @tc.name: NotifyFastDataRecvTest001
 * @tc.desc: NotifyFastDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyFastDataRecvTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    EXPECT_NE(conn, nullptr);

    int32_t channelId = 1;
    NotifyFastDataRecv(conn, channelId);

    SoftBusFree(conn);
}

/**
 * @tc.name: TransTdcFillDataConfigTest001
 * @tc.desc: TransTdcFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcFillDataConfigTest001, TestSize.Level1)
{
    int32_t ret = TransTdcFillDataConfig(NULL);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    AppInfo *appInfo = TestSetAppInfo();
    EXPECT_NE(appInfo, nullptr);

    appInfo->businessType = BUSINESS_TYPE_BUTT;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->peerData.dataConfig = 1;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->peerData.dataConfig = 1;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->peerData.dataConfig = 0;
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: IsMetaSessionTest001
 * @tc.desc: Should return false when given invalid parameter.
 * @tc.desc: Should return true when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, IsMetaSessionTest001, TestSize.Level1)
{
    const char *invalid = "test";
    bool ret = IsMetaSession(invalid);
    EXPECT_FALSE(ret);
    const char *testSession = "testsession";
    ret = IsMetaSession(testSession);
    EXPECT_FALSE(ret);
    const char *sessionName = "IShare";
    ret = IsMetaSession(sessionName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TransTdcGetDataBufInfoByChannelId001
 * @tc.desc: Should return SOFTBUS_ERR when given invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcGetDataBufInfoByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    size_t len = 1;
    int32_t ret = TransTdcGetDataBufInfoByChannelId(channelId, nullptr, &len);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = nullptr;
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: TransTdcUpdateDataBufWInfo0014
 * @tc.desc: Should return SOFTBUS_ERR when dataList is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcUpdateDataBufWInfo0014, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    string recvStr = "testrecvBuf";
    int32_t recvLen = 10;
    void *tmp = SoftBusCalloc(recvLen);
    if (tmp == nullptr) {
        return;
    }

    char *recvBuf = reinterpret_cast<char *>(tmp);
    strcpy_s(recvBuf, recvLen, recvStr.c_str());
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = nullptr;
    ret = TransTdcUpdateDataBufWInfo(channelId, recvBuf, recvLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(tmp);
    tmp = nullptr;
}

}
