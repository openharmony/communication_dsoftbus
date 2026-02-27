/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "data_bus_native.h"
#include "disc_event_manager.h"
#include "lnn_decision_db.h"
#include "lnn_lane_link.h"
#include "lnn_net_builder.h"
#include "message_handler.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_socket.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "trans_channel_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_message.c"
#include "trans_tcp_direct_test.h"
#include "trans_session_service.h"
#include "wifi_direct_manager.h"

#define TEST_CHANNEL_ID 1027
#define TEST_TDC_PID 3284
#define TEST_TDC_FASTDATA_SIZE 125

using namespace testing::ext;

namespace OHOS {

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

/*
 * @tc.name: SwitchCipherTypeToAuthLinkType0001
 * @tc.desc: Test whether the function
 *           SwitchCipherTypeToAuthLinkType can correctly convert different cipher
 *           to the corresponding AuthLinkType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SwitchCipherTypeToAuthLinkType0001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return;
    }

    conn->appInfo.routeType = WIFI_STA;
    uint32_t cipherFlagBr = FLAG_BR;
    uint32_t cipherFlagBle = FLAG_BLE;
    uint32_t cipherFlagP2p = FLAG_P2P;
    uint32_t cipherFlagWifi = FLAG_WIFI;
    uint32_t cipherFlagSle = FLAG_SLE;
    uint32_t cipherFlagEnhance = FLAG_ENHANCE_P2P;

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlagBr);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BR);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagBle);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_BLE);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagP2p);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_P2P);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagEnhance);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_ENHANCED_P2P);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagWifi);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_WIFI);

    linkType = SwitchCipherTypeToAuthLinkType(cipherFlagSle);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_SESSION_KEY);

    SendFailToFlushDevice(conn);
    SoftBusFree(conn);
    conn = nullptr;
}

/*
 * @tc.name: NotifyChannelOpened0002
 * @tc.desc: Test whether the return value of the NotifyChannelOpened function
 *           under a specific channel ID meets the expected results
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelOpened0002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;

    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
}

/*
 * @tc.name: TransTdcPostFisrtData0003
 * @tc.desc: Test whether the return value of the TransTdcPostFisrtData function
 *           meets the expected result under specific conditions
 *           (expected return value: encryption error SOFTBUS_ENCRYPT_ERR)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostFisrtData0003, TestSize.Level1)
{
    int32_t ret;
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return;
    }

    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);

    SoftBusFree(conn);
    conn = nullptr;
}

/*
 * @tc.name: TransGetLocalConfig0004
 * @tc.desc: Test the local configuration retrieval function
 *           of the TCP direct message channel
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

/*
 * @tc.name: TransTdcProcessDataConfig0005
 * @tc.desc: Test the behavior and return values of the TransTdcProcessDataConfig function
 *           under different input conditions to verify if they meet expectations
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

/*
 * @tc.name: ProcessMessage0006
 * @tc.desc: Test the behavior of the ProcessMessage function
 *           when handling empty data, verifying whether it can correctly return a JSON parsing error
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
    uint32_t dataLen = 0;

    ret = ProcessMessage(channelId, flagReply, seq, dataTmp, dataLen);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    ret = ProcessMessage(channelId, flagRequst, seq, dataTmp, dataLen);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: OpenDataBusRequestReply0007
 * @tc.desc: Test whether the return value of the OpenDataBusRequestReply function
 *           meets expectations under specific conditions
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
    EXPECT_EQ(ret, SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/*
 * @tc.name: GetUuidByChanId0008
 * @tc.desc: Test the behavior of the GetUuidByChanId function
 *           when given an invalid channel ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, GetUuidByChanId0008, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret;
    AppInfo *appInfo = TestSetAppInfo();

    ret = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_AUTH_ID_FAILED);
    channelId = 0;

    ret = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_AUTH_ID_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}


/*
 * @tc.name: TransTdcFillDataConfig0009
 * @tc.desc: Test the correctness of the TransTdcFillDataConfig function
 *           under different service types and data configurations
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

/*
 * @tc.name: TransSrvGetDataBufNodeById0010
 * @tc.desc: Test whether the function of obtaining data buffer nodes
 *           through channel ID is working correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransSrvGetDataBufNodeById0010, TestSize.Level1)
{
    int32_t channelId = 1;
    DataBuf *node = TransSrvGetDataBufNodeById(channelId);
    EXPECT_TRUE(node == nullptr || node->data == nullptr);
}

/*
 * @tc.name: ProcessReceivedData0011
 * @tc.desc: Test the behavior of the ProcessReceivedData function
 *           under specific conditions, particularly the return value when the input parameters
 *           may cause the node to be null
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
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_IS_NULL);
    TransSrvDataListDeinit();
}

/*
 * @tc.name: TransTdcSrvProcData0012
 * @tc.desc: Test the server is data processing functionality in the TCP direct message handling module
 *           specifically verifying whether the error handling logic is correct under specific conditions
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

/*
 * @tc.name: TransTdcUpdateDataBufWInfo0013
 * @tc.desc: Test the behavior of the TransTdcUpdateDataBufWInfo function
 *           under different input conditions，particularly verifying its
 *           handling of empty buffers and uninitialized states
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
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    SoftBusFree(tmp);
    tmp = nullptr;
}

/**
 * @tc.name: SwitchCipherTypeToAuthLinkTypeTest001
 * @tc.desc: Test whether the function SwitchCipherTypeToAuthLinkType can correctly convert the cipherFlag
 *           to the corresponding authentication link type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SwitchCipherTypeToAuthLinkTypeTest001, TestSize.Level1)
{
    TdcPacketHead data;
    PackTdcPacketHead(&data);
    UnpackTdcPacketHead(&data);
    UnpackTdcPacketHead(nullptr);
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

    cipherFlag = FLAG_SESSION_KEY;
    linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_SESSION_KEY);
}

/*
 * @tc.name: NotifyChannelClosedTest001
 * @tc.desc: Test whether the NotifyChannelClosed function behaves as expected
 *           under specific conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelClosedTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = NotifyChannelClosed(appInfo, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: NotifyChannelOpenedTest001
 * @tc.desc: test NotifyChannelOpened
 *           use wrong input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
}

/*
 * @tc.name: SendFailToFlushDeviceTest001
 * @tc.desc: Test the behavior of calling the SendFailToFlushDevice function
 *           under specific conditions
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

/*
 * @tc.name: TransTdcPostFisrtDataTest001
 * @tc.desc: Test the ability to handle exceptions in the fast data transmission function
 *           during TCP direct message transfer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostFisrtDataTest001, TestSize.Level1)
{
    SessionConn *con = TestSetSessionConn();
    EXPECT_NE(con, nullptr);

    int32_t ret = TransTdcPostFastData(con);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(con);
}

/*
 * @tc.name: FindConfigTypeTest001
 * @tc.desc: test FindConfigType
 *           use normal input
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

/*
 * @tc.name: FindConfigTypeTest002
 * @tc.desc: test FindConfigType
 *           use wrong input
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

/*
 * @tc.name: TransTdcProcessDataConfigTest001
 * @tc.desc: Test the behavior and return values of the TransTdcProcessDataConfig function
 *           under different input conditions to verify if they meet expectations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcProcessDataConfigTest001, TestSize.Level1)
{
    int32_t ret = TransTdcProcessDataConfig(nullptr);
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

/*
 * @tc.name: TransTdcPostReplyMsgTest001
 * @tc.desc: Test the behavior of the TransTdcPostReplyMsg function
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcPostReplyMsgTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;

    int32_t ret = TransTdcPostReplyMsg(channelId, seq, flags, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: OpenDataBusRequestReplyTest001
 * @tc.desc: Test the OpenDataBusRequestReply function is ability to handle exceptions
 *           when null pointer parameters are passed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestReplyTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;

    int32_t ret = OpenDataBusRequestReply(nullptr, channelId, seq, flags);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: OpenDataBusRequestErrorTest001
 * @tc.desc: Test whether the return value of the OpenDataBusRequestError function meets expectations
 *           under specific input conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, OpenDataBusRequestErrorTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint32_t flags = 1;
    int32_t errCode = -1;

    int32_t ret = OpenDataBusRequestError(channelId, seq, nullptr, errCode, flags);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_PACK_REPLY_FAILED);
}

/*
 * @tc.name: NotifyFastDataRecvTest001
 * @tc.desc: test NotifyFastDataRecv
 *           Test the TCP direct message receiving notification function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, NotifyFastDataRecvTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    EXPECT_NE(conn, nullptr);

    int32_t channelId = 1;
    NotifyFastDataRecv(conn, channelId);

    char *mySessionName = nullptr;
    char *peerSessionName = nullptr;
    OpenDataBusRequestOutSessionName(mySessionName, peerSessionName);

    SoftBusFree(conn);
}

/*
 * @tc.name: TransTdcFillDataConfigTest001
 * @tc.desc: Test the function TransTdcFillDataConfig to verify whether its behavior meets expectations
 *           under different input conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcFillDataConfigTest001, TestSize.Level1)
{
    int32_t ret = TransTdcFillDataConfig(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

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

/*
 * @tc.name: TransTdcGetDataBufInfoByChannelId001
 * @tc.desc: test TransTdcGetDataBufInfoByChannelId
 *           Should return SOFTBUS_INVALID_PARAM when given invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransTdcGetDataBufInfoByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    size_t len = 1;
    int32_t ret = TransTdcGetDataBufInfoByChannelId(channelId, nullptr, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = nullptr;
    ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcUpdateDataBufWInfo0014
 * @tc.desc: test TransTdcUpdateDataBufWInfo
             Should return SOFTBUS_NO_INIT when dataList is null
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
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    SoftBusFree(tmp);
    tmp = nullptr;
}

/*
 * @tc.name: GetChannelInfoFromConn001
 * @tc.desc: test GetChannelInfoFromConn
 *           Test when channelId is valid then GetChannelInfoFromConn returns valid ChannelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, GetChannelInfoFromConn001, TestSize.Level1)
{
    ChannelInfo info;
    SessionConn conn;
    int32_t channelId = 1;
    conn.serverSide = true;
    conn.appInfo.fd = 1;
    (void)strcpy_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), "1");
    conn.appInfo.myHandleId = 1;
    conn.appInfo.peerHandleId = 1;
    (void)strcpy_s(conn.appInfo.peerData.sessionName, sizeof(conn.appInfo.peerData.sessionName), "test");
    (void)strcpy_s(conn.appInfo.groupId, sizeof(conn.appInfo.groupId), "1");
    conn.appInfo.peerData.uid = 1;
    conn.appInfo.peerData.pid = 1;
    conn.appInfo.routeType = WIFI_STA;
    conn.appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    conn.appInfo.autoCloseTime = 1;
    (void)strcpy_s(conn.appInfo.peerData.addr, sizeof(conn.appInfo.peerData.addr), "127.0.0.1");
    conn.appInfo.peerData.port = 1;
    conn.appInfo.linkType = 1;
    conn.appInfo.myData.dataConfig = 1;

    GetChannelInfoFromConn(&info, &conn, channelId);
    EXPECT_EQ(info.channelId, channelId);
    EXPECT_EQ(info.channelType, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(info.isServer, conn.serverSide);
    EXPECT_EQ(info.isEnabled, true);
    EXPECT_EQ(info.fd, conn.appInfo.fd);
    EXPECT_EQ(info.sessionKey, conn.appInfo.sessionKey);
    EXPECT_EQ(info.peerSessionName, conn.appInfo.peerData.sessionName);
    EXPECT_EQ(info.groupId, conn.appInfo.groupId);
    EXPECT_EQ(info.isEncrypt, true);
    EXPECT_EQ(info.keyLen, SESSION_KEY_LENGTH);
    EXPECT_EQ(info.peerUid, conn.appInfo.peerData.uid);
    EXPECT_EQ(info.peerPid, conn.appInfo.peerData.pid);
    EXPECT_EQ(info.routeType, conn.appInfo.routeType);
    EXPECT_EQ(info.businessType, conn.appInfo.businessType);
    EXPECT_EQ(info.autoCloseTime, conn.appInfo.autoCloseTime);
    EXPECT_EQ(info.peerIp, conn.appInfo.peerData.addr);
    EXPECT_EQ(info.peerPort, conn.appInfo.peerData.port);
    EXPECT_EQ(info.linkType, conn.appInfo.linkType);
    EXPECT_EQ(info.dataConfig, conn.appInfo.myData.dataConfig);
}

/*
 * @tc.name: GetServerSideIpInfoTest001
 * @tc.desc: Test the function of obtaining IP information on the server and client sides
 *           verify that in the WIFI_P2P routing type scenario, obtaining the server is IP
 *           information fails, while obtaining the client is IP information succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, GetServerSideIpInfoTest001, TestSize.Level1)
{
    uint32_t len = 10; // test value
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_P2P;
    char myIp[IP_LEN] = { 0 };
    int32_t ret = GetServerSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_P2P_INFO_FAILED);

    ret = GetClientSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(conn);
}

/*
 * @tc.name: ReleaseSessionConnTest001
 * @tc.desc: Test the release function of session connections to verify whether session connection resources
 *           can be correctly released under specific conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, ReleaseSessionConnTest001, TestSize.Level1)
{
    SessionConn *chan = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(chan != nullptr);

    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = NotifyChannelBind(channelId, chan);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NAME_NO_EXIST);
    ReleaseSessionConn(chan);
}

/*
 * @tc.name: TransSrvGetSeqAndFlagsByChannelIdTest001
 * @tc.desc: Test the behavior of the TransSrvGetSeqAndFlagsByChannelId function
 *           under different initialization states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransSrvGetSeqAndFlagsByChannelIdTest001, TestSize.Level1)
{
    uint64_t seq = 1;
    uint32_t flags = 1;
    int32_t channelId = 1;
    int32_t ret = TransSrvGetSeqAndFlagsByChannelId(&seq, &flags, channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = TransSrvDataListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSrvGetSeqAndFlagsByChannelId(&seq, &flags, channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_IS_NULL);
}

/*
 * @tc.name: TransSrvGetSeqAndFlagsByChannelIdTest002
 * @tc.desc: Test the function of obtaining serial numbers and flags through channel IDs
 *           and verify the correctness of the related data processing procedures
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransSrvGetSeqAndFlagsByChannelIdTest002, TestSize.Level1)
{
    uint64_t seq = 1;
    uint32_t flags = 1;
    int32_t channelId = 1;
    int32_t fd = 1;
    int32_t openResult = 1;
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSrvGetSeqAndFlagsByChannelId(&seq, &flags, channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    TransProcessAsyncOpenTdcChannelFailed(conn, openResult, seq, flags);
    TransCleanTdcSource(channelId);
    SoftBusFree(conn);
}

/*
 * @tc.name: TransDealTdcChannelOpenResultTest001
 * @tc.desc: Test the function TransDealTdcChannelOpenResult for handling TCP direct message channel open
 *           results, examining its behavior and return values under different scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransDealTdcChannelOpenResultTest001, TestSize.Level1)
{
    int32_t openResult = 1;
    int32_t channelId = 1;
    int32_t fd = 1;
    AccessInfo accessInfo = { 0 };
    CreatSessionConnList();
    TransSrvDataListInit();
    int32_t ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_IS_NULL);
    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);
    TransDelSessionConnById(channelId);
}

/*
 * @tc.name: TransDealTdcChannelOpenResultTest001
 * @tc.desc: Test the behavior of the function TransDealTdcChannelOpenResult
 *           which processes TCP direct message channel open results, under different conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransDealTdcChannelOpenResultTest002, TestSize.Level1)
{
    int32_t openResult = SOFTBUS_OK;
    int32_t channelId = 1;
    int32_t fd = 1;
    AccessInfo accessInfo = { 0 };
    int32_t ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.myData.tokenType = 1;
    conn->appInfo.channelCapability = 0xF;
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);
    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealTdcChannelOpenResult(channelId, openResult, &accessInfo, TEST_TDC_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);
    TransDelSessionConnById(channelId);
}

/*
 * @tc.name: TransAsyncTcpDirectChannelTaskTest001
 * @tc.desc: Test the processing logic of asynchronous TCP direct channel tasks to verify task execution
 *           under different waiting response count states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, TransAsyncTcpDirectChannelTaskTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransAsyncTcpDirectChannelTask(channelId);
    // conn will free in Line 956
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransAsyncTcpDirectChannelTask(channelId);
    conn->appInfo.waitOpenReplyCnt = CHANNEL_OPEN_SUCCESS;
    TransAsyncTcpDirectChannelTask(channelId);
    conn->appInfo.waitOpenReplyCnt = LOOPER_REPLY_CNT_MAX;
    TransAsyncTcpDirectChannelTask(channelId);
    SessionConn *testConn = TestSetSessionConn();
    ASSERT_TRUE(testConn != nullptr);
    ret = TransTdcAddSessionConn(testConn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    testConn->appInfo.waitOpenReplyCnt = LOOPER_REPLY_CNT_MAX - 1;
    TransAsyncTcpDirectChannelTask(channelId);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: CheckServerPermissionTest001
 * @tc.desc: given fdProtocol is HTP and uid not hold htp will return SOFTBUS_PERMISSION_SERVER_DENIED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, CheckServerPermissionTest001, TestSize.Level1)
{
    AppInfo info;
    info.fdProtocol = LNN_PROTOCOL_HTP;
    info.myData.uid = 0;
    char *data = (char *)SoftBusCalloc(sizeof(SessionConn));
    int32_t ret = CheckServerPermission(&info, data);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_SERVER_DENIED);
    SoftBusFree(data);
}

/**
 * @tc.name: GetSessionConnSeqAndFlagByChannelIdTest001
 * @tc.desc: given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, GetSessionConnSeqAndFlagByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    SessionConn conn;
    uint32_t flags = 1;
    uint64_t seq = 1;
    int32_t ret = GetSessionConnSeqAndFlagByChannelId(channelId, nullptr, &flags, &seq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionConnSeqAndFlagByChannelId(channelId, &conn, nullptr, &seq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionConnSeqAndFlagByChannelId(channelId, &conn, &flags, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BuildEventExtra001
 * @tc.desc: To verify whether the BuildEventExtra function behaves correctly
 *           under specific input parameters, ensuring that it does not trigger a fatal error or crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, BuildEventExtra001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(BuildEventExtra(2688));
}

/**
 * @tc.name: SetByteChannelTos001
 * @tc.desc: test SetByteChannelTos when businessType is BUSINESS_TYPE_BYTE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, SetByteChannelTos001, TestSize.Level1)
{
    AppInfo info = {
        .businessType = BUSINESS_TYPE_BYTE,
        .channelType = CHANNEL_TYPE_TCP_DIRECT,
        .fd = 123
    };

    EXPECT_NO_FATAL_FAILURE(SetByteChannelTos(&info));
}

/**
 * @tc.name: ReleaseSessionConn002
 * @tc.desc: test ReleaseSessionConn when conn is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageStaticTest, ReleaseSessionConn002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ReleaseSessionConn(nullptr));

    SessionConn *chan = static_cast<SessionConn *>(SoftBusCalloc(sizeof(SessionConn)));
    ASSERT_TRUE(chan != nullptr);
    chan->appInfo.fastTransData = const_cast<const uint8_t *>(
        static_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t) * TEST_TDC_FASTDATA_SIZE)));
    ASSERT_TRUE(chan->appInfo.fastTransData != nullptr);

    EXPECT_NO_FATAL_FAILURE(ReleaseSessionConn(chan));
}
}
