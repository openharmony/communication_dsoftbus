/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "bus_center_manager.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "lnn_lane_interface.h"
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

#include "trans_channel_callback.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_auth_message.h"
#include "trans_lane_pending_ctl.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_json.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_sessionconn.c"

using namespace testing::ext;

namespace OHOS {

#define PID 2024
#define UID 4000
#define PKG_NAME_SIZE_MAX_LEN 65
#define NETWORK_ID_BUF_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 256
#define TEST_GROUP_ID_LEN 64
#define IP_LEN 46
#define ERRMOUDLE 13
#define INVALID_VALUE (-1)

static const char *g_sessionName = "com.test.trans.auth.demo";
static const char *g_pkgName = "dms";
static const char *g_ip = "192.168.8.1";
static int32_t g_port = 6000;

class TransCoreTcpDirectTest : public testing::Test {
public:
    TransCoreTcpDirectTest()
    {}
    ~TransCoreTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransCoreTcpDirectTest::SetUpTestCase(void)
{
    InitSoftBusServer();
}

void TransCoreTcpDirectTest::TearDownTestCase(void)
{}

SessionServer *TestSetPack()
{
    SessionServer *newNode = (SessionServer*)SoftBusCalloc(sizeof(SessionServer));
    if (newNode == nullptr) {
        return nullptr;
    }

    (void)memset_s(newNode, sizeof(SessionServer), 0, sizeof(SessionServer));
    (void)memcpy_s(newNode->sessionName, SESSION_NAME_MAX_LEN, g_sessionName, strlen(g_sessionName));
    (void)memcpy_s(newNode->pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, strlen(g_pkgName));
    newNode->pid = PID;
    newNode->uid = UID;
    return newNode;
}

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }

    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authId = 1;
    conn->requestId = 0;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    return conn;
}

string TestGetMsgPack()
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        cJSON_Delete(msg);
        return nullptr;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        cJSON_Delete(msg);
        return nullptr;
    }

    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = 1;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName)+1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    if (TransAuthChannelMsgPack(msg, appInfo) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        return nullptr;
    }
    string data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    return data;
}

/**
 * @tc.name: TransTcpDirectInitTest001
 * @tc.desc: TransTcpDirectInit, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTcpDirectInitTest001, TestSize.Level1)
{
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransTcpDirectDeinit();

    ret = TransTcpDirectInit(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransTcpDirectDeinit();
}

/**
 * @tc.name: TransTdcDeathCallbackTest002
 * @tc.desc: TransTdcDeathCallback, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcDeathCallbackTest002, TestSize.Level1)
{
    int32_t pid = 1;
    TransTdcDeathCallback(g_pkgName, pid);
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcAddSessionConn(conn);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransTdcDeathCallback(g_pkgName, pid);

    TransTdcDeathCallback(nullptr, pid);
    TransTcpDirectDeinit();
}

/**
 * @tc.name: TransOpenDirectChannelTest003
 * @tc.desc: TransOpenDirectChannel, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransOpenDirectChannelTest003, TestSize.Level1)
{
    char mySessionName[SESSION_NAME_MAX_LEN] = "com.test.trans.session.sendfile";
    char peerSessionName[SESSION_NAME_MAX_LEN] = "com.test.trans.session.sendfile";
    char peerNetworkId[NETWORK_ID_BUF_MAX_LEN] = "1234567789";
    char groupId[TEST_GROUP_ID_LEN] = "123";
    SessionAttribute attr;
    LaneConnInfo connInfo;
    ConnectOption connOpt;
    int32_t channelId = 0;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    uint32_t laneId = 0;
    attr.dataType = 1;
    attr.linkTypeNum = 0;
    SessionParam param = {
        .sessionName = mySessionName,
        .peerSessionName = peerSessionName,
        .peerDeviceId = peerNetworkId,
        .groupId = groupId,
        .attr = &attr,
    };
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    (void)memcpy_s(appInfo->myData.addr, IP_LEN, g_ip, strlen(g_ip));

    int32_t ret = TransGetLaneInfo(&param, &connInfo, &laneId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransGetConnectOptByConnInfo(&connInfo, &connOpt);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    connOpt.type = CONNECT_P2P;
    ret = TransOpenDirectChannel(appInfo, &connOpt, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(NULL, &connOpt, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransTdcStopSessionProcTest004
 * @tc.desc: TransTdcStopSessionProc, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcStopSessionProcTest004, TestSize.Level1)
{
    int32_t ret = TransSrvDataListInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransTdcStopSessionProc((ListenerModule)DIRECT_CHANNEL_SERVER_WIFI);

    TransTdcStopSessionProc((ListenerModule)ERRMOUDLE);
    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransSrvDataListInitTest005
 * @tc.desc: TransSrvDataListInit and TransSrvDataListDeinit, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransSrvDataListInitTest005, TestSize.Level1)
{
    int32_t ret = TransSrvDataListInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransSrvAddDataBufNodeTest006
 * @tc.desc: TransSrvAddDataBufNode, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransSrvAddDataBufNodeTest006, TestSize.Level1)
{
    int32_t channeId = 1;
    int32_t fd = 1;

    int32_t ret = TransSrvDataListInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSrvAddDataBufNode(channeId, fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransSrvDelDataBufNodeTest007
 * @tc.desc: TransSrvDelDataBufNode, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransSrvDelDataBufNodeTest007, TestSize.Level1)
{
    int32_t channeId = 1;
    int32_t fd = 1;
    TransSrvDelDataBufNode(channeId);

    int32_t ret = TransSrvDataListInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSrvAddDataBufNode(channeId, fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransSrvDelDataBufNode(channeId);
}

/**
 * @tc.name: VerifyP2pPackTest008
 * @tc.desc: VerifyP2pPack, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, VerifyP2pPackTest008, TestSize.Level1)
{
    char *ret = VerifyP2pPack(g_ip, g_port, NULL);
    EXPECT_TRUE(ret != nullptr);

    ret = VerifyP2pPack(nullptr, g_port, NULL);
    EXPECT_TRUE(ret == nullptr);
}

/**
 * @tc.name: VerifyP2pUnPackTest009
 * @tc.desc: VerifyP2pUnPack, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, VerifyP2pUnPackTest009, TestSize.Level1)
{
    char peerIp[IP_LEN] = {0};
    int32_t peerPort;
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);

    char *pack = VerifyP2pPack(g_ip, g_port, NULL);
    EXPECT_TRUE(pack != nullptr);

    int32_t ret = VerifyP2pUnPack(json, peerIp, IP_LEN, &peerPort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = VerifyP2pUnPack(json, const_cast<char *>(g_ip), IP_LEN, &g_port);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = VerifyP2pUnPack(NULL, const_cast<char *>(g_ip), IP_LEN, &g_port);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(json);
}

/**
 * @tc.name: VerifyP2pPackErrorTest0010
 * @tc.desc: VerifyP2pPackError, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, VerifyP2pPackErrorTest0010, TestSize.Level1)
{
    int32_t code = CODE_VERIFY_P2P;
    int32_t errCode = SOFTBUS_INVALID_PARAM;

    char* ret = VerifyP2pPackError(code, errCode, "OnVerifyP2pRequest unpack fail");
    EXPECT_TRUE(ret != nullptr);

    ret = VerifyP2pPackError(code, errCode, nullptr);
    EXPECT_TRUE(ret == nullptr);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest0011
 * @tc.desc: GetCipherFlagByAuthId, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(TransCoreTcpDirectTest, GetCipherFlagByAuthIdTest0011, TestSize.Level1)
{
    bool isAuthServer = false;
    int64_t authId = 1;
    uint32_t flag = 0;

    int32_t ret = GetCipherFlagByAuthId(authId, &flag, &isAuthServer);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    authId = INVALID_VALUE;
    ret = GetCipherFlagByAuthId(authId, &flag, &isAuthServer);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcStartSessionListenerTest0012
 * @tc.desc: tTransTdcStartSessionListener, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcStartSessionListenerTest0012, TestSize.Level1)
{
    LocalListenerInfo info;
    info.type = CONNECT_P2P;
    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = g_port;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    info.socketOption.moduleId = DIRECT_CHANNEL_SERVER_P2P;

    if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), g_ip) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_TEST, "copy addr failed!");
        return;
    }
    info.type = CONNECT_TCP;
    int32_t ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_P2P, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_P2P, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcStartSessionListener((ListenerModule)ERRMOUDLE, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_P2P);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcSetCallBackTest0013
 * @tc.desc: trans tcp direct set callback, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcSetCallBackTest0013, TestSize.Level1)
{
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTdcSetCallBack(cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcSetCallBack(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcGetUidAndPidTest0015
 * @tc.desc: TransTdcOnChannelOpenFailed, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcGetUidAndPidTest0015, TestSize.Level1)
{
    int32_t uid = 0;
    int32_t pid = 0;
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = TransSessionMgrInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SessionServer *newNode = TestSetPack();
    ret = TransSessionServerAddItem(newNode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    char pkgName[PKG_NAME_SIZE_MAX_LEN] = {0};
    ret = TransTdcGetPkgName(g_sessionName, pkgName, PKG_NAME_SIZE_MAX_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcGetUidAndPid(g_sessionName, &uid, &pid);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcOnChannelOpenFailed(g_pkgName, pid, channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransSessionMgrDeinit();
}

/**
 * @tc.name: TransTdcPostBytesTest0016
 * @tc.desc: TransTdcPostBytes, use wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcPostBytes0016, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *bytes = "Get Message";
    SessionConn* conn = TestSetSessionConn();
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TdcPacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.module = MODULE_SESSION;
    packetHead.seq = 0;
    packetHead.flags = FLAG_REQUEST;
    packetHead.dataLen = strlen(bytes);

    ret = TransTdcPostBytes(channelId, &packetHead, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcPostBytes(channelId, &packetHead, bytes);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest0017
 * @tc.desc: TransTdcSrvRecvData, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, TransTdcSrvRecvDataTest0017, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;

    int32_t ret = TransSrvDataListInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcSrvRecvData((ListenerModule)ERRMOUDLE, channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransSrvDataListDeinit();
}

/**
 * @tc.name: NotifyChannelOpenFailedTest0018
 * @tc.desc: NotifyChannelOpenFailed, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransCoreTcpDirectTest, NotifyChannelOpenFailedTest0018, TestSize.Level1)
{
    int errCode = SOFTBUS_OK;
    int32_t channelId = 1;
    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authId = 1;
    conn->requestId = 0;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));

    ret = TransTdcAddSessionConn(conn);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    conn->serverSide = false;
    ret = TransSessionMgrInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SessionServer *newNode = TestSetPack();
    ret = TransSessionServerAddItem(newNode);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    TransSessionMgrDeinit();
    SoftBusFree(conn);
}
}
