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

#include <securec.h>

#include "auth_interface.h"
#include "gtest/gtest.h"
#include "softbus_access_token_test.h"
#include "softbus_app_info.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "softbus_server_frame.h"
#include "trans_channel_manager.h"
#include "trans_lane_manager.c"
#include "trans_session_manager.h"
#include "trans_udp_channel_manager.c"
#include "trans_udp_negotiation.c"
#include "trans_udp_negotiation_exchange.c"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "trans_udp_negotiation_exchange.h"

using namespace testing::ext;

namespace OHOS {

static int64_t g_channelId = 0;
const char *g_sessionKey = "www.huaweitest.com";
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_groupid = "TEST_GROUP_ID";
#define MAX_ADDR_LENGTH (46)
#define ERROR_RET_TWO (2)
#define ERROR_RET_FIVE (5)
#define INVALID_ID (-1)
#define INVALID_SEQ (-1)
#define INVALID_AUTH_ID (-2)
#define TEST_SOCKET_ADDR "192.168.8.119"

class TransUdpNegoTest : public testing::Test {
public:
    TransUdpNegoTest()
    {}
    ~TransUdpNegoTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpNegoTest::SetUpTestCase(void)
{
    InitSoftBusServer();
    SetAceessTokenPermission("dsoftbusTransTest");
}

void TransUdpNegoTest::TearDownTestCase(void)
{}

char* TestGetMsgInfo(void)
{
    AppInfo info;
    info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    cJSON *requestMsg = cJSON_CreateObject();
    if (requestMsg == NULL) {
        cJSON_Delete(requestMsg);
        return nullptr;
    }

    if (TransPackRequestUdpInfo(requestMsg, &info) != SOFTBUS_OK) {
        cJSON_Delete(requestMsg);
        return nullptr;
    }
    char *msgStr = cJSON_PrintUnformatted(requestMsg);
    cJSON_Delete(requestMsg);
    return msgStr;
}

int64_t TestGetChannelId()
{
    g_channelId++;
    return g_channelId;
}

UdpChannelInfo* CreateUdpChannelPackTest()
{
    UdpChannelInfo *Channel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (Channel == NULL) {
        return nullptr;
    }
    Channel->requestId = 1;
    Channel->seq = 1;
    Channel->info.myData.channelId = TestGetChannelId();
    Channel->info.myData.pid = 1;
    Channel->info.appType = APP_TYPE_NORMAL;
    Channel->info.myData.apiVersion = API_V2;
    Channel->info.businessType = BUSINESS_TYPE_MESSAGE;
    Channel->info.peerData.apiVersion = API_V2;
    Channel->info.encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    Channel->info.algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    Channel->info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    (void)memcpy_s(Channel->info.groupId, GROUP_ID_SIZE_MAX, "123",
        (strlen("123")+1));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session", (strlen("com.test.trans.session")+1));
    (void)memcpy_s(Channel->info.peerNetWorkId, DEVICE_ID_SIZE_MAX,
        "1234567789", (strlen("1234567789")+1));
    (void)memcpy_s(Channel->info.peerData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session.sendfile", (strlen("com.test.trans.session.sendfile")+1));
    (void)memcpy_s(Channel->info.peerData.deviceId, DEVICE_ID_SIZE_MAX,
        "com.test.appinfo.deviceid", strlen("com.test.appinfo.deviceid")+1);
    (void)memcpy_s(Channel->info.sessionKey, SESSION_KEY_LENGTH,
        "auth session key", (strlen("auth session key")+1));
    (void)memcpy_s(Channel->info.myData.pkgName, PKG_NAME_SIZE_MAX,
        "normal pakName", (strlen("normal pakName")+1));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", (strlen("normal sessionName")+1));
    return Channel;
}

static void GenerateAppInfo(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
        EXPECT_TRUE(appInfo != NULL);
        memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    }
    int res = strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), g_sessionKey);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), g_groupid);
    EXPECT_EQ(res, EOK);
}

static void GenerateSessionServer(SessionServer *newNode)
{
    if (newNode == NULL) {
        newNode = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
        EXPECT_TRUE(newNode != NULL);
        memset_s(newNode, sizeof(SessionServer), 0, sizeof(SessionServer));
    }
    int32_t res = strcpy_s(newNode->pkgName, sizeof(newNode->pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    newNode->type = SEC_TYPE_PLAINTEXT;
    newNode->uid = 1;
    newNode->pid = 1;
}



/**
 * @tc.name: TransUdpNegoTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest001, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    int32_t ret = TransUnpackReplyErrInfo(NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    ret = TransUnpackReplyErrInfo(msg, &errCode);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUdpNegoTest002
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest002, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    const char* errDesc = "errDesc";

    int32_t ret = TransPackReplyErrInfo(NULL, errCode, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransPackReplyErrInfo(msg, errCode, errDesc);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUdpNegoTest003
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest003, TestSize.Level1)
{
    int64_t authId = AUTH_INVALID_ID;
    int64_t seq = 0;
    string msg = "ProcessMessage";
    cJSON *replyMsg = cJSON_Parse((char *)msg.c_str());
    int32_t ret = sendUdpInfo(NULL, authId, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = sendUdpInfo(replyMsg, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(replyMsg);
}

/**
 * @tc.name: TransUdpNegoTest004
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest004, TestSize.Level1)
{
    int32_t errCode = 0;
    string errDesc = "ProcessMessage";
    int32_t ret = SendReplyErrInfo(errCode, NULL, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = SendReplyErrInfo(errCode, (char *)errDesc.c_str(), NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest005
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest005, TestSize.Level1)
{
    int64_t authId = INVALID_ID;
    int64_t seq = INVALID_SEQ;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;

    int32_t ret = SendReplyUdpInfo(NULL, authId, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = SendReplyUdpInfo(&appInfo, NULL, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest006
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest006, TestSize.Level1)
{
    (void)TransChannelInit();
    char* data = TestGetMsgInfo();
    ASSERT_TRUE(data != nullptr);
    cJSON *msg = cJSON_Parse(data);
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);

    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    int64_t authId = AUTH_INVALID_ID;

    int32_t ret = TransAddUdpChannel(newChannel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    TransOnExchangeUdpInfoReply(authId, INVALID_SEQ, msg);
    TransOnExchangeUdpInfoReply(INVALID_AUTH_ID, newChannel->seq, msg);
    TransOnExchangeUdpInfoReply(authId, newChannel->seq, msg);
    cJSON_Delete(msg);
    TransChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest007
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest007, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    char* data = TestGetMsgInfo();
    ASSERT_TRUE(data != nullptr);
    cJSON *msg = cJSON_Parse(data);
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    int64_t authId = AUTH_INVALID_ID;

    ret = TransAddUdpChannel(newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransOnExchangeUdpInfoRequest(authId, newChannel->seq, NULL);
    cJSON_Delete(msg);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpNegoTest008
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest008, TestSize.Level1)
{
    int64_t seq = 0;
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = StartExchangeUdpInfo(&channel, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = StartExchangeUdpInfo(&channel, NULL, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest009
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest009, TestSize.Level1)
{
    int64_t authId = AUTH_INVALID_ID;
    AuthTransData data;
    int32_t ret = memset_s(&data, sizeof(AuthTransData), 0, sizeof(AuthTransData));
    EXPECT_TRUE(ret == SOFTBUS_OK);
    UdpModuleCb(authId, NULL);

    data.data = NULL;
    UdpModuleCb(authId, &data);

    data.data = (const uint8_t *)"data";
    data.len = 0;
    UdpModuleCb(authId, &data);

    data.flag = 0;
    UdpModuleCb(authId, &data);
}

/**
 * @tc.name: TransUdpNegoTest011
 * @tc.desc: Trans udp module callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest011, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t authId = 1;
    uint8_t val = 1;
    AuthTransData data1 = {0};
    UdpModuleCb(authId, &data1);
    AuthTransData data2 = {
        .data = nullptr,
    };
    UdpModuleCb(authId, &data2);
    AuthTransData data3 = {
        .data = &val,
    };
    data3.len = 0;
    UdpModuleCb(authId, &data3);
    data3.len = 1;
    data3.flag = true;
    UdpModuleCb(authId, &data3);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest012
 * @tc.desc: Trans dup exchange info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest012, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t authId = 1;
    uint8_t val = 1;
    AuthTransData data = {
        .data = &val,
    };
    cJSON *json = cJSON_Parse((char*)data.data);
    TransOnExchangeUdpInfo(authId, data.flag, data.seq, json);
    data.flag = 1;
    TransOnExchangeUdpInfo(authId, data.flag, data.seq, json);
    cJSON_Delete(json);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest013
 * @tc.desc: Trans udp Exchange UdpInfo reply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest013, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t authId = 1;
    int64_t invalidSeq = 0;
    string msgStr = "normal msgStr";
    cJSON *msg = cJSON_Parse(msgStr.c_str());
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    channel->info.myData.channelId = 1;
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransOnExchangeUdpInfoReply(authId, invalidSeq, msg);
    TransOnExchangeUdpInfoReply(authId, channel->seq, msg);
    cJSON_Delete(msg);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest014
 * @tc.desc: Trans udp Exchange UdpInfo requset.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest014, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t authId = 1;
    int64_t invalidSeq = 0;
    string msgStr = "normal msgStr";
    cJSON *msg = cJSON_Parse(msgStr.c_str());
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransOnExchangeUdpInfoRequest(authId, channel->seq, NULL);
    TransOnExchangeUdpInfoRequest(authId, invalidSeq, msg);
    TransOnExchangeUdpInfoRequest(authId, channel->seq, msg);
    cJSON_Delete(msg);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest015
 * @tc.desc: Trans start exchange udp info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest015, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t authId = 1;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    StartExchangeUdpInfo(channel, authId, channel->seq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest016
 * @tc.desc: Trans open udp auth connect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest016, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    uint32_t invalidId = 0;
    int64_t authId = 1;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    UdpOnAuthConnOpened(invalidId, authId);
    UdpOnAuthConnOpened(channel->requestId, authId);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest017
 * @tc.desc: Trans open udp auth connect failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest017, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    uint32_t invalidId = 0;
    int32_t reason = 1;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpOnAuthConnOpenFailed(invalidId, reason);
    UdpOnAuthConnOpenFailed(channel->requestId, reason);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest018
 * @tc.desc: Trans open udp auth connect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest018, TestSize.Level1)
{
    string peerUdid = "normal peerUid";
    uint32_t requestId = 1;
    bool isMeta = false;
    int32_t ret = UdpOpenAuthConn(peerUdid.c_str(), requestId, isMeta);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    isMeta = true;
    ret = UdpOpenAuthConn(peerUdid.c_str(), requestId, isMeta);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest019
 * @tc.desc: Trans open auth connect for udp negotiation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest019, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    string peerUid = "normal peerUid";
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = OpenAuthConnForUdpNegotiation(NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = OpenAuthConnForUdpNegotiation(channel);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_OPEN_AUTH_CHANNANEL_FAILED);
    channel->info.myData.channelId = 0;
    ret = OpenAuthConnForUdpNegotiation(channel);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_OPEN_AUTH_CHANNANEL_FAILED);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest020
 * @tc.desc: Trans prepare appInfo for udp open.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest020, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo invalidInfo;
    ConnectOption connOpt = {
        .type = CONNECT_P2P,
    };
    SocketOption opt;
    (void)memcpy_s(&opt.addr, MAX_ADDR_LENGTH, "normal addr", strlen("normal addr")+1);
    (void)memcpy_s(&connOpt.socketOption, sizeof(SocketOption),
        &opt, sizeof(SocketOption));
    int32_t ret = PrepareAppInfoForUdpOpen(&connOpt, &invalidInfo, &channelId);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_GET_P2P_INFO_FAILED);
}

/**
 * @tc.name: TransUdpNegoTest021
 * @tc.desc: Transmission udp Exchange UdpInfo requset.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest021, TestSize.Level1)
{
    LnnEventBasicInfo *empty = nullptr;
    LnnEventBasicInfo *info = (LnnEventBasicInfo*)SoftBusCalloc(sizeof(info));
    ASSERT_TRUE(info != nullptr);
    info->event = LNN_EVENT_WLAN_PARAM;
    TransUdpNodeOffLineProc(empty);
    TransUdpNodeOffLineProc(info);
    info->event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED;
    TransUdpNodeOffLineProc(info);
    SoftBusFree(info);
}

/**
 * @tc.name: TransUdpNegoTest022
 * @tc.desc: Trans notify udo channel opened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest022, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    bool isServerSide = true;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    isServerSide = false;
    (void)memcpy_s(&appInfo->myData.pkgName, PKG_NAME_SIZE_MAX,
        "com.invalid pkgName", strlen("com.invalid pkgName")+1);
    appInfo->myData.pid = 0;
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)memcpy_s(&appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.session sessionName", strlen("com.invalid sessionName")+1);
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)memcpy_s(&appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX,
        "com.invalid.deviceid", strlen("com.invalid.deviceid")+1);
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(appInfo);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest023
 * @tc.desc: Trans notify udo channel open failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest023, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int32_t errCode = 0;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    ret = NotifyUdpChannelOpenFailed(appInfo, errCode);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    (void)memcpy_s(&appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.session sessionName", strlen("com.invalid sessionName")+1);
    ret = NotifyUdpChannelOpenFailed(appInfo, errCode);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(appInfo);
    (void)TransDelUdpChannel(channel->info.myData.channelId);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest024
 * @tc.desc: Trans generate seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest024, TestSize.Level1)
{
    bool isServer = false;
    int64_t ret = GenerateSeq(isServer);
    EXPECT_TRUE(ret == ERROR_RET_TWO);
    isServer = true;
    ret = GenerateSeq(isServer);
    EXPECT_TRUE(ret == ERROR_RET_FIVE);
}

/**
 * @tc.name: TransUdpNegoTest025
 * @tc.desc: Trans accept udp channel as server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest025, TestSize.Level1)
{
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    int32_t ret = AcceptUdpChannelAsServer(appInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransUdpNegoTest026
 * @tc.desc: Trans accept udp channel as client.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest026, TestSize.Level1)
{
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    int32_t ret = AcceptUdpChannelAsClient(appInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransUdpNegoTest027
 * @tc.desc: Trans process udp channel state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest027, TestSize.Level1)
{
    bool isServerSide = true;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = ProcessUdpChannelState(appInfo, isServerSide);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    isServerSide = false;
    ret = ProcessUdpChannelState(appInfo, isServerSide);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = ProcessUdpChannelState(appInfo, isServerSide);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransUdpNegoTest28
 * @tc.desc: Trans set peer device id by auth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest28, TestSize.Level1)
{
    int64_t authId = 0;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    int32_t ret = SetPeerDeviceIdByAuth(authId, appInfo);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransUdpNegoTest29
 * @tc.desc: Trans parse request appInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest29, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    (void)TransUdpChannelInit(cb);
    int64_t authId = INVALID_AUTH_ID;
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    ASSERT_TRUE(msg != nullptr);

    int32_t ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = ParseRequestAppInfo(authId, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED);

    SessionServer *newNode = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    EXPECT_TRUE(newNode != nullptr);
    memset_s(newNode, sizeof(SessionServer), 0, sizeof(SessionServer));
    GenerateSessionServer(newNode);
    ret = TransSessionServerAddItem(newNode);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = ParseRequestAppInfo(authId, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    ret = ParseRequestAppInfo(authId, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    ret = ParseRequestAppInfo(authId, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = ParseRequestAppInfo(authId, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
    SoftBusFree(newNode);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest030
 * @tc.desc: Trans exchange udp info request.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest030, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    (void)TransUdpChannelInit(cb);
    int64_t authId = 1;
    int64_t seq = 1;
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    ASSERT_TRUE(msg != nullptr);
    int32_t ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransOnExchangeUdpInfoRequest(authId, seq, msg);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegoTest31
 * @tc.desc: Trans process abnormal udp channel state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest31, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    (void)TransUdpChannelInit(cb);
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t errCode = SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED;
    bool needClose = false;
    ProcessAbnormalUdpChannelState(appInfo, errCode, needClose);
    errCode = 0;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ProcessAbnormalUdpChannelState(appInfo, errCode, needClose);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegoTest32
 * @tc.desc: Trans get code type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest32, TestSize.Level1)
{
    bool flag = IsIShareSession(g_sessionName);
    EXPECT_TRUE(flag == SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    CodeType ret = getCodeType(appInfo);
    EXPECT_TRUE(ret == CODE_EXCHANGE_UDP_INFO);
}
}
