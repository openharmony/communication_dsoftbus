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

#include "gtest/gtest.h"
#include <securec.h>

#include "auth_common.h"
#include "bus_center_event.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_qos.h"
#include "trans_session_account_adapter.h"
#include "trans_session_manager.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.c"
#include "trans_udp_negotiation_exchange.c"

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
    int32_t ret = LnnInitBusCenterEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransUdpChannelInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TransUdpNegoTest::TearDownTestCase(void)
{
    AuthCommonDeinit();
    TransUdpChannelDeinit();
    LnnDeinitBusCenterEvent();
}

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
    (void)memcpy_s(Channel->info.groupId, GROUP_ID_SIZE_MAX, "123", sizeof("123"));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session", sizeof("com.test.trans.session"));
    (void)memcpy_s(Channel->info.peerNetWorkId, DEVICE_ID_SIZE_MAX,
        "1234567789", sizeof("1234567789"));
    (void)memcpy_s(Channel->info.peerData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session.sendfile", sizeof("com.test.trans.session.sendfile"));
    (void)memcpy_s(Channel->info.peerData.deviceId, DEVICE_ID_SIZE_MAX,
        "com.test.appinfo.deviceid", sizeof("com.test.appinfo.deviceid"));
    (void)memcpy_s(Channel->info.sessionKey, SESSION_KEY_LENGTH,
        "auth session key", sizeof("auth session key"));
    (void)memcpy_s(Channel->info.myData.pkgName, PKG_NAME_SIZE_MAX,
        "normal pakName", sizeof("normal pakName"));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", sizeof("normal sessionName"));
    return Channel;
}

static void GenerateAppInfo(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
        EXPECT_TRUE(appInfo != NULL);
        memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    }
    int32_t res = strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), g_sessionKey);
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
 * @tc.name: TransUnpackReplyErrInfo001
 * @tc.desc: TransUnpackReplyErrInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUnpackReplyErrInfo001, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    int32_t ret = TransUnpackReplyErrInfo(NULL, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    ret = TransUnpackReplyErrInfo(msg, &errCode);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransPackReplyErrInfo001
 * @tc.desc: TransPackReplyErrInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransPackReplyErrInfo001, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    const char* errDesc = "errDesc";

    int32_t ret = TransPackReplyErrInfo(NULL, errCode, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransPackReplyErrInfo(msg, errCode, errDesc);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(msg);
}

/**
 * @tc.name: SendUdpInfo001
 * @tc.desc: SendUdpInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, SendUdpInfo001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 0;
    string msg = "ProcessMessage";
    cJSON *replyMsg = cJSON_Parse((char *)msg.c_str());
    int32_t ret = SendUdpInfo(NULL, authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    authHandle.authId = 0;
    ret = SendUdpInfo(replyMsg, authHandle, 0);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_Delete(replyMsg);
}

/**
 * @tc.name: SendReplyErrInfo001
 * @tc.desc: SendReplyErrInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, SendReplyErrInfo001, TestSize.Level1)
{
    int32_t errCode = 0;
    string errDesc = "ProcessMessage";
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = SendReplyErrInfo(errCode, NULL, authHandle, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SendReplyErrInfo(errCode, (char *)errDesc.c_str(), authHandle, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: SendReplyUdpInfo001
 * @tc.desc: SendReplyUdpInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, SendReplyUdpInfo001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = INVALID_SEQ;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;

    int32_t ret = SendReplyUdpInfo(NULL, authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    authHandle.authId = 0;
    ret = SendReplyUdpInfo(&appInfo, authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: TransOnExchangeUdpInfoReply001
 * @tc.desc: TransOnExchangeUdpInfoReply, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransOnExchangeUdpInfoReply001, TestSize.Level1)
{
    char* data = TestGetMsgInfo();
    ASSERT_TRUE(data != nullptr);
    cJSON *msg = cJSON_Parse(data);
    //will free in TransOnExchangeUdpInfoReply line 298
    UdpChannelInfo *newChannel = CreateUdpChannelPackTest();
    ASSERT_TRUE(newChannel != nullptr);
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitQos();
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };

    TransOnExchangeUdpInfoReply(authHandle, INVALID_SEQ, msg);

    TransOnExchangeUdpInfoReply(authHandle, newChannel->seq, msg);

    //will free in TransOnExchangeUdpInfoReply line 305
    UdpChannelInfo *testChannel = CreateUdpChannelPackTest();
    ASSERT_TRUE(testChannel != nullptr);
    ret = TransAddUdpChannel(testChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransOnExchangeUdpInfoReply(authHandle, testChannel->seq, msg);

    cJSON_Delete(msg);
}

/**
 * @tc.name: TransOnExchangeUdpInfoReply002
 * @tc.desc: TransOnExchangeUdpInfoReply, Trans udp Exchange UdpInfo reply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransOnExchangeUdpInfoReply002, TestSize.Level1)
{
    int64_t invalidSeq = 0;
    string msgStr = "normal msgStr";
    cJSON *msg = cJSON_Parse(msgStr.c_str());
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    channel->info.myData.channelId = 1;
    int32_t ret = TransAddUdpChannel(channel);
    ASSERT_FALSE(ret == SOFTBUS_PUBLIC_ERR_BASE);

    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };

    TransOnExchangeUdpInfoReply(authHandle, invalidSeq, msg);

    TransOnExchangeUdpInfoReply(authHandle, channel->seq, msg);

    cJSON_Delete(msg);
}

/**
 * @tc.name: TransOnExchangeUdpInfoRequest001
 * @tc.desc: TransOnExchangeUdpInfoRequest, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransOnExchangeUdpInfoRequest001, TestSize.Level1)
{
    char* data = TestGetMsgInfo();
    ASSERT_TRUE(data != nullptr);
    cJSON *msg = cJSON_Parse(data);
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };

    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransOnExchangeUdpInfoRequest(authHandle, newChannel->seq, NULL);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransOnExchangeUdpInfoRequest002
 * @tc.desc: TransOnExchangeUdpInfoRequest, Trans udp Exchange UdpInfo requset.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransOnExchangeUdpInfoRequest002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t invalidSeq = 0;
    string msgStr = "normal msgStr";
    cJSON *msg = cJSON_Parse(msgStr.c_str());
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransOnExchangeUdpInfoRequest(authHandle, channel->seq, NULL);

    TransOnExchangeUdpInfoRequest(authHandle, invalidSeq, msg);

    TransOnExchangeUdpInfoRequest(authHandle, channel->seq, msg);

    cJSON_Delete(msg);
}

/**
 * @tc.name: StartExchangeUdpInfo001
 * @tc.desc: StartExchangeUdpInfo, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, StartExchangeUdpInfo001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 0;
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = StartExchangeUdpInfo(&channel, authHandle, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;

    (void)AuthCommonInit();
    ret = StartExchangeUdpInfo(&channel, authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: StartExchangeUdpInfo002
 * @tc.desc: StartExchangeUdpInfo, Trans start exchange udp info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, StartExchangeUdpInfo002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    StartExchangeUdpInfo(channel, authHandle, channel->seq);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: UdpModuleCb001
 * @tc.desc: UdpModuleCb, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, UdpModuleCb001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData data;
    int32_t ret = memset_s(&data, sizeof(AuthTransData), 0, sizeof(AuthTransData));
    EXPECT_EQ(ret, SOFTBUS_OK);
    UdpModuleCb(authHandle, NULL);

    data.data = NULL;
    UdpModuleCb(authHandle, &data);

    data.data = (const uint8_t *)"data";
    data.len = 0;
    UdpModuleCb(authHandle, &data);

    data.flag = 0;
    UdpModuleCb(authHandle, &data);
}

/**
 * @tc.name: UdpModuleCb002
 * @tc.desc: UdpModuleCb, Trans udp module callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, UdpModuleCb002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t val = 1;
    AuthTransData data1 = {0};
    int32_t ret = memset_s(&data1, sizeof(AuthTransData), 0, sizeof(AuthTransData));
    EXPECT_EQ(ret, SOFTBUS_OK);
    UdpModuleCb(authHandle, &data1);

    AuthTransData data2 = {
        .data = nullptr,
    };
    UdpModuleCb(authHandle, &data2);

    AuthTransData data3 = {
        .data = &val,
    };
    data3.len = 0;
    UdpModuleCb(authHandle, &data3);

    data3.len = 1;
    data3.flag = true;
    UdpModuleCb(authHandle, &data3);
}

/**
 * @tc.name: TransOnExchangeUdpInfo001
 * @tc.desc: TransOnExchangeUdpInfo, Trans dup exchange info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransOnExchangeUdpInfo001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t val = 1;
    AuthTransData data = {
        .data = &val,
    };

    cJSON *json = cJSON_CreateObject();
    EXPECT_NE(json, nullptr);
    TransOnExchangeUdpInfo(authHandle, data.flag, data.seq, json);

    data.flag = 1;
    TransOnExchangeUdpInfo(authHandle, data.flag, data.seq, json);

    cJSON_Delete(json);
}

/**
 * @tc.name: UdpOnAuthConnOpened001
 * @tc.desc: UdpOnAuthConnOpened, Trans open udp auth connect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, UdpOnAuthConnOpened001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    uint32_t invalidId = 0;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    UdpOnAuthConnOpened(invalidId, authHandle);

    UdpOnAuthConnOpened(channel->requestId, authHandle);
}

/**
 * @tc.name: UdpOnAuthConnOpenFailed001
 * @tc.desc: UdpOnAuthConnOpenFailed, Trans open udp auth connect failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, UdpOnAuthConnOpenFailed001, TestSize.Level1)
{
    uint32_t invalidId = 0;
    int32_t reason = 1;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    UdpOnAuthConnOpenFailed(invalidId, reason);

    UdpOnAuthConnOpenFailed(channel->requestId, reason);
}

/**
 * @tc.name: UdpOpenAuthConn001
 * @tc.desc: UdpOpenAuthConn, Trans open udp auth connect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, UdpOpenAuthConn001, TestSize.Level1)
{
    string peerUdid = "normal peerUid";
    uint32_t requestId = 1;
    bool isMeta = false;
    int32_t ret = UdpOpenAuthConn(peerUdid.c_str(), requestId, isMeta, 0);
    EXPECT_NE(ret, SOFTBUS_OK);

    isMeta = true;
    ret = UdpOpenAuthConn(peerUdid.c_str(), requestId, isMeta, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: OpenAuthConnForUdpNegotiation001
 * @tc.desc: OpenAuthConnForUdpNegotiation, Trans open auth connect for udp negotiation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, OpenAuthConnForUdpNegotiation001, TestSize.Level1)
{
    string peerUid = "normal peerUid";
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenAuthConnForUdpNegotiation(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OpenAuthConnForUdpNegotiation(channel);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CHANNEL_FAILED);

    channel->info.myData.channelId = 0;
    ret = OpenAuthConnForUdpNegotiation(channel);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: PrepareAppInfoForUdpOpen001
 * @tc.desc: PrepareAppInfoForUdpOpen, Trans prepare appInfo for udp open.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, PrepareAppInfoForUdpOpen001, TestSize.Level1)
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
    EXPECT_EQ(ret, SOFTBUS_OK);

    connOpt.type = CONNECT_HML;
    ret = PrepareAppInfoForUdpOpen(&connOpt, &invalidInfo, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNodeOffLineProc001
 * @tc.desc: TransUdpNodeOffLineProc, Transmission udp Exchange UdpInfo requset.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNodeOffLineProc001, TestSize.Level1)
{
    LnnEventBasicInfo *empty = nullptr;
    LnnEventBasicInfo *info = (LnnEventBasicInfo*)SoftBusCalloc(sizeof(LnnEventBasicInfo));
    ASSERT_TRUE(info != nullptr);
    info->event = LNN_EVENT_WLAN_PARAM;
    TransUdpNodeOffLineProc(empty);

    TransUdpNodeOffLineProc(info);

    int32_t ret = TransUdpChannelMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    LnnEventBasicInfo tmpLnnEventBasicInfo = {
    .event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED,
    };
    TransUdpNodeOffLineProc(&tmpLnnEventBasicInfo);

    SoftBusFree(info);
}

/**
 * @tc.name: NotifyUdpChannelOpened001
 * @tc.desc: NotifyUdpChannelOpened, Trans notify udo channel opened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, NotifyUdpChannelOpened001, TestSize.Level1)
{
    bool isServerSide = true;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    isServerSide = false;
    (void)memcpy_s(&appInfo->myData.pkgName, PKG_NAME_SIZE_MAX,
        "com.invalid pkgName", sizeof("com.invalid pkgName"));
    appInfo->myData.pid = 0;
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    (void)memcpy_s(&appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.session sessionName", sizeof("com.invalid sessionName"));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    (void)memcpy_s(&appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX,
        "com.invalid.deviceid", sizeof("com.invalid.deviceid"));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: NotifyUdpChannelOpenFailed001
 * @tc.desc: NotifyUdpChannelOpenFailed, Trans notify udp channel open failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, NotifyUdpChannelOpenFailed001, TestSize.Level1)
{
    int32_t errCode = 0;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = TransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    ret = NotifyUdpChannelOpenFailed(appInfo, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)memcpy_s(&appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.session sessionName", sizeof("com.invalid sessionName"));
    ret = NotifyUdpChannelOpenFailed(appInfo, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: GenerateSeq001
 * @tc.desc: GenerateSeq, Trans generate seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, GenerateSeq001, TestSize.Level1)
{
    bool isServer = false;
    int64_t ret = GenerateSeq(isServer);
    EXPECT_EQ(ret, ERROR_RET_TWO);

    isServer = true;
    ret = GenerateSeq(isServer);
    EXPECT_EQ(ret, ERROR_RET_FIVE);
}

/**
 * @tc.name: AcceptUdpChannelAsServer001
 * @tc.desc: AcceptUdpChannelAsServer, Trans accept udp channel as server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, AcceptUdpChannelAsServer001, TestSize.Level1)
{
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));

    AuthHandle *authHandle = (AuthHandle *)SoftBusCalloc(sizeof(AuthHandle));
    ASSERT_TRUE(authHandle != nullptr);
    int64_t seq = 1;

    int32_t ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(appInfo);
    SoftBusFree(channel);
    SoftBusFree(authHandle);
}

/**
 * @tc.name: AcceptUdpChannelAsClient001
 * @tc.desc: AcceptUdpChannelAsClient, Trans accept udp channel as client.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, AcceptUdpChannelAsClient001, TestSize.Level1)
{
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));

    int32_t ret = AcceptUdpChannelAsClient(appInfo);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: ProcessUdpChannelState001
 * @tc.desc: ProcessUdpChannelState, Trans process udp channel state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, ProcessUdpChannelState001, TestSize.Level1)
{
    bool isServerSide = true;
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    int32_t ret = ProcessUdpChannelState(appInfo, isServerSide, &authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_OK);

    isServerSide = false;
    ret = ProcessUdpChannelState(appInfo, isServerSide, &authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = ProcessUdpChannelState(appInfo, isServerSide, &authHandle, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);

    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: SetPeerDeviceIdByAuth001
 * @tc.desc: SetPeerDeviceIdByAuth, Trans set peer device id by auth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, SetPeerDeviceIdByAuth001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    UdpChannelInfo *channel = CreateUdpChannelPackTest();
    ASSERT_TRUE(channel != nullptr);
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &channel->info, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;

    int32_t ret = SetPeerDeviceIdByAuth(authHandle, appInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    SoftBusFree(appInfo);
    SoftBusFree(channel);
}

/**
 * @tc.name: ParseRequestAppInfo001
 * @tc.desc: ParseRequestAppInfo, Trans parse request appInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, ParseRequestAppInfo001, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthHandle authHandle = { .authId = INVALID_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    ASSERT_TRUE(msg != nullptr);

    ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = ParseRequestAppInfo(authHandle, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED);

    SessionServer *newNode = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    ASSERT_TRUE(newNode != nullptr);
    memset_s(newNode, sizeof(SessionServer), 0, sizeof(SessionServer));
    GenerateSessionServer(newNode);
    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = ParseRequestAppInfo(authHandle, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PEER_PROC_ERR);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    ret = ParseRequestAppInfo(authHandle, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PEER_PROC_ERR);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    ret = ParseRequestAppInfo(authHandle, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PEER_PROC_ERR);

    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    (void)TransSessionMgrInit();
    ret = ParseRequestAppInfo(authHandle, msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PEER_PROC_ERR);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
    SoftBusFree(newNode);
}

/**
 * @tc.name: TransPackRequestUdpInfo001
 * @tc.desc: TransPackRequestUdpInfo, Trans exchange udp info request.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransPackRequestUdpInfo001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    string msgStr = "normal msgStr";
    cJSON *msg = cJSON_Parse(msgStr.c_str());
    int32_t ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TransOnExchangeUdpInfoRequest(authHandle, seq, msg);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: ProcessAbnormalUdpChannelState001
 * @tc.desc: ProcessAbnormalUdpChannelState, Trans process abnormal udp channel state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, ProcessAbnormalUdpChannelState001, TestSize.Level1)
{
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
 * @tc.name: getCodeType001
 * @tc.desc: getCodeType, Trans get code type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, getCodeType001, TestSize.Level1)
{
    const char *dstSessionName = "testSessionName";
    bool flag = CompareSessionName(dstSessionName, g_sessionName);
    EXPECT_EQ(flag, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);

    CodeType ret = getCodeType(appInfo);
    EXPECT_EQ(ret, CODE_EXCHANGE_UDP_INFO);
}
} // namespace OHOS
