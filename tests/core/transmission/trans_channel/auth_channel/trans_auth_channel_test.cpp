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

#include "gtest/gtest.h"

#include "auth_channel_mock.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "disc_event_manager.h"
#include "message_handler.h"
#include "session_set_timer.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "trans_auth_manager.c"
#include "trans_session_service.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_AUTH_ID 1000
#define TRANS_TEST_INVALID_AUTH_ID (-1)
#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define TRANS_TEST_CHANNEL_ID 1000

const char *g_pkgName = "dms";
const char *g_sessionKey = "www.huaweitest.com";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_authSessionName = "com.huawei.devicegroupmanage";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
const char *g_errMsg = "error";
static IServerChannelCallBack *callback = nullptr;
class TransAuthChannelTest : public testing::Test {
public:
    TransAuthChannelTest()
    {}
    ~TransAuthChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthChannelTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
    callback = TransServerGetChannelCb();
}

void TransAuthChannelTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
}

static int32_t TestGenerateAppInfo(AppInfo *appInfo)
{
    if (appInfo == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), g_sessionKey) != EOK ||
        strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), TEST_CONN_IP) != EOK ||
        strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), TEST_CONN_IP) != EOK ||
        strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName) != EOK ||
        strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), g_sessionName) != EOK ||
        strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName) != EOK ||
        strcpy_s(appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName), g_pkgName) != EOK ||
        strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), g_groupid) != EOK ||
        strcpy_s(appInfo->myData.deviceId, sizeof(appInfo->myData.deviceId), g_deviceId) != EOK) {
        return SOFTBUS_MEM_ERR;
    }

    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = TRANS_TEST_CHANNEL_ID;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->myData.pid = TRANS_TEST_PID;
    appInfo->myData.uid = TRANS_TEST_UID;

    return SOFTBUS_OK;
}

static void BuildConnectOption(ConnectOption *connInfo)
{
    connInfo->type = CONNECT_TCP;
    (void)memset_s(
        &(connInfo->socketOption.addr), sizeof(connInfo->socketOption.addr), 0, sizeof(connInfo->socketOption.addr));
    connInfo->socketOption.port = TEST_AUTH_PORT;
    connInfo->socketOption.moduleId = MODULE_MESSAGE_SERVICE;
    connInfo->socketOption.protocol = LNN_PROTOCOL_IP;
}

static int32_t InitAndCreateSessionServer()
{
    int32_t ret = TransSessionMgrInit();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = TransAuthInit(callback);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return ret;
}

/**
 * @tc.name: OperateAuthChannelInfoTest001
 * @tc.desc: Transmission auth manager get channel info with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OperateAuthChannelInfoTest001, TestSize.Level1)
{
    int32_t ret = GetAuthChannelInfoByChanId(TRANS_TEST_CHANNEL_ID, NULL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    ret = GetAuthIdByChannelId(TRANS_TEST_CHANNEL_ID);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret =  GetChannelInfoByAuthId(TRANS_TEST_AUTH_ID, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetAppInfoTest001
 * @tc.desc: Transmission auth manager get AppInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, GetAppInfoTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    ret = GetAppInfo(NULL, TRANS_TEST_CHANNEL_ID, appInfo, isClient);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = GetAppInfo(g_sessionName, TRANS_TEST_CHANNEL_ID, appInfo, isClient);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, g_deviceId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetAppInfo(g_sessionName, TRANS_TEST_CHANNEL_ID, appInfo, isClient);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthInitTest001
 * @tc.desc: TransAuthInitTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthInitTest001, TestSize.Level1)
{
    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);

    int32_t ret = TransAuthInit(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransAuthDeinit();
}

/**
 * @tc.name: TransOpenAuthMsgChannelTest001
 * @tc.desc: TransOpenAuthMsgChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    ConnectOption connInfo;
    BuildConnectOption(&connInfo);
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_CONN_IP) != EOK) {
        return;
    }

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);
    int32_t ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, NULL, &channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, NULL, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    connInfo.type = CONNECT_BR;
    ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, &channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransAuthDeinit();
}

/**
 * @tc.name: TransOpenAuthMsgChannelTest002
 * @tc.desc: TransOpenAuthMsgChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest002, TestSize.Level1)
{
    int32_t channelId = 0;
    ConnectOption connInfo;
    BuildConnectOption(&connInfo);
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_CONN_IP) != EOK) {
        return;
    }

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);
    int32_t ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, &channelId, NULL);
    if (ret != SOFTBUS_OK) {
        printf("test open auth msg channel failed.\n");
    }

    const char *data = TEST_AUTH_DATA;
    ret = TransSendAuthMsg(channelId, data, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND);
    TransAuthDeinit();
}

/**
 * @tc.name: TransSendAuthMsgTest001
 * @tc.desc: TransSendAuthMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransSendAuthMsgTest001, TestSize.Level1)
{
    const char *data = "test auth message data";
    const char *sessionName = "com.test.trans.auth.demo";
    int32_t len = strlen(data);
    int32_t channelId = 0;

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);
    bool isClient = true;
    AuthChannelInfo *channel = CreateAuthChannelInfo(sessionName, isClient);
    if (channel == nullptr) {
        return;
    }
    channel->authId = 1;
    if (AddAuthChannelInfo(channel) != SOFTBUS_OK) {
        SoftBusFree(channel);
        return;
    }
    channelId = channel->appInfo.myData.channelId;
    int32_t ret = TransSendAuthMsg(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSendAuthMsg(channelId, data, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSendAuthMsg(-1, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND);

    ret = TransSendAuthMsg(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    (void)TransCloseAuthChannel(channelId);
    TransAuthDeinit();
}

/**
 * @tc.name: OnAuthChannelDataRecvTest001
 * @tc.desc: OnAuthChannelDataRecvTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnAuthChannelDataRecvTest001, TestSize.Level1)
{
    int32_t authId = TRANS_TEST_AUTH_ID;
    AuthChannelData *data = (AuthChannelData*)SoftBusCalloc(sizeof(AuthChannelData));
    ASSERT_TRUE(data != nullptr);

    OnAuthChannelDataRecv(authId, NULL);

    data->data = NULL;
    OnAuthChannelDataRecv(authId, data);

    data->data = (uint8_t *)TEST_AUTH_DATA;
    data->len = strlen(TEST_AUTH_DATA) + 1;
    data->flag = AUTH_CHANNEL_REQ;
    OnAuthChannelDataRecv(authId, data);

    data->flag = AUTH_CHANNEL_REPLY;
    OnAuthChannelDataRecv(authId, data);

    data->flag = -1;
    OnAuthChannelDataRecv(authId, data);
}

/**
 * @tc.name: OnAuthMsgDataRecvTest001
 * @tc.desc: OnAuthMsgDataRecvTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnAuthMsgDataRecvTest001, TestSize.Level1)
{
    int32_t authId = -1;
    AuthChannelData data;
    IServerChannelCallBack cb;
    int32_t ret = TransAuthInit(&cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnAuthMsgDataRecv(authId, NULL);

    data.data = NULL;
    OnAuthMsgDataRecv(authId, &data);

    data.data = (uint8_t *)"test data";
    OnAuthMsgDataRecv(authId, &data);
    TransAuthDeinit();
}

/**
 * @tc.name: TransPostAuthChannelMsgTest001
 * @tc.desc: TransPostAuthChannelMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransPostAuthChannelMsgTest001, TestSize.Level1)
{
    int32_t authId = -1;
    AppInfo appInfo;
    int32_t flag = 1;

    int32_t ret = TransPostAuthChannelMsg(NULL, authId, flag);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransPostAuthChannelMsg(&appInfo, authId, flag);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransPostAuthChannelErrMsgTest001
 * @tc.desc: TransPostAuthChannelErrMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransPostAuthChannelErrMsgTest001, TestSize.Level1)
{
    int32_t authId = -1;
    int32_t errcode = 0;
    const char *errMsg = "test error msg.";
    IServerChannelCallBack cb;
    int32_t ret = TransAuthInit(&cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransPostAuthChannelErrMsg(authId, errcode, NULL);
    TransPostAuthChannelErrMsg(authId, errcode, errMsg);
    TransAuthDeinit();
}

/**
 * @tc.name: OperateAuthChannelInfoTest002
 * @tc.desc: Transmission auth manager add channel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OperateAuthChannelInfoTest002, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddAuthChannelInfo(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    info->authId = TRANS_TEST_AUTH_ID;
    EXPECT_TRUE(info != nullptr);
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *newInfo = (AuthChannelInfo *)SoftBusCalloc(sizeof(AuthChannelInfo));
    ASSERT_TRUE(newInfo != nullptr);
    int32_t channelId = info->appInfo.myData.channelId;
    newInfo->authId = TRANS_TEST_AUTH_ID;
    ret = GetAuthChannelInfoByChanId(channelId, newInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddAuthChannelInfo(info);
    EXPECT_NE(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(newInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: OperateAuthChannelInfoTest003
 * @tc.desc: Transmission auth manager delete channel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OperateAuthChannelInfoTest003, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_INVALID_UID, TRANS_TEST_INVALID_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = info->appInfo.myData.channelId;
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_EQ(ret,  TRANS_TEST_AUTH_ID);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: OperateAuthChannelInfoTest004
 * @tc.desc: Transmission auth manager delete channel info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OperateAuthChannelInfoTest004, TestSize.Level1)
{
    int32_t authId = TRANS_TEST_SESSION_ID;
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_SESSION_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *newInfo = (AuthChannelInfo *)SoftBusCalloc(sizeof(AuthChannelInfo));
    ASSERT_TRUE(newInfo != nullptr);
    ret = GetChannelInfoByAuthId(TRANS_TEST_SESSION_ID, newInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(authId);
    ret = GetChannelInfoByAuthId(TRANS_TEST_SESSION_ID, newInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(newInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}
/**
 * @tc.name: NotifyOpenAuthChannelSuccessTest001
 * @tc.desc: Transmission auth manager notify open auth channel success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, NotifyOpenAuthChannelSuccessTest001, TestSize.Level1)
{
    bool isServer = true;
    int32_t ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = NotifyOpenAuthChannelSuccess(appInfo, isServer);
    EXPECT_NE(ret, SOFTBUS_OK);
    TransAuthDeinit();
}

/**
 * @tc.name: NotifyOpenAuthChannelFailedTest001
 * @tc.desc: Transmission auth manager notify open auth channel success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, NotifyOpenAuthChannelFailedTest001, TestSize.Level1)
{
    int32_t ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = NotifyOpenAuthChannelFailed(g_pkgName, TRANS_TEST_PID, TRANS_TEST_CHANNEL_ID, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransAuthDeinit();
}

/**
 * @tc.name: NotifyCloseAuthChannelTest001
 * @tc.desc: Transmission auth manager notify close auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, NotifyCloseAuthChannelTest001, TestSize.Level1)
{
    int32_t ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = NotifyCloseAuthChannel(g_pkgName, TRANS_TEST_PID, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_IPC_ERR);
    TransAuthDeinit();
}

/**
 * @tc.name: AuthGetUidAndPidBySessionNameTest001
 * @tc.desc: Transmission auth manager notify close auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, AuthGetUidAndPidBySessionNameTest001, TestSize.Level1)
{
    int32_t uid = 0;
    int32_t pid = 0;
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(uid, TRANS_TEST_UID);
    EXPECT_EQ(pid, TRANS_TEST_PID);
    TransAuthDeinit();
    TransSessionMgrDeinit();
}

/**
 * @tc.name: NotifyOnDataReceivedTest001
 * @tc.desc: Transmission auth manager notify on data received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, NotifyOnDataReceivedTest001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = NotifyOnDataReceived(TRANS_TEST_AUTH_ID, TEST_AUTH_DATA, strlen(TEST_AUTH_DATA));
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: CopyPeerAppInfoTest001
 * @tc.desc: Transmission auth manager copy peer app info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, CopyPeerAppInfoTest001, TestSize.Level1)
{
    AppInfo *recvAppInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(recvAppInfo != nullptr);
    int32_t ret = TestGenerateAppInfo(recvAppInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *channelAppInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(channelAppInfo != nullptr);
    ret = CopyPeerAppInfo(recvAppInfo, channelAppInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(recvAppInfo);
    SoftBusFree(channelAppInfo);
}

/**
 * @tc.name: OnRequsetUpdateAuthChannelTest001
 * @tc.desc: Transmission auth manager request update auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRequsetUpdateAuthChannelTest001, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *testinfo = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(testinfo != nullptr);
    testinfo->authId = TRANS_TEST_AUTH_ID + TRANS_TEST_SESSION_ID;
    ret = AddAuthChannelInfo(testinfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OnRequsetUpdateAuthChannel(TRANS_TEST_AUTH_ID, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_SERVER_NAME_REPEATED);
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OnRequsetUpdateAuthChannel(TRANS_TEST_AUTH_ID, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    AuthChannelInfo *newinfo = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(newinfo != nullptr);
    newinfo->authId = TRANS_TEST_AUTH_ID + 1;
    newinfo->appInfo.myData.channelId++;
    ret = AddAuthChannelInfo(newinfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OnRequsetUpdateAuthChannel(TRANS_TEST_AUTH_ID, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID + 1);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: OnRequsetUpdateAuthChannelTest002
 * @tc.desc: Transmission auth manager request update auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRequsetUpdateAuthChannelTest002, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *testinfo = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(testinfo != nullptr);
    testinfo->authId = TRANS_TEST_AUTH_ID + 1;
    ret = AddAuthChannelInfo(testinfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OnRequsetUpdateAuthChannel(TRANS_TEST_AUTH_ID, appInfo);
    EXPECT_NE(ret, SOFTBUS_TRANS_INVALID_CHANNEL_ID);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_SERVER_NAME_REPEATED);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: OnRecvAuthChannelRequestTest001
 * @tc.desc: Transmission auth manager request update auth channel with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRecvAuthChannelRequestTest001, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthChannelMsgPack(msg, appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *data = cJSON_PrintUnformatted(msg);
    ASSERT_TRUE(data != nullptr);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, NULL, strlen(data));
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, 0);
    SoftBusFree(appInfo);
    cJSON_free(data);
    cJSON_Delete(msg);
}

/**
 * @tc.name: OnRecvAuthChannelRequestTest002
 * @tc.desc: Transmission auth manager request update auth channel no initialization.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRecvAuthChannelRequestTest002, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char cJsonStr[ERR_MSG_MAX_LEN] = {0};
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, NULL, ERR_MSG_MAX_LEN);
    ret = TransAuthChannelErrorPack(SOFTBUS_INVALID_PARAM, g_errMsg, cJsonStr, ERR_MSG_MAX_LEN);
    ASSERT_EQ(ret, SOFTBUS_OK);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, cJsonStr, strlen(cJsonStr));
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    ret = TransAuthChannelMsgPack(msg, appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *data = cJSON_PrintUnformatted(msg);
    ASSERT_TRUE(data != nullptr);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, strlen(data));
    bool res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_authSessionName);
    ASSERT_EQ(res, EOK);
    cJSON_Delete(msg);
    cJSON_free(data);
    msg = cJSON_CreateObject();
    ret = TransAuthChannelMsgPack(msg, appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    data = cJSON_PrintUnformatted(msg);
    ASSERT_TRUE(data != nullptr);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, strlen(data));
    SoftBusFree(appInfo);
    cJSON_free(data);
    cJSON_Delete(msg);
}

/**
 * @tc.name: OnRecvAuthChannelRequestTest003
 * @tc.desc: Transmission auth manager request update auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRecvAuthChannelRequestTest003, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_authSessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    cJSON *msg = cJSON_CreateObject();
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_authSessionName);
    ASSERT_EQ(ret, EOK);
    ret = TransAuthChannelMsgPack(msg, appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *data = cJSON_PrintUnformatted(msg);
    ASSERT_TRUE(data != nullptr);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, strlen(data));
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_authSessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID + 1;
    info->appInfo.myData.channelId++;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = info->appInfo.myData.channelId;
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, strlen(data));
    DelAuthChannelInfoByChanId(channelId);
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, data, strlen(data));
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    cJSON_free(data);
    cJSON_Delete(msg);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: OnDisconnectTest001
 * @tc.desc: Transmission auth manager on disconnect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnDisconnectTest001, TestSize.Level1)
{
    OnDisconnect(TRANS_TEST_AUTH_ID);
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_authSessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_authSessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    OnDisconnect(TRANS_TEST_AUTH_ID);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthGetNameByChanIdTest001
 * @tc.desc: Transmission auth manager on disconnect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetNameByChanIdTest001, TestSize.Level1)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, NULL, sessionName,
                                           PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, NULL,
                                   PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, sessionName,
                                   PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->appInfo.myData.channelId = TRANS_TEST_CHANNEL_ID;
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthGetNameByChanId(TRANS_TEST_CHANNEL_ID, pkgName, sessionName,
                                   PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransPostAuthChannelMsgTest002
 * @tc.desc: Transmission auth manager post auth channel message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransPostAuthChannelMsgTest002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret =TransPostAuthChannelMsg(appInfo, TRANS_TEST_AUTH_ID, AUTH_CHANNEL_REQ);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransSendAuthMsgTest002
 * @tc.desc: Transmission auth manager post auth channel message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransSendAuthMsgTest002, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->appInfo.myData.channelId = TRANS_TEST_CHANNEL_ID;
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransSendAuthMsg(TRANS_TEST_CHANNEL_ID, NULL, strlen(TEST_AUTH_DATA));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransSendAuthMsg(TRANS_TEST_CHANNEL_ID, TEST_AUTH_DATA, strlen(TEST_AUTH_DATA));
    EXPECT_NE(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthGetConnOptionByChanIdTest002
 * @tc.desc: Transmission auth manager get option of connetion by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetConnOptionByChanIdTest002, TestSize.Level1)
{
    int32_t ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != nullptr);
    ret = TransAuthGetConnOptionByChanId(TRANS_TEST_CHANNEL_ID, connOpt);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->appInfo.myData.channelId = TRANS_TEST_CHANNEL_ID;
    info->authId = TRANS_TEST_AUTH_ID;
    info->isClient = false;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthGetConnOptionByChanId(TRANS_TEST_CHANNEL_ID, connOpt);
    EXPECT_NE(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->appInfo.myData.channelId = TRANS_TEST_CHANNEL_ID;
    info->authId = TRANS_TEST_AUTH_ID;
    info->isClient = true;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthGetConnOptionByChanId(TRANS_TEST_CHANNEL_ID, connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(connOpt);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthGetAppInfoByChanIdTest001
 * @tc.desc: Transmission auth manager get appInfo by channel id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetAppInfoByChanIdTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TransAuthGetAppInfoByChanId(TRANS_TEST_CHANNEL_ID, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransAuthGetAppInfoByChanIdTest002
 * @tc.desc: Transmission auth manager get appInfo by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetAppInfoByChanIdTest002, TestSize.Level1)
{
    int32_t ret = TransAuthGetAppInfoByChanId(TRANS_TEST_CHANNEL_ID, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->appInfo.myData.channelId = TRANS_TEST_CHANNEL_ID;
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TransAuthGetAppInfoByChanId(TRANS_TEST_CHANNEL_ID, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransNotifyAuthDataSuccessTest001
 * @tc.desc: Transmission auth manager get appInfo by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransNotifyAuthDataSuccessTest001, TestSize.Level1)
{
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != nullptr);
    int32_t ret = TransNotifyAuthDataSuccess(TRANS_TEST_CHANNEL_ID, NULL);
    EXPECT_NE(ret, SOFTBUS_OK);
    connOpt->type = CONNECT_TYPE_MAX;
    ret = TransNotifyAuthDataSuccess(TRANS_TEST_CHANNEL_ID, connOpt);
    EXPECT_NE(ret, SOFTBUS_OK);
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->type = CONNECT_TCP;
    ret = strncpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), TEST_CONN_IP, strlen(TEST_CONN_IP));
    ASSERT_EQ(ret, EOK);
    ret = TransNotifyAuthDataSuccess(TRANS_TEST_CHANNEL_ID, connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(connOpt);
}

/**
 * @tc.name: UpdateChannelInfo001
 * @tc.desc: Transmission auth manager update channel info with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, UpdateChannelInfo001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, true);
    ASSERT_TRUE(info != nullptr);
    
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = UpdateChannelInfo(TRANS_TEST_AUTH_ID, info);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = UpdateChannelInfo(-1, info);
    ASSERT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthGetPeerUdidByChanId001
 * @tc.desc: Transmission auth manager trans auth get peerudid by chanid with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetPeerUdidByChanId001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, true);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);

    int32_t channelId = info->appInfo.myData.channelId;
    char peerUdid[DEVICE_ID_SIZE_MAX] = {0};
    ret = TransAuthGetPeerUdidByChanId(channelId, peerUdid, DEVICE_ID_SIZE_MAX);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAuthGetPeerUdidByChanId(-1, peerUdid, DEVICE_ID_SIZE_MAX);
    ASSERT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: LnnServerJoinExtCb001
 * @tc.desc: Transmission auth manager lnn server joinext callback with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, LnnServerJoinExtCb001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, true);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ConnectionAddr connAddr;
    (void)memcpy_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    connAddr.type = CONNECTION_ADDR_SESSION;
    connAddr.info.session.channelId = info->appInfo.myData.channelId;
    LnnSvrJoinCallback(&connAddr, SOFTBUS_OK);
    LnnSvrJoinCallback(&connAddr, SOFTBUS_MALLOC_ERR);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: AdaptLnnServerJoinExt001
 * @tc.desc: Transmission auth manager adapt lnn server joinext with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, AdaptLnnServerJoinExt001, TestSize.Level1)
{
    AuthChannelInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnServerJoinExt).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = AdaptLnnServerJoinExt(TRANS_TEST_CHANNEL_ID);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: OnRecvAuthChannelReply001
 * @tc.desc: Transmission auth manager on receive auth channel reply with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnRecvAuthChannelReply001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    OnRecvAuthChannelReply(TRANS_TEST_AUTH_ID, NULL, DEVICE_ID_SIZE_MAX);
    cJSON *msg = cJSON_CreateObject();
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ret = TestGenerateAppInfo(appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char cJsonStr[ERR_MSG_MAX_LEN] = {0};
    OnRecvAuthChannelRequest(TRANS_TEST_AUTH_ID, NULL, ERR_MSG_MAX_LEN);
    ret = TransAuthChannelErrorPack(SOFTBUS_INVALID_PARAM, g_errMsg, cJsonStr, ERR_MSG_MAX_LEN);
    ASSERT_EQ(ret, SOFTBUS_OK);
    OnRecvAuthChannelReply(TRANS_TEST_AUTH_ID, cJsonStr, strlen(cJsonStr));
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    OnRecvAuthChannelReply(TRANS_TEST_AUTH_ID, cJsonStr, strlen(cJsonStr));
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    OnRecvAuthChannelReply(TRANS_TEST_AUTH_ID, cJsonStr, strlen(cJsonStr));
    ret = TransAuthChannelMsgPack(msg, appInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    char *data = cJSON_PrintUnformatted(msg);
    ASSERT_TRUE(data != nullptr);
    OnRecvAuthChannelReply(TRANS_TEST_AUTH_ID, data, strlen(data));
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    SoftBusFree(appInfo);
    cJSON_free(data);
    cJSON_Delete(msg);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransCloseAuthChannel001
 * @tc.desc: Transmission auth manager close auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransCloseAuthChannel001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = info->appInfo.myData.channelId;
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_EQ(ret,  TRANS_TEST_AUTH_ID);
    ret = TransCloseAuthChannel(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthGetChannelInfo001
 * @tc.desc: Transmission auth manager get different info by different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthGetChannelInfo001, TestSize.Level1)
{
    int32_t ret = InitAndCreateSessionServer();
    ASSERT_EQ(ret, SOFTBUS_OK);
    bool isClient = true;
    AuthChannelInfo *info = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(info != nullptr);
    int32_t channelId = info->appInfo.myData.channelId;
    info->authId = TRANS_TEST_AUTH_ID;
    ret = AddAuthChannelInfo(info);
    ASSERT_EQ(ret, SOFTBUS_OK);

    AuthChannelInfo *newInfo = CreateAuthChannelInfo(g_sessionName, isClient);
    ASSERT_TRUE(newInfo != nullptr);
    int32_t newChannelId = newInfo->appInfo.myData.channelId;
    newInfo->authId = TRANS_TEST_AUTH_ID + 1;
    ret = AddAuthChannelInfo(newInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = GetAuthIdByChannelId(channelId);
    EXPECT_EQ(ret,  TRANS_TEST_AUTH_ID);
    ret = GetAuthIdByChannelId(newChannelId);
    EXPECT_EQ(ret,  TRANS_TEST_AUTH_ID + 1);
    AuthChannelInfo *destInfo = (AuthChannelInfo *)SoftBusCalloc(sizeof(AuthChannelInfo));
    ASSERT_TRUE(destInfo != nullptr);
    ret = GetChannelInfoByAuthId(TRANS_TEST_AUTH_ID, destInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = memcmp(info, destInfo,  sizeof(AuthChannelInfo));
    EXPECT_EQ(ret, EOK);
    memset_s(destInfo, sizeof(AuthChannelInfo), 0, sizeof(AuthChannelInfo));
    ret = GetChannelInfoByAuthId(TRANS_TEST_AUTH_ID + 1, destInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memcmp(newInfo, destInfo,  sizeof(AuthChannelInfo));

    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID);
    ret = GetAuthIdByChannelId(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    DelAuthChannelInfoByAuthId(TRANS_TEST_AUTH_ID + 1);
    ret = GetAuthIdByChannelId(newChannelId);
    EXPECT_NE(ret, SOFTBUS_OK);

    SoftBusFree(destInfo);
    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransOpenAuthMsgChannelTest003
 * @tc.desc: Transmission auth manager open auth message channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest003, TestSize.Level1)
{
    int32_t channelId = 0;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = TEST_AUTH_PORT,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    int32_t ret = strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_CONN_IP);
    ASSERT_EQ(ret, EOK);

    ret = TransSessionMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAuthInit(callback);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransCreateSessionServer(g_pkgName, g_sessionName, TRANS_TEST_UID, TRANS_TEST_PID);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransOpenAuthMsgChannel(g_sessionName, &connInfo, &channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TransSessionMgrDeinit();
    TransAuthDeinit();
}

/**
 * @tc.name: TransAuthFillDataConfigTest001
 * @tc.desc: TransAuthFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthFillDataConfigTest001, TestSize.Level1)
{
    int32_t ret = GetAuthChannelLock();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ReleaseAuthChannelLock();
    ret = TransAuthFillDataConfig(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    EXPECT_NE(appInfo, nullptr);

    ret = TransAuthFillDataConfig(appInfo);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransAuthProcessDataConfigTest001
 * @tc.desc: TransAuthFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthProcessDataConfigTest001, TestSize.Level1)
{
    int32_t ret = TransAuthProcessDataConfig(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    EXPECT_NE(appInfo, nullptr);
    appInfo->businessType = BUSINESS_TYPE_FILE;
    ret = TransAuthProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    appInfo->peerData.dataConfig = 1;
    ret = TransAuthProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    appInfo->peerData.dataConfig = 0;
    ret = TransAuthProcessDataConfig(appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FillExtraByAuthChannelErrorEnd(nullptr, nullptr, 1);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransFillAuthChannelInfoTest001
 * @tc.desc: TransAuthFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransFillAuthChannelInfoTest001, TestSize.Level1)
{
    int32_t ret = TransFillAuthChannelInfo(nullptr, nullptr, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AuthChannelInfo *channel = static_cast<AuthChannelInfo *>(SoftBusCalloc(sizeof(AuthChannelInfo)));
    EXPECT_NE(channel, nullptr);
    LaneConnInfo *connInfo = static_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    EXPECT_NE(channel, nullptr);
    int32_t channelId = TRANS_TEST_CHANNEL_ID;
    ret = TransFillAuthChannelInfo(channel, connInfo, &channelId, true);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransOpenAuthMsgChannelWithParaTest001
 * @tc.desc: TransAuthFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelWithParaTest001, TestSize.Level1)
{
    int32_t ret = TransOpenAuthMsgChannelWithPara(nullptr, nullptr, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = CheckIsWifiAuthChannel(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ConnectOption *connInfo = static_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    EXPECT_NE(connInfo, nullptr);
    connInfo->socketOption.moduleId = 1;
    ret = CheckIsWifiAuthChannel(connInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransSetAuthChannelReplyCntTest001
 * @tc.desc: TransAuthFillDataConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransSetAuthChannelReplyCntTest001, TestSize.Level1)
{
    int32_t ret = TransSetAuthChannelReplyCnt(TRANS_TEST_CHANNEL_ID);
    EXPECT_NE(ret, SOFTBUS_OK);
}
} // namespace OHOS
