/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_listener.c"
#include "softbus_utils.h"
#include "trans_auth_mock.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;

class SoftbusProxyChannelListenerTest : public testing::Test {
public:
    SoftbusProxyChannelListenerTest(void)
    {}
    ~SoftbusProxyChannelListenerTest(void)
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override
    {}
    void TearDown(void) override
    {}
};

int32_t TestOnDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    g_testProxyChannelReceiveFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    g_testProxyChannelOpenSuccessFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid,
    int32_t channelId, int32_t channelType, int32_t messageType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)messageType;
    g_testProxyChannelClosedFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)errCode;
    g_testProxyChannelOpenFailFlag = true;
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_OK;
}

extern "C" {
int32_t TestGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    (void)sessionName;
    (void)pkgName;
    (void)len;
    return SOFTBUS_OK;
}
}

static int32_t TestOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

void SoftbusProxyChannelListenerTest::SetUpTestCase(void)
{
    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = TestOnChannelOpened;
    callBack.OnChannelClosed = TestOnChannelClosed;
    callBack.OnChannelOpenFailed = TestOnChannelOpenFailed;
    callBack.OnDataReceived = TestOnDataReceived;
    callBack.OnQosEvent = nullptr;
    callBack.GetPkgNameBySessionName = TestGetPkgNameBySessionName;
    callBack.GetUidAndPidBySessionName = TestGetUidAndPidBySessionName;
    callBack.OnChannelBind = TestOnChannelBind;
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInitInner(&callBack));
}

void SoftbusProxyChannelListenerTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: NotifyNormalChannelClosedTest001
 * @tc.desc: test notify normal channel closed with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelClosedTest001, TestSize.Level1)
{
    char pkgName[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(pkgName, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    g_testProxyChannelClosedFlag = false;
    int32_t ret = NotifyNormalChannelClosed(pkgName, TEST_NUMBER_25, TEST_NUMBER_TEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelClosedFlag);
}

/**
 * @tc.name: NotifyNormalChannelOpenFailedTest001
 * @tc.desc: test notify normal channel open failed with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenFailedTest001, TestSize.Level1)
{
    char pkgName[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(pkgName, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    g_testProxyChannelOpenFailFlag = false;
    int32_t ret = NotifyNormalChannelOpenFailed(pkgName, TEST_NUMBER_25, TEST_NUMBER_TEN, TEST_NUMBER_ONE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelOpenFailFlag);
}

/**
 * @tc.name: NotifyNormalChannelOpenedTest001
 * @tc.desc: test notify normal channel opened with auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->appType = APP_TYPE_AUTH;
    g_testProxyChannelOpenSuccessFlag = false;
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelOpenSuccessFlag);
    SoftBusFree(appInfo);
}

#ifdef DSOFTBUS_FEATURE_PROXY_CHANNEL
/**
 * @tc.name: NotifyNormalChannelOpenedTest002
 * @tc.desc: test notify normal channel opened with normal type and get network id fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest002, TestSize.Level1)
{
    TransAuthInterfaceMock authMock;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->appType = APP_TYPE_NORMAL;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_TRANS_INIT_FAILED));
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, false);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
}
#endif

/**
 * @tc.name: NotifyNormalChannelOpenedTest003
 * @tc.desc: test notify normal channel opened with normal type and get network id succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest003, TestSize.Level1)
{
    TransAuthInterfaceMock authMock;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->appType = APP_TYPE_NORMAL;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: NotifyNormalChannelOpenedTest004
 * @tc.desc: test notify normal channel opened with normal type, server side, native token type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest004, TestSize.Level1)
{
    TransAuthInterfaceMock authMock;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.tokenType = ACCESS_TOKEN_TYPE_NATIVE;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: NotifyNormalChannelOpenedTest005
 * @tc.desc: test notify normal channel opened with isD2D true path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest005, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->isD2D = true;
    appInfo->appType = APP_TYPE_NORMAL;
    g_testProxyChannelOpenSuccessFlag = false;
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelOpenSuccessFlag);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnProxyChannelOpenedTest001
 * @tc.desc: test on proxy channel opened with auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenedTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = OnProxyChannelOpened(TEST_NUMBER_25, appInfo, 0);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelOpenFailedTest001
 * @tc.desc: test on proxy channel open failed with auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenFailedTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    (void)strcpy_s(appInfo->peerData.deviceId, SESSIONKEYSIZE, TEST_STRING_TEN);
    appInfo->appType = APP_TYPE_AUTH;
    g_testProxyChannelOpenFailFlag = false;
    int32_t ret = OnProxyChannelOpenFailed(TEST_NUMBER_25, appInfo, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelOpenFailFlag);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnProxyChannelOpenFailedTest002
 * @tc.desc: test on proxy channel open failed with inner type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenFailedTest002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    (void)strcpy_s(appInfo->peerData.deviceId, SESSIONKEYSIZE, TEST_STRING_TEN);
    appInfo->appType = APP_TYPE_INNER;
    int32_t ret = OnProxyChannelOpenFailed(TEST_NUMBER_25, appInfo, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NOTIFY_NETWORK_OPEN_ERR, ret);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnProxyChannelOpenFailedTest003
 * @tc.desc: test on proxy channel open failed with invalid app type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenFailedTest003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    (void)strcpy_s(appInfo->peerData.deviceId, SESSIONKEYSIZE, TEST_STRING_TEN);
    appInfo->appType = static_cast<AppType>(5);
    int32_t ret = OnProxyChannelOpenFailed(TEST_NUMBER_25, appInfo, 0);
    EXPECT_EQ(SOFTBUS_INVALID_APPTYPE, ret);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnProxyChannelClosedTest001
 * @tc.desc: test on proxy channel closed with auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelClosedTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    appInfo->appType = APP_TYPE_AUTH;
    g_testProxyChannelClosedFlag = false;
    int32_t ret = OnProxyChannelClosed(TEST_NUMBER_25, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelClosedFlag);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnProxyChannelMsgReceivedTest001
 * @tc.desc: test on proxy channel msg received with auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelMsgReceivedTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    (void)strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    char data[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(data, SESSIONKEYSIZE, VALID_SESSIONNAME);
    appInfo->appType = APP_TYPE_AUTH;
    g_testProxyChannelReceiveFlag = false;
    int32_t ret = OnProxyChannelMsgReceived(TEST_NUMBER_25, appInfo, data, SESSIONKEYSIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(g_testProxyChannelReceiveFlag);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransOpenNetWorkingChannelTest001
 * @tc.desc: test trans open networking channel with nullptr preferred returns invalid channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransOpenNetWorkingChannelTest001, TestSize.Level1)
{
    char sessionName[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    char peerNetworkId[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(peerNetworkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    int32_t ret = TransOpenNetWorkingChannel(sessionName, peerNetworkId, nullptr);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransSendNetworkingMessageTest001
 * @tc.desc: test trans send networking message with invalid channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransSendNetworkingMessageTest001, TestSize.Level1)
{
    char sendData[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(sendData, SESSIONKEYSIZE, VALID_SESSIONNAME);
    int32_t ret = TransSendNetworkingMessage(-1, sendData, PROXY_CHANNEL_BT_IDLE_TIMEOUT, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
    ret = TransSendNetworkingMessage(TEST_NUMBER_25, sendData, PROXY_CHANNEL_BT_IDLE_TIMEOUT, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransSendNetworkingMessageTest002
 * @tc.desc: test trans send networking message with keepliveing status and normal app type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransSendNetworkingMessageTest002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "testSessionName");
    (void)strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), "testPkgName");
    (void)strcpy_s(appInfo->peerVersion, sizeof(appInfo->peerVersion), "testPeerVersion");
    appInfo->connectType = 1;
    appInfo->appType = APP_TYPE_NORMAL;
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(chan != nullptr);
    chan->channelId = TEST_NUMBER_ONE;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char sendData[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(sendData, SESSIONKEYSIZE, VALID_SESSIONNAME);
    ret = TransSendNetworkingMessage(TEST_NUMBER_ONE, sendData, PROXY_CHANNEL_BT_IDLE_TIMEOUT, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
    SoftBusFree(chan);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransSendNetworkingMessageTest003
 * @tc.desc: test trans send networking message with invalid channel status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransSendNetworkingMessageTest003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "testSessionName");
    (void)strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), "testPkgName");
    (void)strcpy_s(appInfo->peerVersion, sizeof(appInfo->peerVersion), "testPeerVersion");
    appInfo->connectType = 1;
    appInfo->appType = APP_TYPE_NORMAL;
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(chan != nullptr);
    chan->channelId = TEST_NUMBER_5000;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char sendData[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(sendData, SESSIONKEYSIZE, VALID_SESSIONNAME);
    ret = TransSendNetworkingMessage(TEST_NUMBER_5000, sendData, PROXY_CHANNEL_BT_IDLE_TIMEOUT, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID, ret);
    SoftBusFree(chan);
    SoftBusFree(appInfo);
}

#ifdef DSOFTBUS_FEATURE_PROXY_CHANNEL
/**
 * @tc.name: OnProxyChannelBindTest001
 * @tc.desc: test on proxy channel bind with normal type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelBindTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = OnProxyChannelBind(TEST_NUMBER_25, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = OnProxyChannelBind(TEST_NUMBER_ONE, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelBindTest002
 * @tc.desc: test on proxy channel bind with null app info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelBindTest002, TestSize.Level1)
{
    int32_t ret = OnProxyChannelBind(TEST_NUMBER_25, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OnProxyChannelBind(-1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OnProxyChannelBind(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnProxyChannelBindTest003
 * @tc.desc: test on proxy channel bind with inner type returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelBindTest003, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = APP_TYPE_INNER;
    int32_t ret = OnProxyChannelBind(TEST_NUMBER_25, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = OnProxyChannelBind(TEST_NUMBER_ONE, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelBindTest004
 * @tc.desc: test on proxy channel bind with not care type returns proxy error app type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelBindTest004, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = APP_TYPE_NOT_CARE;
    int32_t ret = OnProxyChannelBind(TEST_NUMBER_25, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
    ret = OnProxyChannelBind(TEST_NUMBER_ONE, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}
#endif

/**
 * @tc.name: FillExtraByProxyChannelErrorEndTest001
 * @tc.desc: test fill extra by proxy channel error end with null params returns early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, FillExtraByProxyChannelErrorEndTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    TransEventExtra extra = {};
    FillExtraByProxyChannelErrorEnd(nullptr, nullptr, nullptr, 1);
    FillExtraByProxyChannelErrorEnd(nullptr, appInfo, nullptr, 1);
    FillExtraByProxyChannelErrorEnd(&extra, nullptr, nullptr, 1);
    FillExtraByProxyChannelErrorEnd(&extra, appInfo, nullptr, 1);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: FillExtraByProxyChannelErrorEndTest002
 * @tc.desc: test fill extra by proxy channel error end with valid params fills extra fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, FillExtraByProxyChannelErrorEndTest002, TestSize.Level1)
{
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "testSessionName");
    (void)strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), "testPkgName");
    (void)strcpy_s(appInfo->peerVersion, sizeof(appInfo->peerVersion), "testPeerVersion");
    appInfo->connectType = 1;
    appInfo->appType = APP_TYPE_AUTH;
    char localUdid[UDID_BUF_LEN] = { 0 };
    TransEventExtra extra = {
        .socketName = nullptr,
        .peerNetworkId = nullptr,
        .calleePkg = nullptr,
        .callerPkg = nullptr,
        .channelId = 1111,
        .costTime = 1000,
        .errcode = 0,
        .result = EVENT_STAGE_RESULT_OK
    };
    FillExtraByProxyChannelErrorEnd(&extra, appInfo, localUdid, 1);
    EXPECT_TRUE(extra.socketName != nullptr);
    EXPECT_TRUE(extra.callerPkg != nullptr);
    EXPECT_TRUE(extra.localUdid != nullptr);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransGetConnectOptionTest001
 * @tc.desc: test trans get connect option fails when lane info unavailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransGetConnectOptionTest001, TestSize.Level1)
{
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, ApplyLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    LanePreferredLinkList *preferred =
        static_cast<LanePreferredLinkList *>(SoftBusCalloc(sizeof(LanePreferredLinkList)));
    ASSERT_TRUE(preferred != nullptr);
    preferred->linkTypeNum = 1;
    const char *sessionName = "testSessionName";
    const char *peerNetworkId = "1111";
    int32_t channelId = 1111;
    int32_t ret = TransGetConnectOption(sessionName, peerNetworkId, preferred, channelId);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    SoftBusFree(preferred);
}

/**
 * @tc.name: GetProxyChannelInfoTest001
 * @tc.desc: test get proxy channel info with D2D true and dataLen greater than zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, GetProxyChannelInfoTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_5000;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->isD2D = true;
    appInfo->peerData.dataLen = 1;
    bool isServer = false;
    ChannelInfo info = {};
    GetProxyChannelInfo(channelId, appInfo, isServer, &info);
    EXPECT_EQ(info.channelId, channelId);
    EXPECT_TRUE(info.isD2D);
    EXPECT_EQ(info.dataLen, static_cast<uint32_t>(1));
    SoftBusFree(appInfo);
}

/**
 * @tc.name: GetProxyChannelInfoTest002
 * @tc.desc: test get proxy channel info with D2D true and server side
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, GetProxyChannelInfoTest002, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_5000;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->isD2D = true;
    appInfo->peerData.dataLen = 1;
    bool isServer = true;
    ChannelInfo info = {};
    GetProxyChannelInfo(channelId, appInfo, isServer, &info);
    EXPECT_TRUE(info.isServer);
    EXPECT_EQ(info.channelId, channelId);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: GetProxyChannelInfoTest003
 * @tc.desc: test get proxy channel info with non-D2D auth type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, GetProxyChannelInfoTest003, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_5000;
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->isD2D = false;
    appInfo->appType = APP_TYPE_AUTH;
    bool isServer = false;
    ChannelInfo info = {};
    GetProxyChannelInfo(channelId, appInfo, isServer, &info);
    EXPECT_EQ(info.channelId, channelId);
    EXPECT_FALSE(info.isEncrypt);
    SoftBusFree(appInfo);
}
} // namespace OHOS
