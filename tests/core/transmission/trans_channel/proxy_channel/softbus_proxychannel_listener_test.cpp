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

#include <securec.h>

#include "gtest/gtest.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_listener.c"
#include "softbus_utils.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
#define TEST_AUTHSESSION "IShareAuthSession"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define VALID_BUSNAME "testbusName"
#define VALID_PKGNAME "testPkgName"
#define VALID_SESSIONNAME "testSessionName"

#define TEST_ARRRY_SIZE 48
#define TEST_BUF_LEN 32
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_DEATH_CHANNEL_ID 14
#define TEST_INVALID_LARGE_SIZE (100 * 1024)
#define TEST_MESSAGE_CHANNEL_ID 13
#define TEST_MESSAGE_CHANNEL_VALID_ID 46
#define TEST_NUMBER_ELEVEN 11
#define TEST_NUMBER_ONE 1
#define TEST_NUMBER_TEN 10
#define TEST_NUMBER_THREE 3
#define TEST_NUMBER_TWENTY 20
#define TEST_NUMBER_TWO 2
#define TEST_NUMBER_VALID (-1)
#define TEST_NUMBER_ZERO (-1)
#define TEST_NUMBER_25 25
#define TEST_NUMBER_26 26
#define TEST_NUMBER_5000 5000
#define TEST_PARSE_MESSAGE_CHANNEL 45
#define TEST_PAY_LOAD "testPayLoad"
#define TEST_PKGNAME "com.test.pkgname"
#define TEST_PKG_NAME_LEN 65
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT 240
#define TEST_RESET_MESSAGE_CHANNEL_ID 30
#define TEST_STRING_TEN "10"
#define TEST_STRING_ELEVEN "11"
#define SESSIONKEYSIZE 256

static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;

class SoftbusProxyChannelListenerTest : public testing::Test {
public:
    SoftbusProxyChannelListenerTest()
    {}
    ~SoftbusProxyChannelListenerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
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

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
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

void SoftbusProxyChannelListenerTest::SetUpTestCase(void)
{

    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = TestOnChannelOpened;
    callBack.OnChannelClosed = TestOnChannelClosed;
    callBack.OnChannelOpenFailed = TestOnChannelOpenFailed;
    callBack.OnDataReceived = TestOnDataReceived;
    callBack.OnQosEvent = NULL;
    callBack.GetPkgNameBySessionName = TestGetPkgNameBySessionName;
    callBack.GetUidAndPidBySessionName = TestGetUidAndPidBySessionName;
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInitInner(&callBack));
}

void SoftbusProxyChannelListenerTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: NotifyNormalChannelClosedTest001
 * @tc.desc: test notify normal channel closed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelClosedTest001, TestSize.Level1)
{
    char pkgName[SESSIONKEYSIZE] = {0};
    strcpy_s(pkgName, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);

    int32_t ret = NotifyNormalChannelClosed(pkgName, TEST_NUMBER_25, TEST_NUMBER_TEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: NotifyNormalChannelOpenFailedTest001
 * @tc.desc: test notify normal channel open failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenFailedTest001, TestSize.Level1)
{
    char pkgName[SESSIONKEYSIZE] = {0};
    strcpy_s(pkgName, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);

    int32_t ret = NotifyNormalChannelOpenFailed(pkgName, TEST_NUMBER_25, TEST_NUMBER_TEN, TEST_NUMBER_ONE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: NotifyNormalChannelOpenedTest001
 * @tc.desc: test notify normal channel opened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, NotifyNormalChannelOpenedTest001, TestSize.Level1)
{
    char pkgName[SESSIONKEYSIZE] = {0};
    strcpy_s(pkgName, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);

    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->appType = APP_TYPE_NORMAL;
    ret = NotifyNormalChannelOpened(TEST_NUMBER_25, appInfo, 0);
    SoftBusFree(appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelOpenedTest001
 * @tc.desc: test On Proxy Channel Opened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenedTest001, TestSize.Level1)
{
    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = OnProxyChannelOpened(TEST_NUMBER_25, appInfo, 0);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelOpenFailedTest001
 * @tc.desc: test onproxy channel open failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelOpenFailedTest001, TestSize.Level1)
{
    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    strcpy_s(appInfo->peerData.deviceId, SESSIONKEYSIZE, TEST_STRING_TEN);

    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = OnProxyChannelOpenFailed(TEST_NUMBER_25, appInfo, 0);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelClosedTest001
 * @tc.desc: test onproxy channel open failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelClosedTest001, TestSize.Level1)
{
    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);

    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = OnProxyChannelClosed(TEST_NUMBER_25, appInfo);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnProxyChannelMsgReceivedTest001
 * @tc.desc: test on proxy channel msg received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelMsgReceivedTest001, TestSize.Level1)
{
    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    strcpy_s(appInfo->myData.pkgName, SESSIONKEYSIZE, TEST_PKG_NAME);
    appInfo->myData.pid = TEST_NUMBER_25;
    strcpy_s(appInfo->myData.sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    char data[SESSIONKEYSIZE] = {0};
    strcpy_s(data, SESSIONKEYSIZE, VALID_SESSIONNAME);

    appInfo->appType = APP_TYPE_AUTH;
    int32_t ret = OnProxyChannelMsgReceived(TEST_NUMBER_25, appInfo, data, SESSIONKEYSIZE);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetAppInfoTest001
 * @tc.desc: test trans proxy get appinfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransProxyGetAppInfoTest001, TestSize.Level1)
{
    AppInfo *appInfo =  (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return;
    }
    char sessionName[SESSIONKEYSIZE] = {0};
    strcpy_s(sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    char peerNetworkId[SESSIONKEYSIZE] = {0};
    strcpy_s(peerNetworkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);

    int32_t ret = TransProxyGetAppInfo(sessionName, peerNetworkId, appInfo);
    SoftBusFree(appInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransOpenNetWorkingChannelTest001
 * @tc.desc: test trans open networking channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransOpenNetWorkingChannelTest001, TestSize.Level1)
{
    char sessionName[SESSIONKEYSIZE] = {0};
    strcpy_s(sessionName, SESSIONKEYSIZE, VALID_SESSIONNAME);
    char peerNetworkId[SESSIONKEYSIZE] = {0};
    strcpy_s(peerNetworkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);

    int32_t ret = TransOpenNetWorkingChannel(sessionName, peerNetworkId, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransSendNetworkingMessageTest001
 * @tc.desc: test trans send networking message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, TransSendNetworkingMessageTest001, TestSize.Level1)
{
    char sendData[SESSIONKEYSIZE] = {0};
    strcpy_s(sendData, SESSIONKEYSIZE, VALID_SESSIONNAME);

    int32_t ret = TransSendNetworkingMessage(TEST_NUMBER_25, sendData, PROXY_CHANNEL_BT_IDLE_TIMEOUT, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID, ret);
}
} // namespace OHOS