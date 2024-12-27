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
    callBack.OnQosEvent = NULL;
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
    EXPECT_NE(NULL, appInfo);
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
    EXPECT_NE(NULL, appInfo);
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
    EXPECT_NE(NULL, appInfo);
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
    EXPECT_NE(NULL, appInfo);
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
    EXPECT_NE(NULL, appInfo);
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
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: OnProxyChannelBindTest001
 * @tc.desc: test OnProxyChannelBind.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelListenerTest, OnProxyChannelBindTest001, TestSize.Level1)
{
    AppInfo appInfo;

    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = OnProxyChannelBind(TEST_NUMBER_25, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS