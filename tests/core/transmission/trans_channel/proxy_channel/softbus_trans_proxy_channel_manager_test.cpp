/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include <securec.h>

#include "mock/softbus_proxychannel_manager_mock_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_proxychannel_manager.c"

using namespace testing;
using namespace testing::ext;
using namespace std;

using testing::_;
using testing::Return;
using testing::SetArgReferee;

namespace OHOS {

#define TEST_INVALID_TYPE 99
#define TEST_CHANNEL_ID 1055
#define TEST_CALLING_PID 1750

class SoftbusTransProxyChannelManagerTest : public testing::Test {
public:
    SoftbusTransProxyChannelManagerTest() { }
    ~SoftbusTransProxyChannelManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftbusTransProxyChannelManagerTest::SetUpTestCase(void)
{
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());
}

void SoftbusTransProxyChannelManagerTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

/**@
 * @tc.name: GetProxyChannelMgrHead
 * @tc.desc: test proxy GetProxyChannelMgrHead.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, GetProxyChannelMgrHead, TestSize.Level1)
{
    EXPECT_EQ(GetProxyChannelMgrHead(), nullptr);
}

/**@
 * @tc.name: GetProxyChannelLock001
 * @tc.desc: test proxy GetProxyChannelLock001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, GetProxyChannelLock001, TestSize.Level1)
{
    EXPECT_EQ(GetProxyChannelLock(), SOFTBUS_NO_INIT);
}

/**@
 * @tc.name: ReleaseProxyChannelLock001
 * @tc.desc: test proxy ReleaseProxyChannelLock001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, ReleaseProxyChannelLock001, TestSize.Level1)
{
    EXPECT_NO_THROW(ReleaseProxyChannelLock());
}

/**@
 * @tc.name: ReleaseProxyChannelLock002
 * @tc.desc: test proxy ReleaseProxyChannelLock002.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, ReleaseProxyChannelLock002, TestSize.Level1)
{
    SoftBusList list;
    g_proxyChannelList = &list;
    EXPECT_NO_THROW(ReleaseProxyChannelLock());
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: FindConfigType
 * @tc.desc: test proxy FindConfigType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, FindConfigType, TestSize.Level1)
{
    int32_t result = FindConfigType(TEST_INVALID_TYPE, TEST_INVALID_TYPE);
    EXPECT_EQ(result, SOFTBUS_CONFIG_TYPE_MAX);
}

/**@
 * @tc.name: TransGetLocalConfig001
 * @tc.desc: test proxy TransGetLocalConfig001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransGetLocalConfig001, TestSize.Level1)
{
    uint32_t len;

    ConfigType configType = static_cast<ConfigType>(FindConfigType(TEST_INVALID_TYPE, TEST_INVALID_TYPE));
    EXPECT_EQ(configType, SOFTBUS_CONFIG_TYPE_MAX);

    int32_t result = TransGetLocalConfig(TEST_INVALID_TYPE, TEST_INVALID_TYPE, &len);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/**@
 * @tc.name: TransGetLocalConfig002
 * @tc.desc: test proxy TransGetLocalConfig002.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransGetLocalConfig002, TestSize.Level1)
{
    uint32_t len;

    ConfigType configType = static_cast<ConfigType>(FindConfigType(CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE));
    EXPECT_NE(configType, SOFTBUS_CONFIG_TYPE_MAX);

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_CONFIG_TYPE_MAX));
    int32_t result = TransGetLocalConfig(CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE, &len);
    EXPECT_EQ(result, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/**@
 * @tc.name: TransProxyProcessDataConfig001
 * @tc.desc: test proxy TransProxyProcessDataConfig001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyProcessDataConfig001, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.businessType = static_cast<BusinessType>(TEST_INVALID_TYPE);
    EXPECT_EQ(TransProxyProcessDataConfig(&appInfo), SOFTBUS_OK);
}

/**@
 * @tc.name: TransProxyHandshakeUnpackErrMsg001
 * @tc.desc: test proxy TransProxyHandshakeUnpackErrMsg001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyHandshakeUnpackErrMsg001, TestSize.Level1)
{
    ProxyChannelInfo info;
    ProxyMessage msg;
    info.myId = 1;
    info.peerId = 2;
    msg.data = const_cast<char *>("Test-Data");
    msg.dataLen = strlen(msg.data);
    int32_t result = TransProxyHandshakeUnpackErrMsg(&info, &msg, nullptr);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/**@
 * @tc.name: TransProxyHandshakeUnpackErrMsg002
 * @tc.desc: test proxy TransProxyHandshakeUnpackErrMsg002.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyHandshakeUnpackErrMsg002, TestSize.Level1)
{
    ProxyChannelInfo info;
    ProxyMessage msg;
    int32_t errCode = 0;
    info.myId = 1;
    info.peerId = 2;
    msg.data = const_cast<char *>("Test-Data");
    msg.dataLen = strlen(msg.data);

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnPackHandshakeErrMsg).WillOnce(Return(SOFTBUS_OK));

    int32_t result = TransProxyHandshakeUnpackErrMsg(&info, &msg, &errCode);
    EXPECT_EQ(result, SOFTBUS_OK);
    EXPECT_EQ(errCode, 0);
}

/**@
 * @tc.name: TransProxyHandshakeUnpackRightMsg001
 * @tc.desc: test proxy TransProxyHandshakeUnpackRightMsg001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyHandshakeUnpackRightMsg001, TestSize.Level1)
{
    ProxyChannelInfo info;
    ProxyMessage msg;
    int32_t errCode = 100;

    int32_t ret = TransProxyHandshakeUnpackRightMsg(&info, &msg, errCode, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**@
 * @tc.name: TransProxyGetLocalInfo001
 * @tc.desc: test proxy TransProxyGetLocalInfo001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyGetLocalInfo001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    chan.appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = strcpy_s(chan.appInfo.myData.sessionName, sizeof(chan.appInfo.myData.sessionName), "test_session");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(chan.appInfo.myData.pkgName, sizeof(chan.appInfo.myData.pkgName), "test_pkg");
    EXPECT_EQ(ret, EOK);

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyGetPkgName(_, _, _)).WillOnce(Return(SOFTBUS_INVALID_PKGNAME));
    EXPECT_CALL(mock, TransProxyGetUidAndPidBySessionName(_, _, _)).Times(0);

    int32_t result = TransProxyGetLocalInfo(&chan);

    EXPECT_EQ(result, SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED);
}

/**@
 * @tc.name: TransProxyFillDataConfig001
 * @tc.desc: test proxy TransProxyFillDataConfig001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillDataConfig001, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NOT_CARE;
    appInfo.businessType = BUSINESS_TYPE_NOT_CARE;

    int32_t ret = TransProxyFillDataConfig(&appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**@
 * @tc.name: TransProxyFillDataConfig002
 * @tc.desc: test proxy TransProxyFillDataConfig002.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillDataConfig002, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.appType = APP_TYPE_NOT_CARE;
    appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    appInfo.peerData.dataConfig = 0;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, SoftbusGetConfig(_, _, _)).WillOnce(Return(SOFTBUS_GET_CONFIG_VAL_ERR));
    int32_t result = TransProxyFillDataConfig(&appInfo);

    EXPECT_EQ(result, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/**@
 * @tc.name: TransProxyFillChannelInfo001
 * @tc.desc: test proxy TransProxyFillChannelInfo001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillChannelInfo001, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillOnce(Return(SOFTBUS_PARSE_JSON_ERR));

    int32_t ret = TransProxyFillChannelInfo(&msg, &chan);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/**@
 * @tc.name: TransProxyFillChannelInfo002
 * @tc.desc: test proxy TransProxyFillChannelInfo002.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillChannelInfo002, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    chan.appInfo.appType = APP_TYPE_NOT_CARE;
    msg.msgHead.cipher = 10;

    int32_t ret = TransProxyFillChannelInfo(&msg, &chan);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**@
 * @tc.name: TransProxyFillChannelInfo003
 * @tc.desc: test proxy TransProxyFillChannelInfo003.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillChannelInfo003, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    chan.appInfo.appType = APP_TYPE_AUTH;
    msg.msgHead.cipher = 9;
    EXPECT_CALL(mock, CheckSessionNameValidOnAuthChannel(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, ConnGetConnectionInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnGetTypeByConnectionId(_, _)).WillRepeatedly(Return(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT));

    int32_t ret = TransProxyFillChannelInfo(&msg, &chan);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
}

/**@
 * @tc.name: TransProxyFillChannelInfo004
 * @tc.desc: test proxy TransProxyFillChannelInfo004.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyFillChannelInfo004, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.appInfo.callingTokenId = 1;
    msg.msgHead.cipher = 9;
    EXPECT_CALL(mock, ConnGetConnectionInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnGetTypeByConnectionId(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransCheckServerAccessControl(_)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = TransProxyFillChannelInfo(&msg, &chan);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: TransNotifyUserSwitchTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransNotifyUserSwitchTest001, TestSize.Level1)
{
    LnnMonitorHbStateChangedEvent *info = (LnnMonitorHbStateChangedEvent *)SoftBusCalloc(
        sizeof(LnnMonitorHbStateChangedEvent));
    ASSERT_TRUE(info != nullptr);
    info->basic.event = LNN_EVENT_BT_STATE_CHANGED;
    info->status = SOFTBUS_USER_SWITCHED;
    TransNotifyUserSwitch(nullptr);
    const LnnEventBasicInfo *event = (const LnnEventBasicInfo *)info;
    TransNotifyUserSwitch(event);
    info->status = SOFTBUS_USER_SWITCH_UNKNOWN;
    TransNotifyUserSwitch(event);
    SoftBusFree(info);
}

/**
 * @tc.name: HandleProxyChanelOpenedTest001
 * @tc.desc: HandleProxyChanelOpened
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyChanelOpenedTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    int32_t channelId = 2122;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyAckHandshake).WillOnce(Return(SOFTBUS_TRANS_PROXY_PACKMSG_ERR));

    int32_t ret = HandleProxyChanelOpened(&chan, channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_PACKMSG_ERR);
}

/**
 * @tc.name: HandleProxyChanelOpenedTest002
 * @tc.desc: HandleProxyChanelOpened
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyChanelOpenedTest002, TestSize.Level1)
{
    ProxyChannelInfo chan;
    int32_t channelId = 2122;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyAckHandshake).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, OnProxyChannelBind).WillOnce(Return(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE));

    int32_t ret = HandleProxyChanelOpened(&chan, channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE);
}

/**
 * @tc.name: HandleProxyChanelOpenedTest003
 * @tc.desc: HandleProxyChanelOpened
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyChanelOpenedTest003, TestSize.Level1)
{
    ProxyChannelInfo chan;
    int32_t channelId = 2122;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyAckHandshake).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, OnProxyChannelBind).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = HandleProxyChanelOpened(&chan, channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: HandleProxyGenUkResultTest001
 * @tc.desc: HandleProxyGenUkResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyGenUkResultTest001, TestSize.Level1)
{
    int32_t requestId = 3068;
    int32_t ukId = 1011;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransUkRequestGetRequestInfoByRequestId).WillOnce(Return(SOFTBUS_NOT_FIND));

    EXPECT_NO_FATAL_FAILURE(HandleProxyGenUkResult(requestId, ukId, SOFTBUS_OK));
}

/**
 * @tc.name: HandleProxyGenUkResultTest002
 * @tc.desc: HandleProxyGenUkResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyGenUkResultTest002, TestSize.Level1)
{
    int32_t requestId = 3068;
    int32_t ukId = 1011;
    UkRequestNode ukRequestNode;
    ukRequestNode.channelId = 1528;
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = 1528;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransUkRequestGetRequestInfoByRequestId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(ukRequestNode), Return(SOFTBUS_OK)));
    
    g_proxyChannelList = CreateSoftBusList();
    if (g_proxyChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "proxy manager init inner failed");
        return;
    }
    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));
    EXPECT_NO_FATAL_FAILURE(HandleProxyGenUkResult(requestId, ukId, SOFTBUS_OK));

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: HandleProxyGenUkResultTest003
 * @tc.desc: HandleProxyGenUkResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, HandleProxyGenUkResultTest003, TestSize.Level1)
{
    int32_t requestId = 3068;
    int32_t ukId = 1011;
    UkRequestNode ukRequestNode;
    ukRequestNode.channelId = 1528;
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = 1528;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransUkRequestGetRequestInfoByRequestId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(ukRequestNode), Return(SOFTBUS_OK)));

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));
    EXPECT_NO_THROW(HandleProxyGenUkResult(requestId, ukId, SOFTBUS_INVALID_PARAM));

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyChannelOpenResultTest001
 * @tc.desc: TransDealProxyChannelOpenResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyChannelOpenResultTest001, TestSize.Level1)
{
    AccessInfo accessInfo;
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;
    proxyChannelInfo->appInfo.myData.pid = 555;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t ret = TransDealProxyChannelOpenResult(TEST_CHANNEL_ID, SOFTBUS_OK, &accessInfo, 666);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyChannelOpenResultTest002
 * @tc.desc: TransDealProxyChannelOpenResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyChannelOpenResultTest002, TestSize.Level1)
{
    AccessInfo accessInfo = {
        .userId = 21445856,
        .localTokenId = 74212546
    };
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;
    proxyChannelInfo->appInfo.myData.pid = 555;
    proxyChannelInfo->appInfo.myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    uint32_t size = 18;
    char accountId[ACCOUNT_UID_LEN_MAX] = "fheowfhqfhnepfgg9";
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, GetLocalAccountUidByUserId)
        .WillRepeatedly(DoAll(SetArgPointee<0>(*accountId), SetArgPointee<2>(size), Return(SOFTBUS_OK)));

    int32_t ret = TransDealProxyChannelOpenResult(TEST_CHANNEL_ID, SOFTBUS_OK, &accessInfo, 555);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyChannelOpenResultTest003
 * @tc.desc: TransDealProxyChannelOpenResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyChannelOpenResultTest003, TestSize.Level1)
{
    AccessInfo accessInfo = {
        .userId = 21445856,
        .localTokenId = 74212546
    };
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    uint32_t size = 18;
    char accountId[ACCOUNT_UID_LEN_MAX] = "fheowfhqfhnepfgg9";
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, GetLocalAccountUidByUserId)
        .WillRepeatedly(DoAll(SetArgPointee<0>(*accountId), SetArgPointee<2>(size), Return(SOFTBUS_OK)));

    int32_t ret = TransDealProxyChannelOpenResult(TEST_CHANNEL_ID, SOFTBUS_OK, &accessInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyChannelOpenResultTest004
 * @tc.desc: TransDealProxyChannelOpenResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyChannelOpenResultTest004, TestSize.Level1)
{
    AccessInfo accessInfo = {
        .userId = 21445856,
        .localTokenId = 74212546
    };
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    uint32_t size = 18;
    char accountId[ACCOUNT_UID_LEN_MAX] = "fheowfhqfhnepfgg9";
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, GetLocalAccountUidByUserId)
        .WillRepeatedly(DoAll(SetArgPointee<0>(*accountId), SetArgPointee<2>(size), Return(SOFTBUS_OK)));

    int32_t ret = TransDealProxyChannelOpenResult(TEST_CHANNEL_ID, SOFTBUS_TRANS_SESSION_OPENING, &accessInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransProxyProcessReNegotiateMsgTest001
 * @tc.desc: TransProxyProcessReNegotiateMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyProcessReNegotiateMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info = {
        .myId = 1516
    };
    ProxyMessage msg = {
        .connId = 103014
    };
    AuthConnInfo authConnInfo = {
        .type = AUTH_LINK_TYPE_WIFI,
        .info.ipInfo.port = 114,
        .info.ipInfo.moduleId = DIRECT_CHANNEL_SERVER_WIFI
    };

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, GetAuthConnInfoByConnId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(authConnInfo), Return(SOFTBUS_OK)));

    EXPECT_CALL(mock, TransReNegotiateSessionKey).WillOnce(Return(SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND));

    int32_t ret = TransProxyProcessReNegotiateMsg(&msg, &info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND);
}

/**
 * @tc.name: TransProxyProcessReNegotiateMsgTest002
 * @tc.desc: TransProxyProcessReNegotiateMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyProcessReNegotiateMsgTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {
        .myId = 1516
    };
    ProxyMessage msg = {
        .connId = 103014
    };
    AuthConnInfo authConnInfo = {
        .type = AUTH_LINK_TYPE_WIFI,
        .info.ipInfo.port = 114,
        .info.ipInfo.moduleId = DIRECT_CHANNEL_SERVER_WIFI
    };

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, GetAuthConnInfoByConnId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(authConnInfo), Return(SOFTBUS_OK)));

    EXPECT_CALL(mock, TransReNegotiateSessionKey).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransProxyProcessReNegotiateMsg(&msg, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransProxyProcessResetMsgTest001
 * @tc.desc: TransProxyProcessResetMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyProcessResetMsgTest001, TestSize.Level1)
{
    ProxyMessage msg = {
        .msgHead.myId = TEST_CHANNEL_ID,
        .msgHead.peerId = TEST_CHANNEL_ID,
        .msgHead.cipher = 12
    };

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackIdentity).WillOnce(Return(SOFTBUS_OK));

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->myId = 1111;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    EXPECT_NO_THROW(TransProxyProcessResetMsg(&msg));

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransProxyProcessResetMsgTest002
 * @tc.desc: TransProxyProcessResetMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyProcessResetMsgTest002, TestSize.Level1)
{
    ProxyMessage msg = {
        .msgHead.myId = TEST_CHANNEL_ID,
        .msgHead.peerId = TEST_CHANNEL_ID,
        .msgHead.cipher = 40
    };

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyUnpackIdentity).WillOnce(Return(SOFTBUS_OK));

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->myId = TEST_CHANNEL_ID;
    proxyChannelInfo->reqId = 7788;
    proxyChannelInfo->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    proxyChannelInfo->appInfo.appType = APP_TYPE_AUTH;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    EXPECT_CALL(mock, GetAuthConnInfoByConnId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransReNegotiateSessionKey).WillOnce(Return(SOFTBUS_OK));

    EXPECT_NO_THROW(TransProxyProcessResetMsg(&msg));

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransProxyOnMessageReceivedTest001
 * @tc.desc: TransProxyOnMessageReceived
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyOnMessageReceivedTest001, TestSize.Level1)
{
    EXPECT_NO_THROW(TransProxyOnMessageReceived(nullptr));
}

/**
 * @tc.name: TransNotifySingleNetworkOffLineTest001
 * @tc.desc: TransNotifySingleNetworkOffLine
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransNotifySingleNetworkOffLineTest001, TestSize.Level1)
{
    LnnSingleNetworkOffLineEvent offLineinfo = {
        .basic = { LNN_EVENT_SINGLE_NETWORK_OFFLINE },
        .type = CONNECTION_ADDR_WLAN,
        .networkId = "hnfhwn8rt24380fp234gh3",
        .uuid = "1053",
        .udid = "45867891635"
    };
    const LnnEventBasicInfo *info = (const LnnEventBasicInfo *)(&offLineinfo);

    EXPECT_NO_THROW(TransNotifySingleNetworkOffLine(info));

    offLineinfo.type = CONNECTION_ADDR_BLE;
    EXPECT_NO_THROW(TransNotifySingleNetworkOffLine(info));

    offLineinfo.type = CONNECTION_ADDR_BR;
    EXPECT_NO_THROW(TransNotifySingleNetworkOffLine(info));

    offLineinfo.type = CONNECTION_ADDR_NCM;
    EXPECT_NO_THROW(TransNotifySingleNetworkOffLine(info));

    offLineinfo.type = CONNECTION_ADDR_SLE;
    EXPECT_NO_THROW(TransNotifySingleNetworkOffLine(info));
}

/**
 * @tc.name: TransNotifyOffLineTest001
 * @tc.desc: TransNotifyOffLine
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransNotifyOffLineTest001, TestSize.Level1)
{
    LnnOnlineStateEventInfo  onlineStateInfo = {
        .basic = { LNN_EVENT_NODE_ONLINE_STATE_CHANGED },
        .isOnline = true,
        .networkId = "nfhbawhfowgwqows",
        .uuid = "5301",
        .udid = "11258796334"
    };
    const LnnEventBasicInfo *info = (const LnnEventBasicInfo *)(&onlineStateInfo);

    EXPECT_NO_FATAL_FAILURE(TransNotifyOffLine(info));

    onlineStateInfo.isOnline = false;
    EXPECT_NO_FATAL_FAILURE(TransNotifyOffLine(info));
}

int32_t OnChannelOpenedTest(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    return SOFTBUS_OK;
}

/**
 * @tc.name: TransProxyManagerInitTest001
 * @tc.desc: TransProxyManagerInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyManagerInitTest001, TestSize.Level1)
{
    IServerChannelCallBack callBack;
    callBack.OnChannelOpened = OnChannelOpenedTest;

    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransProxyTransInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RegisterTimeoutCallback).WillOnce(Return(SOFTBUS_TRANS_ASYNC_SEND_TIMEOUT));

    int32_t ret = TransProxyManagerInit(&callBack);
    EXPECT_EQ(ret, SOFTBUS_TRANS_ASYNC_SEND_TIMEOUT);
}

/**
 * @tc.name: TransProxyResetReplyCntTest001
 * @tc.desc: TransProxyResetReplyCnt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyResetReplyCntTest001, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;

    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t ret = TransProxyResetReplyCnt(TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransProxyResetReplyCntTest002
 * @tc.desc: TransProxyResetReplyCnt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransProxyResetReplyCntTest002, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = 2588;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t ret = TransProxyResetReplyCnt(TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyCheckCollabResultTest001
 * @tc.desc: TransDealProxyCheckCollabResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyCheckCollabResultTest001, TestSize.Level1)
{
    int32_t dmsPid = 6666;
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransGetPidAndPkgName).WillRepeatedly(DoAll(SetArgPointee<2>(dmsPid), Return(SOFTBUS_OK)));

    int32_t ret = TransDealProxyCheckCollabResult(TEST_CHANNEL_ID, SOFTBUS_OK, TEST_CALLING_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);
}

/**
 * @tc.name: TransDealProxyCheckCollabResultTest002
 * @tc.desc: TransDealProxyCheckCollabResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyCheckCollabResultTest002, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = 1096;
    proxyChannelInfo->appInfo.myData.pid = 555;
    proxyChannelInfo->appInfo.myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t dmsPid = TEST_CALLING_PID;
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransGetPidAndPkgName).WillRepeatedly(DoAll(SetArgPointee<2>(dmsPid), Return(SOFTBUS_OK)));

    int32_t ret = TransDealProxyCheckCollabResult(TEST_CHANNEL_ID, SOFTBUS_OK, TEST_CALLING_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyCheckCollabResultTest003
 * @tc.desc: TransDealProxyCheckCollabResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyCheckCollabResultTest003, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;
    proxyChannelInfo->appInfo.myData.pid = 888;
    proxyChannelInfo->appInfo.myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t dmsPid = TEST_CALLING_PID;
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransGetPidAndPkgName).WillRepeatedly(DoAll(SetArgPointee<2>(dmsPid), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, TransCheckChannelOpenRemoveFromLooper).Times(1);

    EXPECT_CALL(mock, OnProxyChannelOpened).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransDealProxyCheckCollabResult(TEST_CHANNEL_ID, SOFTBUS_OK, TEST_CALLING_PID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
}

/**
 * @tc.name: TransDealProxyCheckCollabResultTest004
 * @tc.desc: TransDealProxyCheckCollabResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyCheckCollabResultTest004, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;
    proxyChannelInfo->appInfo.myData.pid = 888;
    proxyChannelInfo->appInfo.myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t dmsPid = TEST_CALLING_PID;
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransGetPidAndPkgName).WillRepeatedly(DoAll(SetArgPointee<2>(dmsPid), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, TransCheckChannelOpenRemoveFromLooper).Times(1);

    int32_t ret = TransDealProxyCheckCollabResult(TEST_CHANNEL_ID, SOFTBUS_TRANS_NODE_NOT_FOUND, TEST_CALLING_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
}

/**
 * @tc.name: TransDealProxyCheckCollabResultTest005
 * @tc.desc: TransDealProxyCheckCollabResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransDealProxyCheckCollabResultTest005, TestSize.Level1)
{
    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->channelId = TEST_CHANNEL_ID;
    proxyChannelInfo->appInfo.myData.pid = 888;
    proxyChannelInfo->appInfo.myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;

    ListAdd(&g_proxyChannelList->list, &(proxyChannelInfo->node));

    int32_t dmsPid = TEST_CALLING_PID;
    SoftbusTransProxyChannelManagerMock mock;
    EXPECT_CALL(mock, TransGetPidAndPkgName).WillRepeatedly(DoAll(SetArgPointee<2>(dmsPid), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, TransCheckChannelOpenRemoveFromLooper).Times(1);

    EXPECT_CALL(mock, OnProxyChannelOpened).WillOnce(Return(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE));
    EXPECT_CALL(mock, TransProxyAckHandshake).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransDealProxyCheckCollabResult(TEST_CHANNEL_ID, SOFTBUS_OK, TEST_CALLING_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE);
}

} // namespace OHOS