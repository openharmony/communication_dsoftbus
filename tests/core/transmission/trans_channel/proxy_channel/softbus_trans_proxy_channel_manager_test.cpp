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

#include "gtest/gtest.h"
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

static SoftBusList *g_proxyChannelList = nullptr;

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
    msg.dateLen = strlen(msg.data);
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
    msg.dateLen = strlen(msg.data);

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
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE);
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
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    chan.appInfo.appType = APP_TYPE_AUTH;
    msg.msgHead.cipher = 9;
    EXPECT_CALL(mock, CheckSessionNameValidOnAuthChannel(_)).WillOnce(Return(true));
    EXPECT_CALL(mock, ConnGetConnectionInfo(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnGetTypeByConnectionId(_, _)).WillOnce(Return(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT));

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
    EXPECT_CALL(mock, TransProxyUnpackHandshakeMsg(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.appInfo.callingTokenId = 1;
    msg.msgHead.cipher = 9;
    EXPECT_CALL(mock, ConnGetConnectionInfo(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnGetTypeByConnectionId(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransCheckServerAccessControl(_)).WillOnce(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = TransProxyFillChannelInfo(&msg, &chan);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_ACL_FAILED);
}

/**
 * @tc.name: TransNotifyUserSwitchTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransProxyChannelManagerTest, TransNotifyUserSwitchTest001, TestSize.Level0)
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
} // namespace OHOS