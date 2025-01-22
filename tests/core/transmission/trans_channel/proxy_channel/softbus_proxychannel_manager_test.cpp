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
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_proxychannel_transceiver.c"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
#define TEST_VALID_CHANNEL_ID 1
#define TEST_INVALID_CHANNEL_ID (-1)
#define TEST_VALID_CONN_ID 1
#define TEST_INVALID_CONN_ID (-1)
#define TEST_VALID_SEQ 1
#define TEST_INVALID_SEQ (-1)
#define TEST_VALID_REQ 1
#define TEST_INVALID_REQ (-1)
#define TEST_VALID_AUTH_ID 1
#define TEST_INVALID_AUTH_ID (-1)
#define TEST_TIMEOUT 5
#define TEST_SLEEP_TIME 5000
#define TEST_ARR_INIT 0
#define TEST_FAST_DATA_SIZE 10

static int32_t m_testProxyAuthChannelId = -1;
static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;
static bool g_testNetworkChannelOpenFailFlag = false;

class SoftbusProxyChannelManagerTest : public testing::Test {
public:
    SoftbusProxyChannelManagerTest()
    {}
    ~SoftbusProxyChannelManagerTest()
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

void TestOnNetworkingChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    g_testNetworkChannelOpenFailFlag = true;
    return;
}

void SoftbusProxyChannelManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

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

void SoftbusProxyChannelManagerTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

static ProxyChannelInfo *BuildProxyChannelInfo(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        return nullptr;
    }
    chan->authHandle.authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    return chan;
}

void TestTransProxyAddAuthChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = BuildProxyChannelInfo(channelId, identity, status);
    ASSERT_TRUE(chan != nullptr);
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TestTransProxyAddNormalChannel(int32_t channelId, const char *identity, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = BuildProxyChannelInfo(channelId, identity, status);
    ASSERT_TRUE(chan != nullptr);
    appInfo.appType = APP_TYPE_NORMAL;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**@
 * @tc.name: TransProxyOpenProxyChannelTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid parameters.
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CREATE_CHANNEL_FAILED when given invalid channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOpenProxyChannelTest001, TestSize.Level1)
{
    AppInfo appInfo;
    ConnectOption connInfo;
    int32_t channelId = TEST_NUMBER_VALID;

    SoftBusList *list = GetProxyChannelMgrHead();
    ASSERT_TRUE(nullptr != list);

    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
    int32_t ret = GetProxyChannelLock();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ReleaseProxyChannelLock();

    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(nullptr != g_proxyChannelList);
    ret = GetProxyChannelLock();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ReleaseProxyChannelLock();

    ret = TransProxyOpenProxyChannel(NULL, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, NULL, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    connInfo.type = CONNECT_BLE_DIRECT;
    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);

    connInfo.type = CONNECT_BLE;
    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);

    connInfo.type = CONNECT_BR;
    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);

    connInfo.type = CONNECT_TCP;
    ret = TransProxyOpenProxyChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransProxyGetNewChanSeqTest001
 * @tc.desc: test proxy get new chan seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetNewChanSeqTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_TEN;
    int32_t ret = TransProxyGetNewChanSeq(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyGetNewChanSeq(TEST_NUMBER_VALID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetNewChanSeqTest002
 * @tc.desc: test proxy get new chan seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetNewChanSeqTest002, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->seq = TEST_VALID_SEQ;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyGetNewChanSeq(TEST_VALID_CHANNEL_ID);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**
  * @tc.name: TransProxyKeepAlvieChanTest001
  * @tc.desc: test trans proxy get new chanseq.
  * @tc.type: FUNC
  * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyKeepAlvieChanTest001, TestSize.Level1)
{
    uint32_t connId = TEST_NUMBER_VALID;
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chanInfo->channelId = TEST_NUMBER_TEN;
    chanInfo->peerId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyKeepAliveChan(chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chanInfo->peerId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyKeepAliveChan(chanInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    TransProxyDelByConnId(connId);
    SoftBusFree(chanInfo);
}

/**
 * @tc.name: TransProxyGetAuthIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAuthIdTest001, TestSize.Level1)
{
    AuthHandle authHandle = { 0 };
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t ret = TransProxyGetAuthId(channelId, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAuthId(channelId, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxyGetAuthIdTest002
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAuthIdTest002, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->seq = TEST_VALID_SEQ;
    chan->connId = TEST_VALID_CONN_ID;
    AuthHandle authHandle = { 0 };
    authHandle.authId = TEST_VALID_AUTH_ID;
    chan->authHandle = authHandle;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    AuthHandle *handle = reinterpret_cast<AuthHandle *>(SoftBusCalloc(sizeof(AuthHandle)));
    int32_t channelId = TEST_VALID_CHANNEL_ID;
    ret = TransProxyGetAuthId(channelId, handle);
    EXPECT_EQ(TEST_VALID_AUTH_ID, handle->authId);
    SoftBusFree(handle);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**
 * @tc.name: TransProxyGetNameByChanIdTest001
 * @tc.desc: test proxy get auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetNameByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    char pkgName[PKG_NAME_SIZE_MAX] = {TEST_NUMBER_ZERO};
    char sessionName[SESSION_NAME_SIZE_MAX] = {TEST_NUMBER_ZERO};
    uint16_t pkgLen = PKG_NAME_SIZE_MAX;
    uint16_t sessionLen = SESSION_NAME_SIZE_MAX;
    int32_t ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyGetNameByChanId(channelId, nullptr, sessionName, pkgLen, sessionLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGetNameByChanId(channelId, pkgName, nullptr, pkgLen, sessionLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = TEST_NUMBER_TEN;
    ret = TransProxyGetNameByChanId(channelId, pkgName, sessionName, pkgLen, sessionLen);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest001
 * @tc.desc: test proxy get session key by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSessionKeyByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    char sessionKey[SESSION_KEY_LENGTH]= {TEST_NUMBER_ZERO};
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;
    int32_t ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest002
 * @tc.desc: test trans proxy check apptype and msghead.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSessionKeyByChanIdTest002, TestSize.Level1)
{
    int32_t channelId;
    char *sessionKey = NULL;
    uint32_t sessionKeySize = SESSIONKEYSIZE;

    channelId = TEST_MESSAGE_CHANNEL_ID;
    int32_t ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest003
 * @tc.desc: test trans proxy get sessionkey by channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSessionKeyByChanIdTest003, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->timeout = TEST_TIMEOUT;
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;

    ret = TransProxyGetSessionKeyByChanId(TEST_VALID_CHANNEL_ID, sessionKey, sessionKeySize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**
 * @tc.name: TransProxyGetAppInfoByChanIdTest001
 * @tc.desc: test proxy get app info by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAppInfoByChanIdTest001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t channelId = TEST_NUMBER_VALID;

    int32_t ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetAppInfoByChanIdTest002
  * @tc.desc: test proxy get appinfo by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAppInfoByChanIdTest002, TestSize.Level1)
{
    int32_t chanId = TEST_MESSAGE_CHANNEL_VALID_ID;
    AppInfo* appInfo = NULL;

    int32_t ret = TransProxyGetAppInfoByChanId(chanId, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    chanId = TEST_MESSAGE_CHANNEL_ID;
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetConnIdByChanIdTest001
 * @tc.desc: test proxy get conn id by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnIdByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t connId = TEST_NUMBER_VALID;

    int32_t ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = TEST_NUMBER_TEN;
    ret = TransProxyGetConnIdByChanId(channelId, &connId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetConnIdByChanIdTest002
  * @tc.desc: test proxy get connid by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnIdByChanIdTest002, TestSize.Level1)
{
    int32_t channelId = TEST_MESSAGE_CHANNEL_ID;
    int32_t* connId = NULL;

    int32_t ret = TransProxyGetConnIdByChanId(channelId, connId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetConnIdByChanIdTest003
 * @tc.desc: test proxy get connid by chanid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnIdByChanIdTest003, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    int32_t connId = TEST_VALID_CONN_ID;
    ret = TransProxyGetConnIdByChanId(TEST_INVALID_CHANNEL_ID, &connId);
    EXPECT_NE(SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID, ret);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**
 * @tc.name: TransProxyGetConnOptionByChanIdTest001
 * @tc.desc: test proxy get cpnn option by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnOptionByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    ConnectOption connOpt;
    AppInfo appInfo;

    int32_t ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authHandle.authId = TEST_NUMBER_TWENTY;
    chan->connId = TEST_NUMBER_TWENTY;
    chan->reqId = TEST_NUMBER_TWENTY;
    chan->channelId = TEST_NUMBER_TWENTY;
    chan->seq = TEST_NUMBER_TWENTY;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;

    ret = TransProxyGetConnOptionByChanId(chan->channelId, &connOpt);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransProxyDelChanByChanId(TEST_NUMBER_TWENTY);
}

/**
  * @tc.name: TransProxyGetConnOptionByChanIdTest002
  * @tc.desc: test proxy get connoption by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetConnOptionByChanIdTest002, TestSize.Level1)
{
    int32_t channelId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ConnectOption* connOpt = NULL;

    int32_t ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    connOpt = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    channelId = TEST_MESSAGE_CHANNEL_ID;
    ret = TransProxyGetConnOptionByChanId(channelId, connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxyGetSendMsgChanInfoTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetSendMsgChanInfoTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    ProxyChannelInfo chanInfo;

    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    channelId = m_testProxyAuthChannelId;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyChanProcessByReqIdTest001
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyChanProcessByReqIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_25;
    uint32_t connId = TEST_NUMBER_TEN;
    char identity[TEST_ARRRY_SIZE] = {0};
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = strcpy_s(identity, TEST_CHANNEL_IDENTITY_LEN, TEST_STRING_ELEVEN);
    if (ret != EOK) {
        TRANS_LOGE(TRANS_TEST, "copy failed");
        return;
    }
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    TransProxyChanProcessByReqId(TEST_NUMBER_26, connId, errCode);
    usleep(TEST_SLEEP_TIME);
    ProxyChannelInfo chanInfo;
    ret = TransProxyGetSendMsgChanInfo(TEST_NUMBER_25, &chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(PROXY_CHANNEL_STATUS_HANDSHAKEING != (uint32_t)chanInfo.status);
}

/**
 * @tc.name: TransProxyChanProcessByReqIdTest002
 * @tc.desc: test proxy get sendmsg chanInfo by chanId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyChanProcessByReqIdTest002, TestSize.Level1)
{
    int32_t ret = TransProxyLoopInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_VALID_CHANNEL_ID;
    uint32_t connId = TEST_VALID_CONN_ID;
    int32_t errCode = SOFTBUS_OK;
    char identity[TEST_ARRRY_SIZE] = { TEST_ARR_INIT };
    (void)strcpy_s(identity, TEST_CHANNEL_IDENTITY_LEN, TEST_STRING_ELEVEN);
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_PYH_CONNECTING);
    TransProxyChanProcessByReqId(TEST_VALID_CHANNEL_ID, connId, errCode);
    usleep(TEST_SLEEP_TIME);
    ProxyChannelInfo chanInfo;
    ret = TransProxyGetSendMsgChanInfo(TEST_VALID_CHANNEL_ID, &chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest001
 * @tc.desc: test proxy received handshake message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOnMessageReceivedTest001, TestSize.Level1)
{
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyMessage msg;

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    (void)strcpy_s(info.appInfo.peerData.sessionName, SESSIONKEYSIZE, TEST_AUTHSESSION);
    msg.data = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.connId = TEST_NUMBER_ELEVEN;
    msg.msgHead.myId = TEST_NUMBER_ELEVEN;
    msg.msgHead.peerId = TEST_NUMBER_ELEVEN;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest002
 * @tc.desc: test proxy received handshake ack message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOnMessageReceivedTest002, TestSize.Level1)
{
    ProxyMessage msg;

    g_testProxyChannelOpenSuccessFlag = false;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE_ACK;
    msg.data = TransProxyPackHandshakeErrMsg(SOFTBUS_INVALID_PARAM);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;

    /* test receive errcode msg */
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);

    /* test receive normal msg */
    g_testProxyChannelOpenSuccessFlag = false;
    ProxyChannelInfo chan;
    chan.appInfo.appType = APP_TYPE_AUTH;
    string identity = TEST_STRING_TEN;
    (void)strcpy_s(chan.identity, TEST_CHANNEL_IDENTITY_LEN, identity.c_str());
    msg.data = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg.data);

    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.msgHead.myId = TEST_NUMBER_TEN;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelOpenSuccessFlag);
}


/**@
 * @tc.name: TransProxyOnMessageReceivedTest003
 * @tc.desc: test proxy received reset message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOnMessageReceivedTest003, TestSize.Level1)
{
    ProxyMessage msg;
    const char *identity = TEST_STRING_ELEVEN;
    msg.data = TransProxyPackIdentity(identity);
    ASSERT_TRUE(NULL != msg.data);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;
    msg.connId = TEST_NUMBER_VALID;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_RESET;
    /* test no compare channel */
    msg.msgHead.myId = TEST_NUMBER_VALID;
    msg.msgHead.peerId = TEST_NUMBER_VALID;
    g_testProxyChannelClosedFlag = false;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelClosedFlag);

    TestTransProxyAddAuthChannel(TEST_RESET_MESSAGE_CHANNEL_ID, identity, PROXY_CHANNEL_STATUS_COMPLETED);
    g_testProxyChannelClosedFlag = false;
    g_testProxyChannelOpenFailFlag = false;
    msg.msgHead.myId = TEST_RESET_MESSAGE_CHANNEL_ID;
    msg.msgHead.peerId = TEST_RESET_MESSAGE_CHANNEL_ID;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelClosedFlag || g_testProxyChannelOpenFailFlag);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest004
 * @tc.desc: test proxy received  keepalive message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOnMessageReceivedTest004, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 15;
    ProxyMessage msg;
    msg.msgHead.myId = channelId;
    msg.msgHead.peerId = channelId;
    const char *identity = TEST_STRING_ELEVEN;
    TestTransProxyAddAuthChannel(channelId, identity, PROXY_CHANNEL_STATUS_KEEPLIVEING);
    msg.data = TransProxyPackIdentity(identity);
    msg.dateLen = strlen(msg.data) + TEST_NUMBER_ONE;

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE;
    TransProxyOnMessageReceived(&msg);

    ProxyChannelInfo chanInfo;
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);

    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_KEEPALIVE_ACK;
    TransProxyOnMessageReceived(&msg);
    ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(PROXY_CHANNEL_STATUS_COMPLETED, chanInfo.status);
}

/**@
 * @tc.name: TransProxyOnMessageReceivedTest005
 * @tc.desc: test proxy received normal message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOnMessageReceivedTest005, TestSize.Level1)
{
    ProxyMessage msg;
    msg.msgHead.type = PROXYCHANNEL_MSG_TYPE_NORMAL;

    msg.msgHead.myId = TEST_NUMBER_VALID;
    msg.msgHead.peerId = TEST_NUMBER_VALID;
    g_testProxyChannelReceiveFlag = false;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    msg.msgHead.myId = TEST_NUMBER_TEN;
    msg.msgHead.peerId = TEST_NUMBER_TEN;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);

    g_testProxyChannelReceiveFlag = false;
    msg.msgHead.myId = TEST_NUMBER_ELEVEN;
    msg.msgHead.peerId = TEST_NUMBER_ELEVEN;
    TransProxyOnMessageReceived(&msg);
    EXPECT_FALSE(g_testProxyChannelReceiveFlag);
}

/**@
 * @tc.name: TransProxyCloseProxyChannelTest001
 * @tc.desc: test proxy close proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyCloseProxyChannelTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_VALID;
    int32_t ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    TestTransProxyAddAuthChannel(29, TEST_STRING_ELEVEN, PROXY_CHANNEL_STATUS_COMPLETED);

    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyCloseProxyChannelTest002
  * @tc.desc: test trans proxy close proxychannel.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyCloseProxyChannelTest002, TestSize.Level1)
{
    int32_t channelId = TEST_MESSAGE_CHANNEL_VALID_ID;

    TransProxyOpenProxyChannelSuccess(channelId);

    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    msg->msgHead.cipher = TEST_NUMBER_ONE;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    TransProxyProcessDataRecv(msg);
    TransProxyProcessKeepAliveAck(msg);
    TransProxyProcessKeepAlive(msg);
    TransProxyProcessHandshakeAuthMsg(msg);

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    TransProxyFastDataRecv(chan);

    TransProxyProcessResetMsg(msg);

    int32_t ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);

    channelId = TEST_MESSAGE_CHANNEL_ID;
    ret = TransProxyCloseProxyChannel(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyFastDataRecvTest001
 * @tc.desc: test proxy fastdata recv.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyFastDataRecvTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    chan->appInfo.routeType = WIFI_STA;

    TransProxyFastDataRecv(chan);
    SoftBusFree(chan);
}

/**@
 * @tc.name: ReleaseChannelInfoTest001
 * @tc.desc: test release channelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, ReleaseChannelInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    ReleaseChannelInfo(nullptr);

    chan->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan->appInfo.fastTransDataSize)));
    ASSERT_TRUE(nullptr != chan->appInfo.fastTransData);
    ReleaseChannelInfo(chan);
}

/**@
 * @tc.name: TransProxyProcessHandshakeMsgTest001
 * @tc.desc: test trans proxy process handshake msg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyProcessHandshakeMsgTest001, TestSize.Level1)
{
    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    TransProxyProcessHandshakeMsg(nullptr);
    msg->connId = TEST_VALID_CONN_ID;
    msg->msgHead.cipher = TEST_VALID_CHANNEL_ID;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    TransProxyProcessHandshakeMsg(msg);
    SoftBusFree(msg);
}

/**@
 * @tc.name: TransGetRemoteDeviceIdByReqIdTest001
 * @tc.desc: test trans get remote deviceId by reqId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransGetRemoteDeviceIdByReqIdTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->reqId = TEST_VALID_REQ;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
    char peerNetworkId[TEST_ARRRY_SIZE] = { TEST_ARR_INIT };

    ret = TransGetRemoteDeviceIdByReqId(TEST_INVALID_REQ, peerNetworkId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**@
 * @tc.name: TransProxyProcessReNegotiateMsgTest001
 * @tc.desc: test trans proxy process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyProcessReNegotiateMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan->appInfo.fastTransDataSize)));
    ASSERT_TRUE(nullptr != chan->appInfo.fastTransData);

    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    msg->msgHead.cipher = TEST_VALID_CHANNEL_ID;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);

    int32_t ret = TransProxyProcessReNegotiateMsg(msg, chan);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
    ReleaseChannelInfo(chan);
    SoftBusFree(msg);
}

/**@
 * @tc.name: TransProxyProcessResetMsgHelperTest001
 * @tc.desc: test trans proxy process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyProcessResetMsgHelperTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan->appInfo.fastTransDataSize)));
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    ASSERT_TRUE(nullptr != chan->appInfo.fastTransData);

    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    msg->msgHead.cipher = TEST_VALID_CHANNEL_ID;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);

    TransProxyProcessResetMsgHelper(chan, msg);
    ReleaseChannelInfo(chan);
    SoftBusFree(msg);
}

/**@
 * @tc.name: TransProxyNegoSessionKeySuccTest001
 * @tc.desc: test trans proxy process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyNegoSessionKeySuccTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->reqId = TEST_VALID_REQ;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyNegoSessionKeySucc(TEST_VALID_CHANNEL_ID);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**@
 * @tc.name: TransProxyNegoSessionKeyFailTest001
 * @tc.desc: test trans proxy process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyNegoSessionKeyFailTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->reqId = TEST_VALID_REQ;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyNegoSessionKeyFail(TEST_VALID_CHANNEL_ID, SOFTBUS_OK);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**@
 * @tc.name: TransProxyOpenProxyChannelSuccessTest001
 * @tc.desc: test trans proxy process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyOpenProxyChannelSuccessTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->reqId = TEST_VALID_REQ;
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyOpenProxyChannelSuccess(TEST_VALID_CHANNEL_ID);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**@
 * @tc.name: TransProxyTimerItemProcTest001
 * @tc.desc: test trans proxy timer item proc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyTimerItemProcTest001, TestSize.Level1)
{
    ListNode proxyProcList;
    ListInit(&proxyProcList);

    ProxyChannelInfo *chan1 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan1);
    chan1->channelId = TEST_VALID_CHANNEL_ID;
    chan1->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan1->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan1->appInfo.fastTransDataSize)));
    chan1->status = PROXY_CHANNEL_STATUS_HANDSHAKE_TIMEOUT;
    ASSERT_TRUE(nullptr != chan1->appInfo.fastTransData);
    ListAdd(&proxyProcList, &chan1->node);

    ProxyChannelInfo *chan2 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan2);
    chan2->channelId = TEST_VALID_CHANNEL_ID;
    chan2->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan2->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan2->appInfo.fastTransDataSize)));
    chan2->status = PROXY_CHANNEL_STATUS_CONNECTING_TIMEOUT;
    ASSERT_TRUE(nullptr != chan2->appInfo.fastTransData);
    ListAdd(&proxyProcList, &chan2->node);

    ProxyChannelInfo *chan3 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan3);
    chan3->channelId = TEST_VALID_CHANNEL_ID;
    chan3->appInfo.fastTransDataSize = TEST_FAST_DATA_SIZE;
    chan3->appInfo.fastTransData = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(chan3->appInfo.fastTransDataSize)));
    chan3->status = PROXY_CHANNEL_STATUS_TIMEOUT;
    ASSERT_TRUE(nullptr != chan3->appInfo.fastTransData);
    ListAdd(&proxyProcList, &chan3->node);

    TransProxyTimerItemProc(&proxyProcList);
    TransProxyTimerProc();
    ListDelInit(&proxyProcList);
}

/**@
 * @tc.name: TransNotifySingleNetworkOffLineTest001
 * @tc.desc: test trans notfiy single network offline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransNotifySingleNetworkOffLineTest001, TestSize.Level1)
{
    LnnEventBasicInfo *info = reinterpret_cast<LnnEventBasicInfo *>(SoftBusCalloc(sizeof(LnnEventBasicInfo)));
    ASSERT_TRUE(nullptr != info);
    info->event = LNN_EVENT_IP_ADDR_CHANGED;
    TransNotifySingleNetworkOffLine(info);
    info->event = LNN_EVENT_WIFI_STATE_CHANGED;
    TransNotifySingleNetworkOffLine(info);
    info->event = LNN_EVENT_BT_STATE_CHANGED;
    TransNotifySingleNetworkOffLine(info);
    SoftBusFree(info);
}

/**@
 * @tc.name: TransNotifyOffLineTest001
 * @tc.desc: test trans notify offline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransNotifyOffLineTest001, TestSize.Level1)
{
    LnnEventBasicInfo *info = reinterpret_cast<LnnEventBasicInfo *>(SoftBusCalloc(sizeof(LnnEventBasicInfo)));
    ASSERT_TRUE(nullptr != info);
    info->event = LNN_EVENT_NODE_MIGRATE;
    TransNotifyOffLine(info);
    SoftBusFree(info);
}

/**@
 * @tc.name: TransProxyCloseProxyOtherResTest001
 * @tc.desc: test trans proxy close proxy other res
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyCloseProxyOtherResTest001, TestSize.Level1)
{
    int32_t ret = TransProxyLoopInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    int32_t channelId = TEST_VALID_CHANNEL_ID;
    chan->channelId = TEST_VALID_CHANNEL_ID;

    TransProxyCloseProxyOtherRes(channelId, chan);
}

/**@
 * @tc.name: TransProxyReleaseChannelListTest001
 * @tc.desc: test trans proxy timer item proc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyReleaseChannelListTest001, TestSize.Level1)
{
    int32_t ret = TransProxyLoopInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListNode proxyChannelList;
    ListInit(&proxyChannelList);

    ProxyChannelInfo *chan1 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan1);
    chan1->channelId = TEST_VALID_CHANNEL_ID;
    chan1->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    ListAdd(&proxyChannelList, &chan1->node);

    ProxyChannelInfo *chan2 = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan2);
    chan2->channelId = TEST_VALID_CHANNEL_ID;
    chan2->status = PROXY_CHANNEL_STATUS_COMPLETED;
    ListAdd(&proxyChannelList, &chan2->node);

    TransProxyReleaseChannelList(&proxyChannelList, SOFTBUS_TRANS_PROXY_DISCONNECTED);
}

/**@
 * @tc.name: TransProxyDelChanByChanIdTest001
 * @tc.desc: test proxy del proxy channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelChanByChanIdTest001, TestSize.Level1)
{
    TransProxyDelChanByChanId(TEST_NUMBER_VALID);

    TransProxyDelChanByChanId(m_testProxyAuthChannelId);
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(m_testProxyAuthChannelId, &chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelChanByReqIdTest001
 * @tc.desc: test proxy del proxy channel by reqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelChanByReqIdTest001, TestSize.Level1)
{
    TransProxyDelChanByReqId(TEST_NUMBER_VALID, TEST_NUMBER_ONE);

    int32_t channelId = TEST_NUMBER_25;
    ProxyChannelInfo chanInfo;
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelChanByReqIdTest002
 * @tc.desc: test trans proxy del chan by reqId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelChanByReqIdTest002, TestSize.Level1)
{
    int32_t ret = TransProxyLoopInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    TransProxyAddChanItem(chan);

    TransProxyDelChanByReqId(TEST_VALID_REQ, SOFTBUS_OK);
    TransProxyDelChanByChanId(TEST_VALID_CHANNEL_ID);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest001
 * @tc.desc: test proxy del proxy channel by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest001, TestSize.Level1)
{
    TransProxyDelByConnId(TEST_NUMBER_VALID);
    ProxyChannelInfo chan;
    int32_t channelId = TEST_BUF_LEN;
    usleep(TEST_NUMBER_5000);
    int32_t ret = TransProxyGetSendMsgChanInfo(channelId, &chan);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyDelByConnIdTest002
  * @tc.desc: test trans proxy get new chanseq.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest002, TestSize.Level1)
{
    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    chanInfo->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chanInfo->peerId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyKeepAliveChan(chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    chanInfo->peerId = TEST_MESSAGE_CHANNEL_VALID_ID;
    ret = TransProxyKeepAliveChan(chanInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(chanInfo);
}

/**@
 * @tc.name: TransProxyDeathCallbackTest001
 * @tc.desc: test proxy TransProxyDeathCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDeathCallbackTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)strcpy_s(appInfo.myData.pkgName, TEST_PKG_NAME_LEN, TEST_PKGNAME);
    appInfo.appType = APP_TYPE_AUTH;
    appInfo.myData.pid = TEST_DEATH_CHANNEL_ID;
    // will free in TransProxyDeathCallback
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->channelId = TEST_DEATH_CHANNEL_ID;
    chan->connId = TEST_NUMBER_VALID;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;

    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);

    TransProxyDeathCallback(NULL, TEST_DEATH_CHANNEL_ID);
    TransProxyDeathCallback(TEST_PKGNAME, TEST_DEATH_CHANNEL_ID);

    ProxyChannelInfo *chanInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chanInfo);
    chanInfo->channelId = TEST_DEATH_CHANNEL_ID;
    chanInfo->connId = TEST_NUMBER_VALID;
    chanInfo->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;

    ret = TransProxyGetSendMsgChanInfo(chanInfo->channelId, chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(chanInfo);
}

/**
  * @tc.name: CheckAppTypeAndMsgHeadTest001
  * @tc.desc: test trans proxy check apptype and msghead.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, CheckAppTypeAndMsgHeadTest001, TestSize.Level1)
{
    ProxyMessageHead *msgHead = (ProxyMessageHead *)SoftBusCalloc(sizeof(ProxyMessageHead));
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));

    int32_t ret = CheckAppTypeAndMsgHead(msgHead, appInfo);

    msgHead->cipher = ENCRYPTED;
    appInfo->appType = APP_TYPE_AUTH;
    ret = CheckAppTypeAndMsgHead(msgHead, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    msg->msgHead.cipher = TEST_NUMBER_ONE;
    msg->msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    TransProxyProcessHandshakeAckMsg(msg);
    SoftBusFree(msgHead);
    SoftBusFree(appInfo);
    SoftBusFree(msg);
}

/**
  * @tc.name: TransProxyGetChanByReqId001
  * @tc.desc: test trans proxy get chan by reqid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetChanByReqIdTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = NULL;
    int32_t reqId = TEST_PARSE_MESSAGE_CHANNEL;

    int32_t ret = TransProxyGetChanByReqId(reqId, chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    reqId = TEST_MESSAGE_CHANNEL_VALID_ID;
    chan = NULL;
    ret = TransProxyGetChanByReqId(reqId, chan);
    EXPECT_EQ(NULL, chan);
}


/**
 * @tc.name: TransChanIsEqualTest001
 * @tc.desc: TransChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransChanIsEqualTest001, TestSize.Level1)
{
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = TEST_NUMBER_ZERO;
    info1.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);


    info2.myId = TEST_NUMBER_ZERO;
    info2.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    bool ret = ChanIsEqual(&info1, &info2);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: TransResetChanIsEqualTest001
 * @tc.desc: TransResetChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransResetChanIsEqualTest001, TestSize.Level1)
{
    int32_t status = TEST_NUMBER_THREE;
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = TEST_NUMBER_ZERO;
    info1.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = TEST_NUMBER_ZERO;
    info2.peerId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    bool ret = ResetChanIsEqual(PROXY_CHANNEL_STATUS_HANDSHAKEING, &info1, &info2);
    EXPECT_EQ(ret, true);
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_EQ(ret, true);

    info1.myId = TEST_NUMBER_TWO;
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_NE(true, ret);
}

/**
 * @tc.name: TransProxyUpdateAckInfoTest001
 * @tc.desc: TransProxyUpdateAckInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyUpdateAckInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo testInfo;

    testInfo.myId = TEST_NUMBER_ZERO;
    testInfo.peerId = TEST_NUMBER_ZERO;
    testInfo.appInfo.encrypt = TEST_NUMBER_TWO;
    testInfo.appInfo.algorithm = TEST_NUMBER_TWO;
    testInfo.appInfo.crc = TEST_NUMBER_TWO;
    (void)strcpy_s(testInfo.identity, sizeof(testInfo.identity), TEST_CHANNEL_INDENTITY);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = TEST_NUMBER_ZERO;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);

    int32_t ret = TransProxyUpdateAckInfo(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyUpdateAckInfo(&testInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest003
 * @tc.desc: test proxy del proxy channel by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest003, TestSize.Level1)
{
    int32_t channelId = 1;

    int32_t ret = TransRefreshProxyTimesNative(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->myId = 1;
    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransRefreshProxyTimesNative(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    LnnEventBasicInfo lnnInfo;
    TransWifiStateChange(NULL);
    TransWifiStateChange(&lnnInfo);
}

/**@
 * @tc.name: TransProxyDelByConnIdTest004
 * @tc.desc: test proxy del by connId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByConnIdTest004, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyDelByConnId(TEST_VALID_CONN_ID);
    TransProxyDelChanByChanId(TEST_PARSE_MESSAGE_CHANNEL);
}

/**@
 * @tc.name: TransProxyDelByChannelIdTest001
 * @tc.desc: test proxy del by channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByChannelIdTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_PARSE_MESSAGE_CHANNEL;

    ret = TransProxyDelByChannelId(channelId, chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyResetChanTest001
 * @tc.desc: test proxy reset chan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyResetChanTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    chan->myId = TEST_NUMBER_ZERO;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyChannelInfo *chanRes = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chanRes);
    chanRes->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chanRes->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    chanRes->myId = TEST_NUMBER_ZERO;

    ret = TransProxyResetChan(chanRes);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyDelChanByChanId(TEST_PARSE_MESSAGE_CHANNEL);
    SoftBusFree(chanRes);
}

/**@
 * @tc.name: TransProxyGetRecvMsgChanInfoTest001
 * @tc.desc: test proxy get recv msg chanInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetRecvMsgChanInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_COMPLETED;
    chan->myId = TEST_NUMBER_ZERO;
    chan->peerId = TEST_NUMBER_ONE;
    chan->connId = TEST_VALID_CONN_ID;
    chan->timeout = TEST_TIMEOUT;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyChannelInfo *chanRes = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chanRes);
    chanRes->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    ret = TransProxyGetRecvMsgChanInfo(TEST_NUMBER_ZERO, TEST_NUMBER_ONE, chanRes);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(PROXY_CHANNEL_STATUS_COMPLETED, chanRes->status);
    TransProxyDelChanByChanId(TEST_PARSE_MESSAGE_CHANNEL);
    SoftBusFree(chanRes);
}

/**@
 * @tc.name: TransProxyKeepAliveChanTest001
 * @tc.desc: test proxy get recv msg chanInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyKeepAliveChanTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    chan->myId = TEST_NUMBER_ZERO;
    chan->peerId = TEST_NUMBER_ONE;
    chan->connId = TEST_VALID_CONN_ID;
    chan->timeout = TEST_TIMEOUT;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ProxyChannelInfo *chanRes = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chanRes);
    chanRes->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    chanRes->myId = TEST_NUMBER_ZERO;
    chanRes->peerId = TEST_NUMBER_ONE;
    ret = TransProxyKeepAliveChan(chanRes);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(PROXY_CHANNEL_STATUS_COMPLETED, chanRes->status);
    TransProxyDelChanByChanId(TEST_PARSE_MESSAGE_CHANNEL);
    SoftBusFree(chanRes);
}

/**@
 * @tc.name: TransProxyDelByChannelIdTest004
 * @tc.desc: test proxy del by channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyDelByChannelIdTest004, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_PARSE_MESSAGE_CHANNEL;

    ret = TransProxyDelByChannelId(channelId, chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransChanIsEqualTest002
 * @tc.desc: TransChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransChanIsEqualTest002, TestSize.Level1)
{
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = 0;
    info1.peerId = 0;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = 0;
    info2.peerId = 0;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    bool ret = ChanIsEqual(&info1, &info2);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: TransResetChanIsEqualTest002
 * @tc.desc: TransResetChanIsEqualTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransResetChanIsEqualTest002, TestSize.Level1)
{
    int32_t status = 3;
    ProxyChannelInfo info1;
    ProxyChannelInfo info2;

    info1.myId = 0;
    info1.peerId = 0;
    (void)strcpy_s(info1.identity, sizeof(info1.identity), TEST_CHANNEL_INDENTITY);

    info2.myId = 0;
    info2.peerId = 0;
    (void)strcpy_s(info2.identity, sizeof(info2.identity), TEST_CHANNEL_INDENTITY);

    bool ret = ResetChanIsEqual(PROXY_CHANNEL_STATUS_HANDSHAKEING, &info1, &info2);
    EXPECT_EQ(ret, true);
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_EQ(ret, true);

    info1.myId = 2;
    ret = ResetChanIsEqual(status, &info1, &info2);
    EXPECT_NE(true, ret);
}

/**
 * @tc.name: TransProxyUpdateAckInfoTest002
 * @tc.desc: TransProxyUpdateAckInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyUpdateAckInfoTest002, TestSize.Level1)
{
    ProxyChannelInfo testInfo;

    testInfo.myId = 0;
    testInfo.peerId = 0;
    testInfo.appInfo.encrypt = 2;
    testInfo.appInfo.algorithm = 2;
    testInfo.appInfo.crc = 2;
    (void)strcpy_s(testInfo.identity, sizeof(testInfo.identity), TEST_CHANNEL_INDENTITY);

    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        return;
    }
    info->appInfo.appType = APP_TYPE_AUTH;
    info->myId = 0;
    (void)strcpy_s(info->identity, sizeof(info->identity), TEST_CHANNEL_INDENTITY);

    int32_t ret = TransProxyUpdateAckInfo(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyUpdateAckInfo(&testInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetLocalInfoTest001
 * @tc.desc: TransProxyGetLocalInfoTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetLocalInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    int32_t ret = TransProxyGetLocalInfo(chan);
    EXPECT_NE(SOFTBUS_OK, ret);

    chan->appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyGetLocalInfo(chan);
    EXPECT_NE(SOFTBUS_OK, ret);

    int16_t newChanId = 1;
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));

    info.type = CONNECT_TCP;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BR;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BLE;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);
    info.type = CONNECT_BLE_DIRECT;
    ConstructProxyChannelInfo(chan, msg, newChanId, &info);

    TransWifiOnLineProc(NULL);

    char network[TEST_NUMBER_TWENTY]  = { TEST_ARR_INIT };
    ret = strcpy_s(network, TEST_NUMBER_TWENTY, TEST_CHANNEL_INDENTITY);
    if (ret != EOK) {
        TRANS_LOGE(TRANS_TEST, "copy failed");
        return;
    }
    TransWifiOffLineProc(network);

    char networkId = 5;
    TransWifiOnLineProc(&networkId);
    TransWifiOffLineProc(&networkId);

    LnnEventBasicInfo lnnInfo;
    TransNotifyOffLine(NULL);
    TransNotifyOffLine(&lnnInfo);
}

/**
 * @tc.name: TransProxyGetAppInfoTypeTest001
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE when given invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetAppInfoTypeTest001, TestSize.Level1)
{
    int16_t myId = 1;
    const char *identity = "test";
    AppType appType;
    int32_t ret = TransProxyGetAppInfoType(myId, identity, &appType);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
}

/**
 * @tc.name: TransProxySpecialUpdateChanInfoTest001
 * @tc.desc: Should return SOFTBUS_TRANS_NODE_NOT_FOUND when given invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxySpecialUpdateChanInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo channelInfo;
    memset_s(&channelInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int32_t ret = TransProxySpecialUpdateChanInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelInfo.channelId = TEST_MESSAGE_CHANNEL_ID;
    channelInfo.reqId = -1;
    channelInfo.isServer = -1;
    channelInfo.type = CONNECT_BR;
    channelInfo.status = -1;
    channelInfo.status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    channelInfo.connId = 1;
    ret = TransProxySpecialUpdateChanInfo(&channelInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    channelInfo.type = CONNECT_TYPE_MAX;
    ret = TransProxySpecialUpdateChanInfo(&channelInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxySpecialUpdateChanInfoTest002
 * @tc.desc: Should return SOFTBUS_TRANS_NODE_NOT_FOUND when given invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxySpecialUpdateChanInfoTest002, TestSize.Level1)
{
    ProxyChannelInfo channelInfo;
    (void)memset_s(&channelInfo, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int32_t ret = TransProxySpecialUpdateChanInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelInfo.channelId = TEST_VALID_CHANNEL_ID;
    channelInfo.reqId = 1;
    channelInfo.isServer = 1;
    channelInfo.type = CONNECT_BR;
    channelInfo.status = -1;
    channelInfo.status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
    channelInfo.connId = 1;
    channelInfo.type = CONNECT_TYPE_MAX;
    ret = TransProxySpecialUpdateChanInfo(&channelInfo);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxyGetChanByChanIdTest001
 * @tc.desc: Should return SOFTBUS_TRANS_NODE_NOT_FOUND when given invalid parameters.
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null channelInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetChanByChanIdTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int32_t chanId = 1;
    int32_t ret = TransProxyGetChanByChanId(chanId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGetChanByChanId(chanId, &chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxyProcessDataConfigTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null appInfo.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyProcessDataConfigTest001, TestSize.Level1)
{
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransProxyProcessDataConfig(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    appInfo.peerData.dataConfig = 2;
    appInfo.myData.dataConfig = 1;
    ret = TransProxyProcessDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo.peerData.dataConfig = 0;
    ret = TransProxyProcessDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyProcessDataConfigTest002
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null appInfo.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyProcessDataConfigTest002, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    appInfo.peerData.dataConfig = 2;
    appInfo.myData.dataConfig = 1;
    int32_t ret = TransProxyProcessDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyFillDataConfigTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null appInfo.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyFillDataConfigTest001, TestSize.Level1)
{
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = APP_TYPE_AUTH;
    int32_t ret = TransProxyFillDataConfig(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    appInfo.peerData.dataConfig = 2;
    appInfo.myData.dataConfig = 1;
    ret = TransProxyFillDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo.peerData.dataConfig = 0;
    ret = TransProxyFillDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyFillDataConfigTest002
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null appInfo.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyFillDataConfigTest002, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.appType = APP_TYPE_AUTH;
    appInfo.businessType = BUSINESS_TYPE_FILE;
    appInfo.peerData.dataConfig = 2;
    appInfo.myData.dataConfig = 1;
    int32_t ret = TransProxyFillDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo.peerData.dataConfig = 0;
    int32_t errorCode = SOFTBUS_OK;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(nullptr != chan);
    TransProxyReportAuditEvent(chan, AUDIT_EVENT_PACKETS_ERROR, errorCode);
    ret = TransProxyFillDataConfig(&appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyFillChannelInfoTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null appInfo.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyFillChannelInfoTest001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    chan->appInfo.appType = APP_TYPE_NORMAL;
    chan->appInfo.callingTokenId = TOKENID_NOT_SET;
    msg->data = TransProxyPackHandshakeMsg(chan);
    msg->dateLen = strlen(msg->data) + 1;

    int32_t ret = TransProxyFillChannelInfo(msg, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyFillChannelInfo(msg, chan);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
    msg->msgHead.type = ENCRYPTED;
    ret = TransProxyFillChannelInfo(msg, chan);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
    ReleaseChannelInfo(chan);
    SoftBusFree(msg);
}

/**
 * @tc.name: TransProxySetAuthHandleByChanId001
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND when given invalid authId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxySetAuthHandleByChanId001, TestSize.Level1)
{
    int32_t channelId = TEST_MESSAGE_CHANNEL_ID;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };

    int32_t ret = TransProxySetAuthHandleByChanId(channelId, authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: TransProxySetAuthHandleByChanId002
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND when given invalid authId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxySetAuthHandleByChanId002, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_MESSAGE_CHANNEL_ID;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_KEEPLIVEING;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    ret = TransProxySetAuthHandleByChanId(TEST_MESSAGE_CHANNEL_ID, authHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyDelChanByChanId(TEST_MESSAGE_CHANNEL_ID);
}

/**
 * @tc.name: TransProxyHandShakeUnpackErrMsg001
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND when given invalid authId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyHandShakeUnpackErrMsg001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    int32_t *errcode = nullptr;
    int32_t ret = TransProxyHandshakeUnpackErrMsg(chan, msg, errcode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    chan->channelId = TEST_VALID_CHANNEL_ID;
    chan->myId = TEST_NUMBER_THREE;
    chan->peerId = TEST_NUMBER_TEN;
    msg->dateLen = TEST_NUMBER_TWENTY;
    int32_t code = SOFTBUS_OK;
    ret = TransProxyHandshakeUnpackErrMsg(chan, msg, &code);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
    ReleaseChannelInfo(chan);
    SoftBusFree(msg);
}

/**
 * @tc.name: TransProxyHandShakeUnpackRightMsg001
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND when given invalid authId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyHandShakeUnpackRightMsg001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    ProxyMessage *msg = reinterpret_cast<ProxyMessage *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(nullptr != msg);
    int32_t *errcode = nullptr;
    int32_t ret = TransProxyHandshakeUnpackRightMsg(chan, msg, *errcode, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint16_t *fastDataSize = reinterpret_cast<uint16_t *>(SoftBusCalloc(sizeof(uint16_t)));
    *fastDataSize = TEST_NUMBER_ONE;
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->myId = TEST_NUMBER_THREE;
    chan->peerId = TEST_NUMBER_TEN;
    msg->dateLen = TEST_NUMBER_TWENTY;
    ret = TransProxyHandshakeUnpackRightMsg(chan, msg, SOFTBUS_OK, fastDataSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ReleaseChannelInfo(chan);
    SoftBusFree(msg);
}

/**
 * @tc.name: TransProxyGetPrivilegeCloseList001
 * @tc.desc: TransProxyGetPrivilegeCloseList Test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerTest, TransProxyGetPrivilegeCloseList001, TestSize.Level1)
{
    ProxyChannelInfo *chan = reinterpret_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = TEST_PARSE_MESSAGE_CHANNEL;
    chan->reqId = TEST_VALID_REQ;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    chan->connId = TEST_VALID_CONN_ID;
    int32_t ret = TransProxyAddChanItem(chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_PARSE_MESSAGE_CHANNEL;

    uint64_t tokenId = 1;
    int32_t pid = 1;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    ret = TransProxyGetPrivilegeCloseList(nullptr, tokenId, pid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyDelByChannelId(channelId, chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
