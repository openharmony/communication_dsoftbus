/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "softbus_proxychannel_manager_paging_test_mock.h"
#include "softbus_proxychannel_message_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1056
#define TEST_PID 3516
#define TEST_LEN 10
#define TEST_LOW_LEN 4
#define TEST_REQ 35
static const char *TEST_DATA = "TEST_DATA";
static const char *TEST_EXTRA_DATA = "EXT";

namespace OHOS {

class SoftbusProxyChannelManagerPagingTest : public testing::Test {
public:
    SoftbusProxyChannelManagerPagingTest()
    {}
    ~SoftbusProxyChannelManagerPagingTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusProxyChannelManagerPagingTest::SetUpTestCase(void)
{
}

void SoftbusProxyChannelManagerPagingTest::TearDownTestCase(void)
{
}

static ProxyChannelInfo *TestCreateProxyChannelInfo(void)
{
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == nullptr) {
        return nullptr;
    }
    chan->authHandle.authId = TEST_CHANNEL_ID;
    chan->connId = TEST_CHANNEL_ID;
    chan->myId = TEST_CHANNEL_ID;
    chan->peerId = TEST_CHANNEL_ID;
    chan->reqId = TEST_CHANNEL_ID;
    chan->channelId = TEST_CHANNEL_ID;
    chan->seq = TEST_CHANNEL_ID;
    chan->appInfo.fastTransData = nullptr;
    chan->retried = true;
    chan->appInfo.myData.pid = TEST_PID;
    return chan;
}

/**@
 * @tc.name: TransPagingUpdatePagingChannelInfoTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransPagingUpdatePagingChannelInfoTest001, TestSize.Level1)
{
    int32_t ret = TransPagingUpdatePagingChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = TEST_CHANNEL_ID,
        .isD2D = true,
        .appInfo.peerData.channelId = static_cast<int64_t>(TEST_CHANNEL_ID),
    };
    int32_t channelId = TEST_CHANNEL_ID;
    TransPagingBadKeyRetry(channelId);
    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    ret = TransPagingUpdatePagingChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPagingUpdatePagingChannelInfo(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransPagingBadKeyRetry(channelId);
    info->retried = false;
    NiceMock<SoftbusProxychannelManagerPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransPagingBadKeyRetry(channelId);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthGenApplyKey).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransPagingBadKeyRetry(channelId);
    EXPECT_CALL(ProxyPagingMock, AuthGenApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    TransPagingBadKeyRetry(channelId);
    ret = TransPagingUpdatePagingChannelInfo(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    chan.appInfo.myData.channelId = TEST_CHANNEL_ID;
    ret = TransPagingUpdatePagingChannelInfo(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyDelChanByChanId(TEST_CHANNEL_ID);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: TransPagingUpdatePidAndDataTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransPagingUpdatePidAndDataTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t pid = TEST_PID;
    char *data = const_cast<char *>(TEST_EXTRA_DATA);
    uint32_t len = EXTRA_DATA_MAX_LEN + 1;

    int32_t ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);
    ret = TransPagingUpdatePidAndData(channelId, pid, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = TEST_LOW_LEN;

    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    len = 0;
    ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    channelId = TEST_CHANNEL_ID + 1;
    ret = TransPagingUpdatePidAndData(channelId, pid, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    TransProxyDelChanByChanId(TEST_CHANNEL_ID);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: TransUpdateAuthSeqByChannelIdTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransUpdateAuthSeqByChannelIdTest001, TestSize.Level1)
{
    uint32_t requestId = TEST_REQ;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t reqId = TEST_REQ;
    uint8_t *data = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint32_t applyKeyLen = D2D_APPLY_KEY_LEN + 1;

    TransOnGenSuccess(requestId, data, 0);
    TransOnGenSuccess(requestId, data, applyKeyLen);
    applyKeyLen = TEST_LEN;
    TransOnGenSuccess(requestId, nullptr, applyKeyLen);
    TransOnGenSuccess(requestId, data, applyKeyLen);

    int32_t ret = TransUpdateAuthSeqByChannelId(channelId, reqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);

    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    ret = TransUpdateAuthSeqByChannelId(channelId, reqId);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthSeqByChannelId(channelId, reqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<SoftbusProxychannelManagerPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransProxyPagingHandshakeMsgToLoop).Times(1);
    TransOnGenSuccess(requestId, data, applyKeyLen);
    channelId = TEST_CHANNEL_ID + 1;
    ret = TransUpdateAuthSeqByChannelId(channelId, reqId);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    TransProxyDelChanByChanId(TEST_CHANNEL_ID);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
    TransOnGenFailed(requestId, SOFTBUS_INVALID_PARAM);
}

/**@
 * @tc.name: TransPagingResetChanTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransPagingResetChanTest001, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = TEST_CHANNEL_ID,
        .isD2D = true,
        .appInfo.peerData.channelId = TEST_CHANNEL_ID,
    };

    int32_t ret = TransPagingResetChan(&chan);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);
    ret = TransPagingResetChan(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    ret = TransPagingResetChan(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    chan.peerId = TEST_CHANNEL_ID + 1;
    ret = TransPagingResetChan(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    chan.peerId = TEST_CHANNEL_ID;
    chan.myId = TEST_CHANNEL_ID + 1;
    ret = TransPagingResetChan(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    chan.myId = TEST_CHANNEL_ID;
    ret = TransPagingResetChan(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: TransPagingHandshakeUnpackErrMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransPagingHandshakeUnpackErrMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = TEST_CHANNEL_ID,
        .isD2D = true,
        .appInfo.peerData.channelId = static_cast<int64_t>(TEST_CHANNEL_ID),
    };
    ProxyMessage msg = {
        .data = const_cast<char *>(TEST_DATA),
        .dataLen = sizeof(TEST_DATA),
    };
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t errCode = SOFTBUS_OK;
    cJSON *root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    int32_t ret = TransPagingHandshakeUnPackErrMsg(nullptr, &msg, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPagingHandshakeUnPackErrMsg(&chan, nullptr, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPagingHandshakeUnPackErrMsg(&chan, &msg, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<SoftbusProxychannelManagerPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    ret = TransPagingHandshakeUnPackErrMsg(&chan, &msg, &errCode);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(root));
    ret = TransPagingHandshakeUnPackErrMsg(&chan, &msg, &errCode);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddNumberToJsonObject(testRoot, ERR_CODE, errCode);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingHandshakeUnPackErrMsg(&chan, &msg, &errCode);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    res = AddNumberToJsonObject(testRootTest, ERR_CODE, errCode);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRootTest, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    ret = TransPagingHandshakeUnPackErrMsg(&chan, &msg, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransDealProxyChannelOpenResultTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransDealProxyChannelOpenResultTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t openResult = SOFTBUS_OK;
    AccessInfo accessInfo;
    pid_t callingPid = TEST_PID + 1;
    int32_t ret = TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);
    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    info->isD2D = true;
    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_TRANS_CHECK_PID_ERROR, ret);
    callingPid = TEST_PID;
    NiceMock<SoftbusProxychannelManagerPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelBind).WillOnce(Return(SOFTBUS_OK));
    ret = TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    callingPid = TEST_PID + 1;
    ret = TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_TRANS_CHECK_PID_ERROR, ret);
    callingPid = 0;
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelClosed).WillOnce(Return(SOFTBUS_OK));
    ret = TransDealProxyChannelOpenResult(channelId, openResult, &accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: TransProxyCreatePagingChanInfoTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransProxyCreatePagingChanInfoTest001, TestSize.Level1)
{
    int32_t ret = TransProxyCreatePagingChanInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    ret = TransProxyCreatePagingChanInfo(info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);
    ret = TransProxyCreatePagingChanInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransProxyDelChanByChanId(TEST_CHANNEL_ID);

    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**@
 * @tc.name: TransProxyGetProxyChannelIdByAuthReqTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelManagerPagingTest, TransProxyGetProxyChannelIdByAuthReqTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t reqId = TEST_REQ;

    int32_t ret = TransProxyGetProxyChannelIdByAuthReq(reqId, &channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);

    ret = TransProxyGetProxyChannelIdByAuthReq(reqId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyGetProxyChannelIdByAuthReq(reqId, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ProxyChannelInfo *info = TestCreateProxyChannelInfo();
    ASSERT_TRUE(info != nullptr);
    info->authReqId = TEST_REQ;
    ret = TransProxyAddChanItem(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyGetProxyChannelIdByAuthReq(reqId, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    reqId = TEST_REQ + 1;
    ret = TransProxyGetProxyChannelIdByAuthReq(reqId, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    TransProxyDelChanByChanId(TEST_CHANNEL_ID);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}
} // namespace OHOS

