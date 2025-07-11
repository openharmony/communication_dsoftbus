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

#include "gmock/gmock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_proxychannel_transceiver.c"
#include "softbus_proxychannel_transceiver_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID    1058
#define TEST_KEY_LEN       14
#define TEST_LEN           10
#define TEST_CONNECTION_ID 65542
#define TEST_SEQ           64
#define TEST_FOR_NUM       51
static const char *TEST_AUTH_KEY = "TEST_AUTH_KEY";

namespace OHOS {

class SoftbusProxyChannelTransceiverPagingTest : public testing::Test {
public:
    SoftbusProxyChannelTransceiverPagingTest()
    {}
    ~SoftbusProxyChannelTransceiverPagingTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusProxyChannelTransceiverPagingTest::SetUpTestCase(void)
{
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, TransProxyLoopInit());
    g_proxyPagingWaitList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyPagingWaitList != nullptr);
}

void SoftbusProxyChannelTransceiverPagingTest::TearDownTestCase(void)
{
}

/**@
 * @tc.name: TransProxyPagingHandshakeMsgToLoopTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, TransProxyPagingHandshakeMsgToLoopTest001, TestSize.Level1)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    uint8_t *authKey = (uint8_t *)SoftBusCalloc(TEST_KEY_LEN);
    ASSERT_TRUE(msg != nullptr);
    msg->what = LOOP_PAGINGHANDSHAKE_MSG;
    msg->arg1 = TEST_CHANNEL_ID;
    msg->arg2 = 0;
    msg->obj = static_cast<void *>(const_cast<char *>(TEST_AUTH_KEY));
    (void)memcpy_s((void *)authKey, TEST_KEY_LEN, TEST_AUTH_KEY, TEST_KEY_LEN);
    TransProxyLoopMsgHandler(msg);
    SoftBusFree(msg);
    TransProxyPagingHandshakeMsgToLoop(TEST_CHANNEL_ID, nullptr, 0);
    TransProxyPagingHandshakeMsgToLoop(TEST_CHANNEL_ID, authKey, 0);
}

/**@
 * @tc.name: TransProxyParseMsgTypeTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, TransProxyParseMsgTypeTest001, TestSize.Level1)
{
    uint8_t type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (VERSION_SHIFT << VERSION_SHIFT);
    int32_t len = TEST_LEN;
    char *data = reinterpret_cast<char *>(&type);
    uint32_t connectionId = TEST_CONNECTION_ID;
    ConnModule moduleId = MODULE_PAGING_CONN;
    int64_t seq = TEST_SEQ;
    TransProxyOnDataReceived(connectionId, moduleId, seq, nullptr, len);
    TransProxyOnDataReceived(connectionId, moduleId, seq, data, len);
    moduleId = MODULE_PROXY_CHANNEL;
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, TransParseMessageHeadType).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransProxyOnDataReceived(connectionId, moduleId, seq, data, len);
    EXPECT_CALL(PagingMock, TransParseMessageHeadType).WillRepeatedly(Return(SOFTBUS_OK));
    TransProxyOnDataReceived(connectionId, moduleId, seq, data, len);
}

/**@
 * @tc.name: TransPagingLoadSaFailTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, TransPagingLoadSaFailTest001, TestSize.Level1)
{
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransPagingLoadSaFail(false);
    EXPECT_EQ(SOFTBUS_TRANS_PAGING_WAIT_LISTEN_NOT_FOUND, ret);
    ret = TransPagingLoadSaFail(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelWaitListenByFlag(false);
    EXPECT_EQ(SOFTBUS_TRANS_PAGING_WAIT_LISTEN_NOT_FOUND, ret);
    ret = DelWaitListenByFlag(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransPagingWaitListenStatusTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, TransPagingWaitListenStatusTest001, TestSize.Level1)
{
    PagingWaitListenStatus status = PAGING_WAIT_LISTEN_LOAD_SA_FAIL;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransPagingWaitListenStatus(false, status);
    EXPECT_EQ(SOFTBUS_TRANS_PAGING_WAIT_LISTEN_NOT_FOUND, ret);
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_OK, ret);
    status = PAGING_WAIT_LISTEN_DONE;
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_OK, ret);
    status = (PagingWaitListenStatus)-1;
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    status = (PagingWaitListenStatus)5;
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelWaitListenByFlag(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: CheckListenResultTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckListenResultTest001, TestSize.Level1)
{
    PagingWaitListenStatus status = PAGING_WAIT_LISTEN_DONE;
    uint32_t businessFlag = true;
    int32_t num = TEST_FOR_NUM;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CheckResultType res = CheckListenResult(false);
    EXPECT_EQ(WAIT_LISTEN_CHECK_INVALID, res);
    res = CheckListenResult(true);
    EXPECT_EQ(WAIT_LISTEN_CHECK_RETRY, res);
    for (int i = 0; i <= num; i++) {
        (void)CheckListenResult(true);
    }
    res = CheckListenResult(true);
    EXPECT_EQ(WAIT_LISTEN_CHECK_TIMEOUT, res);
    ret = TransPagingLoadSaFail(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    res = CheckListenResult(true);
    EXPECT_EQ(WAIT_LISTEN_CHECK_LOAD_FAIL, res);
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_OK, ret);
    res = CheckListenResult(true);
    EXPECT_EQ(WAIT_LISTEN_CHECK_SUCCESS, res);
    ret = DelWaitListenByFlag(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: CheckPagingListenTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckPagingListenTest001, TestSize.Level1)
{
    uint32_t *tmp = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmp != nullptr);
    *tmp = false;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CheckPagingListen(nullptr);
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, TransProxyGetChannelByFlag).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(PagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(PagingMock, TransProxyPagingChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmp);
}

/**@
 * @tc.name: CheckPagingListenTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckPagingListenTest002, TestSize.Level1)
{
    uint32_t *tmp = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmp != nullptr);
    *tmp = true;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmp);
    uint32_t *tmpTest = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmpTest != nullptr);
    *tmpTest = true;
    EXPECT_CALL(PagingMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(PagingMock, TransProxyGetChannelByFlag).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(PagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(PagingMock, TransProxyPagingChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmpTest);
}

/**@
 * @tc.name: CheckPagingListenTest003
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckPagingListenTest003, TestSize.Level1)
{
    PagingWaitListenStatus status = PAGING_WAIT_LISTEN_DONE;
    uint32_t *tmp = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmp != nullptr);
    *tmp = true;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransPagingWaitListenStatus(true, status);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, TransProxyGetChannelByFlag).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(PagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(PagingMock, TransProxyPagingChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmp);
}


/**@
 * @tc.name: CheckPagingListenTest004
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckPagingListenTest004, TestSize.Level1)
{
    uint32_t *tmp = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmp != nullptr);
    *tmp = true;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransPagingLoadSaFail(true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, TransProxyGetChannelByFlag).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(PagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(PagingMock, TransProxyPagingChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmp);
}

/**@
 * @tc.name: CheckPagingListenTest005
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, CheckPagingListenTest005, TestSize.Level1)
{
    uint32_t *tmp = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    ASSERT_TRUE(tmp != nullptr);
    *tmp = true;
    uint32_t businessFlag = true;
    int32_t ret = AddWaitListInfo(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t num = TEST_FOR_NUM;
    for (int i = 0; i <= num; i++) {
        (void)CheckListenResult(true);
    }
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, TransProxyGetChannelByFlag).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(PagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(PagingMock, TransProxyPagingChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    CheckPagingListen((void *)tmp);
}

/**@
 * @tc.name: TransCheckPagingListenStateTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelTransceiverPagingTest, TransCheckPagingListenStateTest001, TestSize.Level1)
{
    uint32_t businessFlag = true;
    NiceMock<SoftbusProxychannelTransceiverPagingInterfaceMock> PagingMock;
    EXPECT_CALL(PagingMock, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransCheckPagingListenState(businessFlag);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(PagingMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransCheckPagingListenState(businessFlag);
    EXPECT_EQ(SOFTBUS_TRANS_PAGING_ASYNC_FAIL, ret);
}
} // namespace OHOS

