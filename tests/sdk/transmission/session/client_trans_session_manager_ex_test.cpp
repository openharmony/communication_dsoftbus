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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "client_trans_session_manager.c"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "trans_common_mock.h"
#include "trans_log.h"
#include "trans_socket_mgr_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using testing::NiceMock;

namespace OHOS {

class TransClientSessionManagerExTest : public testing::Test {
public:
    TransClientSessionManagerExTest()
    {}
    ~TransClientSessionManagerExTest()
    {}
    static void SetUpTestCase(void)
    {}
    static void TearDownTestCase(void)
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}
};

typedef enum {
    EXCUTE_IN_FIRST_TIME = 1,
    EXCUTE_IN_SECOND_TIME,
    EXCUTE_IN_THIRD_TIME,
    EXCUTE_IN_FOURTH_TIME,
    EXCUTE_IN_FIFTH_TIME,
    EXCUTE_IN_SIXTH_TIME,
} ExcuteTimes;

SoftBusList g_clientSessionServerList;
ClientSessionServer g_server;
SessionInfo g_sessionNode;

/**
 * @tc.name: TransClientSessionManagerExTest01
 * @tc.desc: TransClientInit with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest01, TestSize.Level1)
{
    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, RegNodeDeviceStateCbInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, CreateSoftBusList).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&g_clientSessionServerList));
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);

    NiceMock<TransSocketMgrMock> transSocketMgrMock;
    EXPECT_CALL(transSocketMgrMock, TransDataSeqInfoListInit).WillOnce(Return(SOFTBUS_TRANS_DATA_SEQ_INFO_NO_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_DATA_SEQ_INFO_NO_INIT);

    EXPECT_CALL(transCommInterfaceMock, TransServerProxyInit).WillOnce(Return(SOFTBUS_TRANS_SERVER_INIT_FAILED))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_SERVER_INIT_FAILED);

    EXPECT_CALL(transCommInterfaceMock, ClientTransChannelInit).WillOnce(Return(SOFTBUS_TRANS_SERVER_INIT_FAILED))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_SERVER_INIT_FAILED);

    EXPECT_CALL(transCommInterfaceMock, RegisterTimeoutCallback).WillRepeatedly(
        [](int32_t timerFunId, TimerFunCallback callback) -> int32_t {
        (void)timerFunId;
        (void)callback;
        static int32_t times = 0;
        times++;
        if (times == EXCUTE_IN_FIRST_TIME) {
            return SOFTBUS_TRANS_SERVER_INIT_FAILED;
        }
        if (times == EXCUTE_IN_SECOND_TIME) {
            return SOFTBUS_OK;
        }
        if (times == EXCUTE_IN_THIRD_TIME) {
            return SOFTBUS_TRANS_DATA_SEQ_INFO_INIT_FAIL;
        }
        return SOFTBUS_OK;
    });
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_SERVER_INIT_FAILED);

    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_TRANS_DATA_SEQ_INFO_INIT_FAIL);

    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest02
 * @tc.desc: ClientGetSessionNameBySessionId with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest02, TestSize.Level1)
{
    char *sessionName = reinterpret_cast<char *>(SoftBusCalloc(SESSION_NAME_SIZE_MAX));

    int32_t ret = ClientGetSessionNameBySessionId(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientGetSessionNameBySessionId(-1, sessionName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientGetSessionNameBySessionId(1, sessionName);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    EXPECT_EQ(SoftBusMutexInit(&g_clientSessionServerList.lock, &mutexAttr), SOFTBUS_OK);
    ListInit(&g_clientSessionServerList.list);
    ListInit(&g_server.node);
    ListInit(&g_server.sessionList);
    ListInit(&g_sessionNode.node);

    ListAdd(&g_clientSessionServerList.list, &g_server.node);
    ret = ClientGetSessionNameBySessionId(0, sessionName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ListAdd(&g_server.sessionList, &g_sessionNode.node);
    g_sessionNode.sessionId = 0;
    ret = ClientGetSessionNameBySessionId(1, sessionName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    g_sessionNode.sessionId = 1;

    (void)strcpy_s(g_server.sessionName, SESSION_NAME_SIZE_MAX, "sessionName");
    ret = ClientGetSessionNameBySessionId(1, sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(sessionName);
}

/**
 * @tc.name: TransClientSessionManagerExTest03
 * @tc.desc: TransSetNeedAckBySocket with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest03, TestSize.Level1)
{
    int32_t ret = TransSetNeedAckBySocket(0, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSetNeedAckBySocket(2, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.isSupportTlv = false;
    ret = TransSetNeedAckBySocket(1, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NOT_SUPPORT_TLV_HEAD);
    g_sessionNode.isSupportTlv = true;

    ret = TransSetNeedAckBySocket(1, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest04
 * @tc.desc: TransGetSupportTlvBySocket with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest04, TestSize.Level1)
{
    int32_t optValueSize = 0;
    bool supportTlv = false;
    int32_t ret = TransGetSupportTlvBySocket(0, &supportTlv, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(1, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(1, &supportTlv, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(0, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(0, &supportTlv, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(1, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetSupportTlvBySocket(1, &supportTlv, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(supportTlv, true);
    EXPECT_EQ(optValueSize, sizeof(bool));
}

/**
 * @tc.name: TransClientSessionManagerExTest05
 * @tc.desc: ClientGetCachedQosEventBySocket with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest05, TestSize.Level1)
{
    CachedQosEvent cachedQosEvent;
    int32_t ret = ClientGetCachedQosEventBySocket(0, &cachedQosEvent);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientGetCachedQosEventBySocket(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientGetCachedQosEventBySocket(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientGetCachedQosEventBySocket(2, &cachedQosEvent);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientGetCachedQosEventBySocket(1, &cachedQosEvent);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest06
 * @tc.desc: ClientCacheQosEvent with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest06, TestSize.Level1)
{
    QosTV qos;
    (void)memset_s(&qos, sizeof(QosTV), 0, sizeof(QosTV));
    int32_t ret = ClientCacheQosEvent(0, QOS_SATISFIED, &qos, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(1, QOS_SATISFIED, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(1, QOS_SATISFIED, &qos, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(0, QOS_SATISFIED, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(0, QOS_SATISFIED, &qos, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(1, QOS_SATISFIED, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(0, QOS_SATISFIED, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientCacheQosEvent(2, QOS_SATISFIED, &qos, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.lifecycle.sessionState = SESSION_STATE_CALLBACK_FINISHED;
    ret = ClientCacheQosEvent(1, QOS_SATISFIED, &qos, 1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NO_NEED_CACHE_QOS_EVENT);
    g_sessionNode.lifecycle.sessionState = SESSION_STATE_OPENING;

    ret = ClientCacheQosEvent(1, QOS_SATISFIED, &qos, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest07
 * @tc.desc: ClientCancelAuthSessionTimer with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest07, TestSize.Level1)
{
    int32_t ret = ClientCancelAuthSessionTimer(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);

    ret = ClientCancelAuthSessionTimer(1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    (void)strcpy_s(g_server.sessionName, SESSION_NAME_SIZE_MAX, "IShareAuthSession");
    ret = ClientCancelAuthSessionTimer(2);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.actionId = 0;
    g_sessionNode.channelType = CHANNEL_TYPE_UNDEFINED;
    ret = ClientCancelAuthSessionTimer(1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.channelType = CHANNEL_TYPE_PROXY;
    ret = ClientCancelAuthSessionTimer(1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_sessionNode.channelType = CHANNEL_TYPE_AUTH;
    ret = ClientCancelAuthSessionTimer(1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest08
 * @tc.desc: ClientUpdateAuthSessionTimer with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest08, TestSize.Level1)
{
    g_sessionNode.actionId = 0;
    int32_t ret = ClientUpdateAuthSessionTimer(&g_sessionNode, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_sessionNode.actionId = 1;

    g_sessionNode.lifecycle.maxWaitTime = 0;
    ret = ClientUpdateAuthSessionTimer(&g_sessionNode, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_NEED_UPDATE);

    g_sessionNode.lifecycle.maxWaitTime = 1;
    ret = ClientUpdateAuthSessionTimer(&g_sessionNode, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest09
 * @tc.desc: ClientSignalSyncBind with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest09, TestSize.Level1)
{
    int32_t ret = ClientSignalSyncBind(0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);

    ret = ClientSignalSyncBind(2, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.isAsync = true;
    ret = ClientSignalSyncBind(1, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_sessionNode.isAsync = false;

    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, SoftBusCondSignal).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ret = ClientSignalSyncBind(1, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientSignalSyncBind(1, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest10
 * @tc.desc: ClientWaitSyncBind with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest10, TestSize.Level1)
{
    int32_t ret = ClientWaitSyncBind(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);

    ret = ClientWaitSyncBind(2);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    g_sessionNode.lifecycle.sessionState = SESSION_STATE_CANCELLING;
    g_sessionNode.lifecycle.bindErrCode = SOFTBUS_INVALID_PARAM;
    ret = ClientWaitSyncBind(1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    g_sessionNode.lifecycle.sessionState = SESSION_STATE_OPENING;
    g_sessionNode.lifecycle.bindErrCode = SOFTBUS_OK;

    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, SoftBusGetTime).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transCommInterfaceMock, SoftBusCondWait).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    g_sessionNode.lifecycle.maxWaitTime = 1;
    ret = ClientWaitSyncBind(1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_sessionNode.enableStatus = ENABLE_STATUS_SUCCESS;
    ret = ClientWaitSyncBind(1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerExTest11
 * @tc.desc: GetLogicalBandwidth with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerExTest, TransClientSessionManagerExTest11, TestSize.Level1)
{
    int32_t optValueSize = 0;
    int32_t optValue = 0;
    int32_t ret = GetLogicalBandwidth(0, &optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(1, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(1, &optValue, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(0, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(0, &optValue, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(1, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetLogicalBandwidth(1, &optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(optValue, 0);
    EXPECT_EQ(optValueSize, sizeof(int32_t));

    ret = GetLogicalBandwidth(2, &optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ListDelete(&g_server.node);
    ListDelete(&g_sessionNode.node);
}
}