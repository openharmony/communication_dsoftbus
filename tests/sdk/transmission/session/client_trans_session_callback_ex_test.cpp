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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_session_callback.c"
#include "softbus_def.h"
#include "softbus_app_info.h"
#include "softbus_trans_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "softbus_server_frame.h"
#include "softbus_feature_config.h"
#include "softbus_conn_interface.h"
#include "trans_log.h"
#include "trans_manager_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using testing::NiceMock;

namespace OHOS {

class TransClientSessionCallbackExTest : public testing::Test {
public:
    TransClientSessionCallbackExTest()
    {}
    ~TransClientSessionCallbackExTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionCallbackExTest::SetUpTestCase(void) {}

void TransClientSessionCallbackExTest::TearDownTestCase(void) {}

typedef enum {
    EXCUTE_IN_FIRST_TIME = 1,
    EXCUTE_IN_SECOND_TIME,
    EXCUTE_IN_THIRD_TIME,
    EXCUTE_IN_FOURTH_TIME,
    EXCUTE_IN_FIFTH_TIME,
    EXCUTE_IN_SIXTH_TIME,
} ExcuteTimes;

/**
 * @tc.name: FillSessionInfoTest01
 * @tc.desc: FillSessionInfo param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, FillSessionInfoTest01, TestSize.Level1)
{
    SessionInfo session;
    ChannelInfo channel = {
        .peerSessionName = reinterpret_cast<char *>(SoftBusCalloc(SESSION_NAME_SIZE_MAX)),
        .peerDeviceId = reinterpret_cast<char *>(SoftBusCalloc(DEVICE_ID_SIZE_MAX)),
        .groupId = reinterpret_cast<char *>(SoftBusCalloc(GROUP_ID_SIZE_MAX)),
        .tokenType = ACCESS_TOKEN_TYPE_NATIVE,
    };
    strcpy_s(channel.peerSessionName, SESSION_NAME_SIZE_MAX, "peerSessionName");
    strcpy_s(channel.peerDeviceId, DEVICE_ID_SIZE_MAX, "peerDeviceId");
    strcpy_s(channel.groupId, GROUP_ID_SIZE_MAX, "groupId");

    int32_t ret = FillSessionInfo(&session, &channel, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channel.tokenType = ACCESS_TOKEN_TYPE_HAP;
    channel.peerBusinessAccountId = reinterpret_cast<char *>(SoftBusCalloc(ACCOUNT_UID_LEN_MAX));
    ret = FillSessionInfo(&session, &channel, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channel.peerExtraAccessInfo = reinterpret_cast<char *>(SoftBusCalloc(EXTRA_ACCESS_INFO_LEN_MAX));
    ret = FillSessionInfo(&session, &channel, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channel.tokenType = ACCESS_TOKEN_TYPE_NATIVE;
    ret = FillSessionInfo(&session, &channel, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(channel.peerSessionName);
    SoftBusFree(channel.peerDeviceId);
    SoftBusFree(channel.groupId);
    SoftBusFree(channel.peerBusinessAccountId);
    SoftBusFree(channel.peerExtraAccessInfo);
}

void MyOnError(int32_t socket, int32_t errCode)
{
    (void)socket;
    (void)errCode;
    return;
}

/**
 * @tc.name: TransOnBindFailedTest001
 * @tc.desc: TransOnBindFailed param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnBindFailedTest001, TestSize.Level1)
{
    ISocketListener listener = {
        .OnError = MyOnError,
    };
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionIsAsyncBySessionId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
    .WillOnce(TransMgrInterfaceMock::ActionOfClientGetSessionIsAsyncBySessionId).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnBindFailed(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.OnError = nullptr;
    ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    listener.OnError = MyOnError;

    EXPECT_CALL(transMgrInterfaceMock, GetSocketLifecycleAndSessionNameBySessionId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(TransMgrInterfaceMock::ActionOfGetSocketLifecycleAndSessionNameBySessionId);

    ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnBindFailed(0, &listener, 0);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
}

/**
 * @tc.name: HandleAsyncBindSuccessTest001
 * @tc.desc: HandleAsyncBindSuccess param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, HandleAsyncBindSuccessTest001, TestSize.Level1)
{
    SocketLifecycleData lifecycle = {
        .sessionState = SESSION_STATE_OPENING,
    };
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientHandleBindWaitTimer).WillRepeatedly(Return(SOFTBUS_OK));

    lifecycle.sessionState = SESSION_STATE_CANCELLING;
    int32_t ret = HandleAsyncBindSuccess(0, nullptr, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    lifecycle.sessionState = SESSION_STATE_OPENING;

    EXPECT_CALL(transMgrInterfaceMock, SetSessionStateBySessionId).WillOnce(Return(SOFTBUS_TRANS_INVALID_SESSION_ID))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ret = HandleAsyncBindSuccess(0, nullptr, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);

    ret = HandleAsyncBindSuccess(0, nullptr, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

bool MyOnNegotiateSucc(int32_t socket, PeerSocketInfo info)
{
    (void)socket;
    (void)info;
    return true;
}

bool MyOnNegotiateFailed(int32_t socket, PeerSocketInfo info)
{
    (void)socket;
    (void)info;
    return false;
}

/**
 * @tc.name: TransOnNegotiateTest001
 * @tc.desc: TransOnNegotiate param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnNegotiateTest001, TestSize.Level1)
{
    ISocketListener socketCallback = {
        .OnNegotiate = MyOnNegotiateFailed,
    };
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetPeerSocketInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = TransOnNegotiate(0, &socketCallback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnNegotiate(0, &socketCallback);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NEGOTIATE_REJECTED);

    socketCallback.OnNegotiate = MyOnNegotiateSucc;
    ret = TransOnNegotiate(0, &socketCallback);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

bool MyOnNegotiate2Succ(int32_t socket, PeerSocketInfo info, SocketAccessInfo *peerInfo, SocketAccessInfo *localInfo)
{
    (void)socket;
    (void)info;
    (void)peerInfo;
    (void)localInfo;
    return true;
}

bool MyOnNegotiate2Failed(int32_t socket, PeerSocketInfo info, SocketAccessInfo *peerInfo, SocketAccessInfo *localInfo)
{
    (void)socket;
    (void)info;
    (void)peerInfo;
    (void)localInfo;
    return false;
}

/**
 * @tc.name: TransOnNegotiateTest002
 * @tc.desc: TransOnNegotiate2 param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnNegotiateTest002, TestSize.Level1)
{
    ISocketListener socketCallback = {
        .OnNegotiate2 = nullptr,
    };
    ChannelInfo channel = {
        .peerUserId = -1,
    };

    int32_t ret = TransOnNegotiate2(0, nullptr, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnNegotiate2(0, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnNegotiate2(0, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetPeerSocketInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    socketCallback.OnNegotiate2 = MyOnNegotiate2Failed;
    channel.peerUserId = 0;
    ret = TransOnNegotiate2(0, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnNegotiate2(0, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NEGOTIATE_REJECTED);

    socketCallback.OnNegotiate2 = MyOnNegotiate2Succ;
    ret = TransOnNegotiate2(0, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: HandleServerOnNegotiateTest001
 * @tc.desc: HandleServerOnNegotiate param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, HandleServerOnNegotiateTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSocketSession).WillRepeatedly(Return(SOFTBUS_OK));
    ISocketListener socketCallback = {
        .OnNegotiate = nullptr,
        .OnNegotiate2 = nullptr,
    };
    ChannelInfo channel = {
        .peerUserId = -1,
        .channelType = CHANNEL_TYPE_AUTH,
    };

    int32_t ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_HAP, nullptr, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_HAP, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_NATIVE, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channel.channelId = CHANNEL_TYPE_TCP_DIRECT;
    ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_HAP, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_NATIVE, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    socketCallback.OnNegotiate2 = MyOnNegotiate2Failed;
    ret = HandleServerOnNegotiate(0, ACCESS_TOKEN_TYPE_NATIVE, &socketCallback, &channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int32_t ActionOfGetIsAsyncAndTokenTypeBySessionId(int32_t sessionId, bool *isAsync, int32_t *tokenType)
{
    (void)sessionId;
    (void)tokenType;
    *isAsync = false;
    return SOFTBUS_OK;
}

/**
 * @tc.name: HandleOnBindSuccessTest001
 * @tc.desc: HandleOnBindSuccess param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, HandleOnBindSuccessTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSocketSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, GetIsAsyncAndTokenTypeBySessionId).WillRepeatedly(
        [](int32_t sessionId, bool *isAsync, int32_t *tokenType) -> int32_t {
        static int32_t times = 0;
        times++;
        if (times < EXCUTE_IN_THIRD_TIME) {
            return SOFTBUS_OK;
        }
        return ActionOfGetIsAsyncAndTokenTypeBySessionId(sessionId, isAsync, tokenType);
    });
    SessionListenerAdapter sessionCallback;
    sessionCallback.socketServer.OnNegotiate = nullptr;
    sessionCallback.socketClient.OnQos = nullptr;
    ChannelInfo channel = {
        .isServer = true,
    };
    SocketAccessInfo sinkAccessInfo;

    EXPECT_CALL(transMgrInterfaceMock, GetSocketLifecycleAndSessionNameBySessionId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = HandleOnBindSuccess(0, sessionCallback, &channel, &sinkAccessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = HandleOnBindSuccess(0, sessionCallback, &channel, &sinkAccessInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channel.isServer = false;
    EXPECT_CALL(transMgrInterfaceMock, ClientHandleBindWaitTimer).WillRepeatedly(Return(SOFTBUS_OK));
    ret = HandleOnBindSuccess(0, sessionCallback, &channel, &sinkAccessInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = HandleOnBindSuccess(0, sessionCallback, &channel, &sinkAccessInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

int MyOnSessionOpened(int sessionId, int result)
{
    (void)sessionId;
    (void)result;
    return SOFTBUS_OK;
}

/**
 * @tc.name: TransOnSessionOpenFailedTest001
 * @tc.desc: TransOnSessionOpenFailed param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnSessionOpenFailedTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientSetEnableStatusBySocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSocketSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientHandleBindWaitTimer).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientSignalSyncBind).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionIsAsyncBySessionId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
    .WillOnce(TransMgrInterfaceMock::ActionOfClientGetSessionIsAsyncBySessionId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionCallbackAdapterById).WillRepeatedly(
        [](int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) -> int32_t {
        (void)sessionId;
        static int32_t times = 0;
        times++;
        callbackAdapter->isSocketListener = false;
        *isServer = false;
        if (times == EXCUTE_IN_FIRST_TIME) {
            callbackAdapter->session.OnSessionOpened = nullptr;
            return SOFTBUS_OK;
        }
        if (times == EXCUTE_IN_SECOND_TIME) {
            callbackAdapter->session.OnSessionOpened = MyOnSessionOpened;
            return SOFTBUS_OK;
        }
        callbackAdapter->isSocketListener = true;

        if (times < EXCUTE_IN_SIXTH_TIME) {
            return SOFTBUS_OK;
        }
        *isServer = true;
        return SOFTBUS_OK;
    });
    int32_t ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnSessionOpenFailed(0, 0, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void MyOnSessionClosed(int sessionId)
{
    (void)sessionId;
    return;
}

void MyOnShutdown(int32_t socket, ShutdownReason reason)
{
    (void)socket;
    (void)reason;
    return;
}

int32_t ActionOfClientGetChannelBySessionId(
    int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus)
{
    (void)sessionId;
    (void)channelId;
    (void)type;
    static int32_t times = 0;
    times++;
    if (times < EXCUTE_IN_SECOND_TIME) {
        *enableStatus = ENABLE_STATUS_FAILED;
        return SOFTBUS_OK;
    }
    *enableStatus = ENABLE_STATUS_SUCCESS;
    return SOFTBUS_OK;
}

/**
 * @tc.name: TransOnSessionClosedTest001
 * @tc.desc: TransOnSessionClosed param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnSessionClosedTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSocketSession).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientDeleteSession).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    EXPECT_CALL(transMgrInterfaceMock, ClientGetChannelBySessionId)
        .WillRepeatedly(ActionOfClientGetChannelBySessionId);
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionCallbackAdapterById).WillRepeatedly(
        [](int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) -> int32_t {
        (void)sessionId;
        static int32_t times = 0;
        times++;
        *isServer = true;
        callbackAdapter->socketServer.OnShutdown = nullptr;
        callbackAdapter->session.OnSessionClosed = nullptr;
        if (times == EXCUTE_IN_FIRST_TIME) {
            callbackAdapter->isSocketListener = true;
            return SOFTBUS_OK;
        }
        if (times == EXCUTE_IN_SECOND_TIME) {
            callbackAdapter->isSocketListener = false;
            callbackAdapter->session.OnSessionClosed = MyOnSessionClosed;
            return SOFTBUS_OK;
        }
        if (times == EXCUTE_IN_THIRD_TIME) {
            callbackAdapter->isSocketListener = true;
            return SOFTBUS_OK;
        }
        callbackAdapter->isSocketListener = true;
        callbackAdapter->socketServer.OnShutdown = MyOnShutdown;
        return SOFTBUS_OK;
    });

    int32_t ret = TransOnSessionClosed(0, CHANNEL_TYPE_UDP, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransOnSessionClosed(0, CHANNEL_TYPE_UDP, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnSessionClosed(0, CHANNEL_TYPE_UDP, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnSessionClosed(0, CHANNEL_TYPE_UDP, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void MyOnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    (void)socket;
    (void)data;
    (void)dataLen;
    return;
}

void MyOnMessage(int32_t socket, const void *data, uint32_t dataLen)
{
    (void)socket;
    (void)data;
    (void)dataLen;
    return;
}

/**
 * @tc.name: TransOnDataReceivedTest001
 * @tc.desc: TransOnDataReceived param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackExTest, TransOnDataReceivedTest001, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMgrInterfaceMock, ClientResetIdleTimeoutById).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(transMgrInterfaceMock, ClientGetSessionCallbackAdapterById).WillRepeatedly(
        [](int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer) -> int32_t {
        (void)sessionId;
        static int32_t times = 0;
        times++;
        *isServer = true;
        callbackAdapter->isSocketListener = true;
        callbackAdapter->socketServer.OnBytes = nullptr;
        callbackAdapter->socketServer.OnMessage = nullptr;
        callbackAdapter->session.OnBytesReceived = nullptr;
        callbackAdapter->session.OnMessageReceived = nullptr;
        if (times < EXCUTE_IN_THIRD_TIME) {
            callbackAdapter->isSocketListener = false;
            return SOFTBUS_OK;
        }
        if (times < EXCUTE_IN_FIFTH_TIME) {
            return SOFTBUS_OK;
        }
        callbackAdapter->socketServer.OnBytes = MyOnBytes;
        callbackAdapter->socketServer.OnMessage = MyOnMessage;
        return SOFTBUS_OK;
    });

    int32_t ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_BYTES);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_BYTES);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_BYTES);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(0, CHANNEL_TYPE_UDP, nullptr, 0, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}