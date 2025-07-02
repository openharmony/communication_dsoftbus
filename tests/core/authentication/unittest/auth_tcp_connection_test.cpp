/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_log.h"
#include "auth_tcp_connection.c"
#include "auth_tcp_connection.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 30;
const int32_t TEST_MAGIC = 1;
const int32_t TEST_MODULE = 2;
const int64_t TSET_SEQ = 3;
const int32_t TEST_FLAG = 4;
const uint32_t TEST_LEN = 5;

class AuthTcpConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t SetSocketPktHead(SocketPktHead *head);
    static void OnWiFiConnected(ListenerModule module, int32_t fd, bool isClient);
    static void OnWiFiDisconnected(ListenerModule module, int32_t fd);
    static void OnWiFiDataReceived(ListenerModule module, int32_t fd, const AuthDataHead *head,
        const uint8_t *data);
    static void OnDataReceived(int32_t authId, const AuthChannelData *data);
    static void OnDisconnect(int32_t authId);
    static bool isOnWiFiConnectedSuccess;
    static bool isOnWiFiDisconnectedSuccess;
    static bool isOnWiFiDataReceivedSuccess;
    static bool isOnDataReceivedSuccess;
    static bool isOnDisconnectSuccess;
};

bool AuthTcpConnectionTest::isOnWiFiConnectedSuccess = false;
bool AuthTcpConnectionTest::isOnWiFiDisconnectedSuccess = false;
bool AuthTcpConnectionTest::isOnWiFiDataReceivedSuccess = false;
bool AuthTcpConnectionTest::isOnDataReceivedSuccess = false;
bool AuthTcpConnectionTest::isOnDisconnectSuccess = false;

void AuthTcpConnectionTest::SetUpTestCase() { }

void AuthTcpConnectionTest::TearDownTestCase() { }

void AuthTcpConnectionTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthTcpConnectionTest start.");
}

void AuthTcpConnectionTest::TearDown() { }

int32_t AuthTcpConnectionTest::SetSocketPktHead(SocketPktHead *head)
{
    if (head == nullptr) {
        AUTH_LOGE(AUTH_TEST, "aclInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    head->magic = TEST_MAGIC;
    head->module = TEST_MODULE;
    head->seq = TSET_SEQ;
    head->flag = TEST_FLAG;
    head->len = TEST_LEN;
    return SOFTBUS_OK;
}

void AuthTcpConnectionTest::OnWiFiConnected(ListenerModule module, int32_t fd, bool isClient)
{
    AUTH_LOGI(AUTH_TEST, "OnWiFiConnected: fd=%{public}d, side=%{public}s", fd,
        isClient ? "client" : "server(ignored)");
    isOnWiFiConnectedSuccess = true;
}

void AuthTcpConnectionTest::OnWiFiDisconnected(ListenerModule module, int32_t fd)
{
    AUTH_LOGI(AUTH_TEST, "OnWiFiDisconnected: module=%{public}d, fd=%{public}d", module, fd);
    isOnWiFiDisconnectedSuccess = true;
}

void AuthTcpConnectionTest::OnWiFiDataReceived(ListenerModule module, int32_t fd,
    const AuthDataHead *head, const uint8_t *data)
{
    AUTH_LOGI(AUTH_TEST, "OnWiFiDataReceived: module=%{public}d, fd=%{public}d", module, fd);
    isOnWiFiDataReceivedSuccess = true;
}

void AuthTcpConnectionTest::OnDataReceived(int32_t authId, const AuthChannelData *data)
{
    AUTH_LOGI(AUTH_TEST, "OnDataReceived: authId=%{public}d", authId);
    isOnDataReceivedSuccess = true;
}

void AuthTcpConnectionTest::OnDisconnect(int32_t authId)
{
    AUTH_LOGI(AUTH_TEST, "OnDisconnect: authId=%{public}d", authId);
    isOnDisconnectSuccess = true;
}


/*
 * @tc.name: PACK_SOCKET_PKT_TEST_001
 * @tc.desc: pack socket pkt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, PACK_SOCKET_PKT_TEST_001, TestSize.Level1)
{
    SocketPktHead head;
    int32_t ret = SetSocketPktHead(&head);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    uint8_t buf[10] = { 0 };
    uint32_t size = 1;
    ret = PackSocketPkt(&head, data, buf, size);
    EXPECT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);
}

/*
 * @tc.name: UNPACK_SOCKET_PKT_TEST_001
 * @tc.desc: unpack socket pkt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, UNPACK_SOCKET_PKT_TEST_001, TestSize.Level1)
{
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    uint32_t len = 1;
    SocketPktHead head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    int32_t ret = UnpackSocketPkt(data, len, &head);
    EXPECT_TRUE(ret == SOFTBUS_NO_ENOUGH_DATA);
    len = AUTH_PKT_HEAD_LEN;
    ret = UnpackSocketPkt(data, len, &head);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: NOTIFY_CONNECTED_TEST_001
 * @tc.desc: notify connected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_CONNECTED_TEST_001, TestSize.Level1)
{
    ListenerModule module = ListenerModule::LISTENER_MODULE_DYNAMIC_START;
     int32_t fd = 1;
     bool isClient = true;
     isOnWiFiConnectedSuccess = false;
     NotifyConnected(module, fd, isClient);
     EXPECT_FALSE(isOnWiFiConnectedSuccess);

     SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    int32_t ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyConnected(module, fd, isClient);
    EXPECT_TRUE(isOnWiFiConnectedSuccess);
    UnsetSocketCallback();
}

/*
 * @tc.name: NOTIFY_DISCONNECTED_TEST_001
 * @tc.desc: notify disconnected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_DISCONNECTED_TEST_001, TestSize.Level1)
{
    ListenerModule module = ListenerModule::LISTENER_MODULE_DYNAMIC_START;
    int32_t fd = 1;
    isOnWiFiDisconnectedSuccess = false;
    NotifyDisconnected(module, fd);
    EXPECT_FALSE(isOnWiFiDisconnectedSuccess);

    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    int32_t ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDisconnected(module, fd);
    EXPECT_TRUE(isOnWiFiDisconnectedSuccess);
    UnsetSocketCallback();
}

/*
 * @tc.name: MODULE_TO_DATA_TYPE_TEST_001
 * @tc.desc: module to data type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, MODULE_TO_DATA_TYPE_TEST_001, TestSize.Level1)
{
    int32_t module = MODULE_TRUST_ENGINE;
    uint32_t ret = ModuleToDataType(module);
    EXPECT_EQ(ret, DATA_TYPE_DEVICE_ID);
    module = MODULE_AUTH_SDK;
    ret = ModuleToDataType(module);
    EXPECT_EQ(ret, DATA_TYPE_AUTH);
    module = MODULE_AUTH_CONNECTION;
    ret = ModuleToDataType(module);
    EXPECT_EQ(ret, DATA_TYPE_DEVICE_INFO);
    module = MODULE_AUTH_CANCEL;
    ret = ModuleToDataType(module);
    EXPECT_EQ(ret, DATA_TYPE_CANCEL_AUTH);
    module = MODULE_MESSAGE_SERVICE;
    ret = ModuleToDataType(module);
    EXPECT_EQ(ret, DATA_TYPE_CONNECTION);
}

/*
 * @tc.name: SESSION_NOTIFY_DATA_RECEIVED_TEST_001
 * @tc.desc: Notice received the data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SESSION_NOTIFY_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    uint32_t len = 1;
    ListenerModule module = ListenerModule::LISTENER_MODULE_DYNAMIC_START;
    int32_t fd = 1;
    isOnWiFiDataReceivedSuccess = false;
    SessionNotifyDataReceived(module, fd, len, data);
    EXPECT_FALSE(isOnWiFiDataReceivedSuccess);

    len = AUTH_PKT_HEAD_LEN;
    SessionNotifyDataReceived(module, fd, len, data);
    EXPECT_FALSE(isOnWiFiDataReceivedSuccess);

    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    int32_t ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionNotifyDataReceived(module, fd, len, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);
    UnsetSocketCallback();
}

/*
 * @tc.name: SESSION_KEY_NOTIFY_DATA_RECEIVED_TEST_001
 * @tc.desc: Notice received the data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SESSION_KEY_NOTIFY_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    uint32_t len = 1;
    ListenerModule module = ListenerModule::LISTENER_MODULE_DYNAMIC_START;
    int32_t fd = 1;
    isOnWiFiDataReceivedSuccess = false;
    SessionKeyNotifyDataReceived(module, fd, len, data);
    EXPECT_FALSE(isOnWiFiDataReceivedSuccess);

    len = AUTH_PKT_HEAD_LEN;
    SessionKeyNotifyDataReceived(module, fd, len, data);
    EXPECT_FALSE(isOnWiFiDataReceivedSuccess);

    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    int32_t ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionKeyNotifyDataReceived(module, fd, len, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);
    UnsetSocketCallback();
}

/*
 * @tc.name: NOTIFY_DATA_RECEIVED_TEST_001
 * @tc.desc: Notify channel data received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    ListenerModule module = ListenerModule::AUTH_SESSION_KEY;
    int32_t fd = 1;
    SocketPktHead pktHead;
    int32_t ret = SetSocketPktHead(&pktHead);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    isOnDataReceivedSuccess = false;
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_FALSE(isOnDataReceivedSuccess);

    pktHead.module = MODULE_AUTH_MSG;
    AuthChannelListener listenerTestOne = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnect,
    };
    AuthChannelListener listenerTestTwo = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnect,
    };
    ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_FALSE(isOnDataReceivedSuccess);

    ret = RegAuthChannelListener(MODULE_AUTH_MSG, &listenerTestTwo);
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_TRUE(isOnDataReceivedSuccess);

    isOnDataReceivedSuccess = false;
    UnregAuthChannelListener(MODULE_AUTH_MSG);
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_FALSE(isOnDataReceivedSuccess);

    pktHead.module = MODULE_META_AUTH;
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_FALSE(isOnDataReceivedSuccess);
    UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
}

/*
 * @tc.name: NOTIFY_DATA_RECEIVED_TEST_002
 * @tc.desc: Session notify data received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_DATA_RECEIVED_TEST_002, TestSize.Level1)
{
    ListenerModule module = ListenerModule::AUTH_SESSION_KEY;
    int32_t fd = 1;
    SocketPktHead pktHead;
    int32_t ret = SetSocketPktHead(&pktHead);
    EXPECT_EQ(ret, SOFTBUS_OK);
    pktHead.module = MODULE_SESSION_AUTH;
    pktHead.len = AUTH_PKT_HEAD_LEN;
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    isOnWiFiDataReceivedSuccess = false;
    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);
    UnsetSocketCallback();
}

/*
 * @tc.name: NOTIFY_DATA_RECEIVED_TEST_003
 * @tc.desc: Session notify data received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_DATA_RECEIVED_TEST_003, TestSize.Level1)
{
    ListenerModule module = ListenerModule::LISTENER_MODULE_DYNAMIC_START;
    int32_t fd = 1;
    SocketPktHead pktHead;
    int32_t ret = SetSocketPktHead(&pktHead);
    EXPECT_EQ(ret, SOFTBUS_OK);
    pktHead.module = MODULE_SESSION_KEY_AUTH;
    pktHead.len = AUTH_PKT_HEAD_LEN;
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    isOnWiFiDataReceivedSuccess = false;
    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    ret = SetSocketCallback(&socketCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);

    isOnWiFiDataReceivedSuccess = false;
    module = ListenerModule::AUTH_SESSION_KEY;
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);

    isOnWiFiDataReceivedSuccess = false;
    pktHead.module = MODULE_CONNECTION;
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_TRUE(isOnWiFiDataReceivedSuccess);
    UnsetSocketCallback();

    isOnWiFiDataReceivedSuccess = false;
    NotifyDataReceived(module, fd, &pktHead, data);
    EXPECT_FALSE(isOnWiFiDataReceivedSuccess);
}

/*
 * @tc.name: RECV_PACKET_HEAD_TEST_001
 * @tc.desc: recv packet head test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, RECV_PACKET_HEAD_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    SocketPktHead pktHead;
    (void)memset_s(&pktHead, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    int32_t ret = RecvPacketHead(AUTH, fd, &pktHead);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RECV_PACKET_DATA_TEST_001
 * @tc.desc: recv packet head test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, RECV_PACKET_DATA_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    SocketPktHead pktHead;
    uint8_t data[TEST_DATA_LEN] = { 0 };
    (void)memset_s(&pktHead, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    pktHead.module = MODULE_AUTH_CHANNEL;
    NotifyDataReceived(AUTH, fd, &pktHead, data);
    pktHead.module = MODULE_AUTH_MSG;
    NotifyDataReceived(AUTH, fd, &pktHead, data);
    pktHead.module = MODULE_CONNECTION;
    NotifyDataReceived(AUTH, fd, &pktHead, data);

    uint32_t len = TEST_DATA_LEN;
    uint8_t *packetData = RecvPacketData(fd, len);
    EXPECT_TRUE(packetData == nullptr);
}

/*
 * @tc.name: REQUIRE_AUTH_TCP_CONN_FD_LIST_LOCK_TEST_001
 * @tc.desc: Require list lock.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, REQUIRE_AUTH_TCP_CONN_FD_LIST_LOCK_TEST_001, TestSize.Level1)
{
    bool ret = RequireAuthTcpConnFdListLock();
    EXPECT_FALSE(ret);
    ReleaseAuthTcpConnFdListLock();

    int32_t result = AuthTcpConnFdLockInit();
    EXPECT_EQ(result, SOFTBUS_OK);

    ret = RequireAuthTcpConnFdListLock();
    EXPECT_TRUE(ret);
    ReleaseAuthTcpConnFdListLock();
    AuthTcpConnFdLockDeinit();
}

/*
 * @tc.name: ADD_AUTH_TCP_CONN_FD_ITEM_TEST_001
 * @tc.desc: AddAuthTcpConnFdItem test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, ADD_AUTH_TCP_CONN_FD_ITEM_TEST_001, TestSize.Level1)
{
    int32_t fd = 1;

    int32_t ret = AddAuthTcpConnFdItem(fd);
    EXPECT_TRUE(ret == SOFTBUS_LOCK_ERR);
    ret = AuthTcpConnFdLockInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AddAuthTcpConnFdItem(fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DeleteAuthTcpConnFdItemByConnId(fd);
    AuthTcpConnFdLockDeinit();
}

/*
 * @tc.name: IS_EXIST_AUTH_TCP_CONN_FD_ITEM_BY_COON_ID_TEST_001
 * @tc.desc: is exist FdItem test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, IS_EXIST_AUTH_TCP_CONN_FD_ITEM_BY_COON_ID_TEST_001, TestSize.Level1)
{
    int32_t fd = 1;
    bool ret = IsExistAuthTcpConnFdItemByConnId(fd);
    EXPECT_FALSE(ret);
    int32_t result = AuthTcpConnFdLockInit();
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = IsExistAuthTcpConnFdItemByConnId(fd);
    EXPECT_FALSE(ret);
    result = AddAuthTcpConnFdItem(fd);
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = IsExistAuthTcpConnFdItemByConnId(fd);
    EXPECT_TRUE(ret);
    DeleteAuthTcpConnFdItemByConnId(fd);
    AuthTcpConnFdLockDeinit();
}

/*
 * @tc.name: PROCESS_SOCKET_OUT_EVENT_TEST_001
 * @tc.desc: process socket out event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, PROCESS_SOCKET_OUT_EVENT_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    bool isClient = true;
    NotifyConnected(AUTH, fd, isClient);
    NotifyDisconnected(AUTH, fd);
    StopSocketListening(AUTH);

    int32_t ret = ProcessSocketOutEvent(AUTH, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_SOCKET_IN_EVENT_TEST_001
 * @tc.desc: process socket in event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, PROCESS_SOCKET_IN_EVENT_TEST_001, TestSize.Level1)
{
    int32_t fd = 1;
    int32_t ret = ProcessSocketInEvent(AUTH_USB, fd);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    int32_t result = AuthTcpConnFdLockInit();
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = ProcessSocketInEvent(AUTH_USB, fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AddAuthTcpConnFdItem(fd);
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = ProcessSocketInEvent(AUTH_USB, fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_DATA_HEAD);

    int32_t channelId = 0;
    SocketPktHead head;
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    (void)memset_s(&head, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    NotifyChannelDataReceived(channelId, &head, data);
    NotifyChannelDisconnected(channelId);

    ret = ProcessSocketInEvent(AUTH, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    AuthTcpConnFdLockDeinit();
}

/*
 * @tc.name: IS_ENHANCE_P2P_MODULE_ID_TEST_001
 * @tc.desc: is enhance p2p module id test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, IS_ENHANCE_P2P_MODULE_ID_TEST_001, TestSize.Level1)
{
    ListenerModule moduleId = ListenerModule::AUTH_SESSION_KEY;
    bool ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_FALSE(ret);

    moduleId = ListenerModule::AUTH_P2P;
    ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_FALSE(ret);

    moduleId = ListenerModule::AUTH_ENHANCED_P2P_START;
    ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: ON_CONNECT_EVENT_TEST_001
 * @tc.desc: on connect event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, ON_CONNECT_EVENT_TEST_001, TestSize.Level1)
{
    ListenerModule module = AUTH;
    int32_t cfd = -1;
    ConnectOption clientAddr;
    (void)memset_s(&clientAddr, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    cfd = 1;
    ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL);

    module = AUTH_USB;
    ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL);

    module = AUTH_P2P;
    ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL);

    module = AUTH_RAW_P2P_CLIENT;
    ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL);
}

/*
 * @tc.name: ON_DATA_EVENT_TEST_001
 * @tc.desc: on data event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, ON_DATA_EVENT_TEST_001, TestSize.Level1)
{
    ListenerModule module = AUTH_P2P;
    int32_t events = SOFTBUS_SOCKET_OUT;
    int32_t fd = 0;
    int32_t ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    events = SOFTBUS_SOCKET_IN;
    ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    events = SOFTBUS_SOCKET_EXCEPTION;
    ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SET_SOCKET_CALLBACK_TEST_001
 * @tc.desc: set socket callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SET_SOCKET_CALLBACK_TEST_001, TestSize.Level1)
{
    int32_t ret = SetSocketCallback(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: START_SOCKET_LISTENING_TEST_001
 * @tc.desc: start socket listening test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, START_SOCKET_LISTENING_TEST_001, TestSize.Level1)
{
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "192.168.12.1",
            .port = 22,
            .moduleId = AUTH,
            .protocol = LNN_PROTOCOL_IP,
        },
    };
    int32_t ret = StartSocketListening(AUTH, &info);
    EXPECT_NE(ret, SOFTBUS_OK);

    StopSocketListening(AUTH);
}

/*
 * @tc.name: AUTH_TCP_CREATE_LISTENER_TEST_001
 * @tc.desc: AuthTcpCreateListener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_TCP_CREATE_LISTENER_TEST_001, TestSize.Level1)
{
    ListenerModule module = PROXY;
    int32_t fd = 1;
    TriggerType trigger = READ_TRIGGER;

    int32_t ret = AuthTcpCreateListener(module, fd, trigger);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: SOCKET_GET_CONN_INFO_TEST_001
 * @tc.desc: socket get conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_GET_CONN_INFO_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    AuthConnInfo connInfo;
    bool isServer;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = SocketGetConnInfo(fd, nullptr, &isServer, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = SocketGetConnInfo(fd, &connInfo, nullptr, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = SocketGetConnInfo(fd, &connInfo, &isServer, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOCKET_GET_CONN_INFO_TEST_002
 * @tc.desc: Get conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_GET_CONN_INFO_TEST_002, TestSize.Level1)
{
    int32_t fd = -1;
    AuthConnInfo connInfo;
    bool isServer = true;
    int32_t ifnameIdx = 1;

    SetSessionKeyListenerModule(fd);
    StopSessionKeyListening(fd);
    fd = USB_IF;
    SetSessionKeyListenerModule(fd);
    StopSessionKeyListening(fd);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = SocketGetConnInfo(fd, nullptr, &isServer, ifnameIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SocketGetConnInfo(fd, &connInfo, nullptr, ifnameIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SocketGetConnInfo(fd, &connInfo, &isServer, ifnameIdx);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_PEER_SOCKET_ADDR_FAIL);

    fd = WLAN_IF;
    ret = SocketGetConnInfo(fd, &connInfo, &isServer, ifnameIdx);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_PEER_SOCKET_ADDR_FAIL);
}

/*
 * @tc.name: SOCKET_CONNECT_INNER_TEST_001
 * @tc.desc: SocketConnectInner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_CONNECT_INNER_TEST_001, TestSize.Level1)
{
    const char *localIp = "192.168.11.22";
    const char *peerIp = "192.168.11.33";
    int32_t ret = SocketConnectInner(nullptr, peerIp, 37025, AUTH, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = SocketConnectInner(localIp, nullptr, 37025, AUTH, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = SocketConnectInner(localIp, peerIp, 37025, AUTH, true);
    EXPECT_TRUE(ret == SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR);
}

/*
 * @tc.name: SOCKET_CONNECT_DEVICE_WITH_APP_IP_TEST_001
 * @tc.desc: SocketConnectDeviceWithAllIp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_CONNECT_DEVICE_WITH_APP_IP_TEST_001, TestSize.Level1)
{
    const char *localIp = "192.168.11.22";
    const char *peerIp = "192.168.11.33";
    int32_t ret = SocketConnectDeviceWithAllIp(localIp, peerIp, 37025, true);
    EXPECT_EQ(ret, SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR);
}

/*
 * @tc.name: SOCKET_SET_DEVICE_TEST_001
 * @tc.desc: Socket set device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_SET_DEVICE_TEST_001, TestSize.Level1)
{
    int32_t fd = -1;
    bool isBlockMode = true;
    int32_t ret = SocketSetDevice(fd, isBlockMode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);

    fd = 1;
    ret = SocketSetDevice(fd, isBlockMode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
}

/*
 * @tc.name: SET_TCP_KEEP_ALIVE_AND_IP_TOS_TEST_001
 * @tc.desc: SetTcpKeepaliveAndIpTos test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SET_TCP_KEEP_ALIVE_AND_IP_TOS_TEST_001, TestSize.Level1)
{
    bool isBlockMode = true;
    int32_t ifnameIdx = 1;
    TriggerType triggerMode = TriggerType::READ_TRIGGER;
    ListenerModule module = PROXY;
    int32_t fd = -1;
    int32_t ret = SetTcpKeepaliveAndIpTos(isBlockMode, ifnameIdx, triggerMode, module, fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fd = 1;
    ret = SetTcpKeepaliveAndIpTos(isBlockMode, ifnameIdx, triggerMode, module, fd);
    EXPECT_EQ(ret, SOFTBUS_ADAPTER_ERR);
}

/*
 * @tc.name: SOCKET_CONNECT_DEVICE_TEST_001
 * @tc.desc: SocketConnectDevice test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_CONNECT_DEVICE_TEST_001, TestSize.Level1)
{
    const char *addr = "192.168.11.44";
    int32_t port = 37025;
    bool isBlockMode = true;
    int32_t ifnameIdx = 1;
    int32_t ret = SocketConnectDevice(nullptr, port, isBlockMode, ifnameIdx);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = SocketConnectDevice(addr, port, isBlockMode, ifnameIdx);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
}

/*
 * @tc.name: NIP_SOCKET_CONNECT_DEVICE_TEST_001
 * @tc.desc: NipSocketConnectDevice test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NIP_SOCKET_CONNECT_DEVICE_TEST_001, TestSize.Level1)
{
    const char *addr = "192.168.11.44";
    int32_t ret = NipSocketConnectDevice(AUTH, addr, 37025, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = NipSocketConnectDevice(AUTH, nullptr, 37025, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
}

/*
 * @tc.name: SOCKET_POST_BYTES_TEST_001
 * @tc.desc: Socket post bytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_POST_BYTES_TEST_001, TestSize.Level1)
{
    int32_t fd = 1;
    AuthDataHead dataHead = {
        .dataType = 1,
        .module = AUTH,
        .seq = 2,
        .flag = 3,
        .len = AUTH_PKT_HEAD_LEN,
    };
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };

    int32_t ret = SocketPostBytes(fd, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SocketPostBytes(fd, &dataHead, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SocketPostBytes(fd, &dataHead, data);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    int32_t result = AuthTcpConnFdLockInit();
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = SocketPostBytes(fd, &dataHead, data);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);

    dataHead.module = AUTH_USB;
    ret = SocketPostBytes(fd, &dataHead, data);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);
}

/*
 * @tc.name: NOTIFY_CHANNEL_DATA_RECEIVED_TEST_001
 * @tc.desc: Notification of receipt of data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_CHANNEL_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    SocketPktHead pktHead;
    int32_t ret = SetSocketPktHead(&pktHead);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    int32_t channelId = 1;
    isOnDataReceivedSuccess = false;
    NotifyChannelDataReceived(channelId, &pktHead, data);
    EXPECT_FALSE(isOnDataReceivedSuccess);

    pktHead.module = MODULE_AUTH_MSG;
    AuthChannelListener listenerTestOne = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnect,
    };
    AuthChannelListener listenerTestTwo = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnect,
    };
    ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RegAuthChannelListener(MODULE_AUTH_MSG, &listenerTestTwo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyChannelDataReceived(channelId, &pktHead, data);
    EXPECT_TRUE(isOnDataReceivedSuccess);
    UnregAuthChannelListener(MODULE_AUTH_MSG);
    UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
}

/*
 * @tc.name: NOTIFY_CHANNEL_DISCONNECTED_TEST_001
 * @tc.desc: Notification channel disconnected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NOTIFY_CHANNEL_DISCONNECTED_TEST_001, TestSize.Level1)
{
    int32_t channelId = 1;
    isOnDisconnectSuccess = false;
    NotifyChannelDisconnected(channelId);
    EXPECT_FALSE(isOnDisconnectSuccess);

    AuthChannelListener listenerTestOne = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnect,
    };
    int32_t ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyChannelDisconnected(channelId);
    EXPECT_TRUE(isOnDisconnectSuccess);
    UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
}

/*
 * @tc.name: REG_AUTH_CHANNEL_LISTENER_TEST_001
 * @tc.desc: register listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, REG_AUTH_CHANNEL_LISTENER_TEST_001, TestSize.Level1)
{
    int32_t ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AuthChannelListener listenerTestOne = {
        .onDataReceived = nullptr,
        .onDisconnected = OnDisconnect,
    };
    ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listenerTestOne.onDataReceived = OnDataReceived;
    ret = RegAuthChannelListener(MODULE_AUTH_CHANNEL, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = RegAuthChannelListener(MODULE_AUTH_SDK, &listenerTestOne);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    UnregAuthChannelListener(MODULE_AUTH_CHANNEL);
}

/*
 * @tc.name: AUTH_OPEN_CHANNEL_WITH_ALL_IP_TEST_001
 * @tc.desc: AuthOpenChannelWithAllIp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_OPEN_CHANNEL_WITH_ALL_IP_TEST_001, TestSize.Level1)
{
    const char *localIp = "192.168.11.22";
    const char *remoteIp = "192.168.11.33";
    int32_t ret = AuthOpenChannelWithAllIp(localIp, remoteIp, 37025);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
    ret = AuthOpenChannelWithAllIp(nullptr, remoteIp, 37025);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenChannelWithAllIp(localIp, nullptr, 37025);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenChannelWithAllIp(localIp, remoteIp, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_OPEN_CHANNEL_WITH_ALL_IP_TEST_001
 * @tc.desc: open channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_OPEN_CHANNEL_TEST_001, TestSize.Level1)
{
    const char *addr = "192.168.11.22";
    int32_t port = 0;
    int32_t ifnameIdx = 1;
    int32_t ret = AuthOpenChannel(nullptr, port, ifnameIdx);
    EXPECT_EQ(ret, INVALID_CHANNEL_ID);

    ret = AuthOpenChannel(addr, port, ifnameIdx);
    EXPECT_EQ(ret, INVALID_CHANNEL_ID);

    port = 1;
    ret = AuthOpenChannel(addr, port, ifnameIdx);
    EXPECT_EQ(ret, INVALID_CHANNEL_ID);
}

/*
 * @tc.name: AUTH_POST_CHANNEL_DATA_TEST_001
 * @tc.desc: post channel data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_POST_CHANNEL_DATA_TEST_001, TestSize.Level1)
{
    int32_t channelId = -1;
    AuthChannelData channelData = {
        .module = AUTH,
        .flag = 2,
        .seq = 3,
        .len = 0,
    };
    int32_t ret = AuthPostChannelData(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    channelId = 1;
    ret = AuthPostChannelData(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AuthPostChannelData(channelId, &channelData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t data = 123;
    channelData.data = &data;
    ret = AuthPostChannelData(channelId, &channelData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    channelData.len = AUTH_PKT_HEAD_LEN;
    ret = AuthPostChannelData(channelId, &channelData);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);
}

/*
 * @tc.name: GET_TCP_KEEP_ALIVE_OPTION_BY_CYCLE_TEST_001
 * @tc.desc: get option test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, GET_TCP_KEEP_ALIVE_OPTION_BY_CYCLE_TEST_001, TestSize.Level1)
{
    ModeCycle cycle = (ModeCycle)1;
    TcpKeepaliveOption option = { 0 };
    int32_t ret = GetTcpKeepaliveOptionByCycle(cycle, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetTcpKeepaliveOptionByCycle(cycle, &option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cycle = HIGH_FREQ_CYCLE;
    ret = GetTcpKeepaliveOptionByCycle(cycle, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cycle = MID_FREQ_CYCLE;
    ret = GetTcpKeepaliveOptionByCycle(cycle, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cycle = LOW_FREQ_CYCLE;
    ret = GetTcpKeepaliveOptionByCycle(cycle, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cycle = DEFAULT_FREQ_CYCLE;
    ret = GetTcpKeepaliveOptionByCycle(cycle, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_SET_TCP_KEEP_ALIVE_OPTION_TEST_001
 * @tc.desc: set option test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_SET_TCP_KEEP_ALIVE_OPTION_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    ModeCycle cycle = (ModeCycle)1;
    int32_t ret = AuthSetTcpKeepaliveOption(fd, cycle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fd = 1;
    ret = AuthSetTcpKeepaliveOption(fd, cycle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cycle = (ModeCycle)666;
    ret = AuthSetTcpKeepaliveOption(fd, cycle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cycle = MID_FREQ_CYCLE;
    ret = AuthSetTcpKeepaliveOption(fd, cycle);
    EXPECT_EQ(ret, SOFTBUS_ADAPTER_ERR);
}

/*
 * @tc.name: GET_CONNECT_OPTION_BY_IFNAME_TEST_001
 * @tc.desc: GetConnectOptionByIfname test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, GET_CONNECT_OPTION_BY_IFNAME_TEST_001, TestSize.Level1)
{
    int32_t ifnameIdx = 0;
    int32_t port = 1;

    ConnectOption option = GetConnectOptionByIfname(ifnameIdx, port);
    EXPECT_TRUE(option.socketOption.moduleId == AUTH);
    ifnameIdx = 1;
    option = GetConnectOptionByIfname(ifnameIdx, port);
    EXPECT_TRUE(option.socketOption.moduleId == AUTH_USB);
}
} // namespace OHOS
