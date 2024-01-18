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

#include <string>
#include <gtest/gtest.h>
#include <securec.h>

#include "socket.h"
#include "softbus_error_code.h"

#define SOCKET_NAME_MAX_LEN          255
#define SOCKET_NAME_INVALID_LEN      (SOCKET_NAME_MAX_LEN + 1)
#define SOCKET_PKG_NAME_MAX_LEN      64
#define SOCKET_PKG_NAME_INVALID_LEN  (SOCKET_PKG_NAME_MAX_LEN + 1)
#define SOCKET_NETWORKID_MAX_LEN     64
#define SOCKET_NETWORKID_INVALID_LEN (SOCKET_NETWORKID_MAX_LEN + 1)

using namespace testing::ext;
namespace OHOS {
static std::string g_pkgName = "dms";
static std::string g_socketName = "ohos.distributedschedule.dms.test.client";
static std::string g_socketPeerName = "ohos.distributedschedule.dms.test.server";
static std::string g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";

class TransClientSocketServiceTest : public testing::Test {
public:
    TransClientSocketServiceTest() { }
    ~TransClientSocketServiceTest() { }
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override { }
    void TearDown() override { }
};

/**
 * @tc.name: SocketName001
 * @tc.desc: call Socket function with different socket name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketName001, TestSize.Level1)
{
    SocketInfo info;
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = -1;

    // socket name is null pointer
    info.name = nullptr;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket name is zero
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 0, SOCKET_NAME_INVALID_LEN + 1);
    info.name = socketName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket name greater than 255
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 'a', SOCKET_NAME_INVALID_LEN);
    info.name = socketName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SocketPeerName001
 * @tc.desc: call Socket function with different socket peerName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerName001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;
    int32_t socketId = -1;

    // the length of socket peerName is zero
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 0, SOCKET_NAME_INVALID_LEN + 1);
    info.peerName = socketName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket name greater than 255
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 'a', SOCKET_NAME_INVALID_LEN);
    info.peerName = socketName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SocketPeerNetworkId001
 * @tc.desc: call Socket function with different socket peerNetworkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerNetworkId001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;
    int32_t socketId = -1;

    // the length of socket peerNetworkId is zero
    char networkId[SOCKET_NETWORKID_INVALID_LEN + 1];
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 0, SOCKET_NETWORKID_INVALID_LEN + 1);
    info.peerNetworkId = networkId;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket peerNetworkId greater than 65
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 'a', SOCKET_NETWORKID_INVALID_LEN);
    info.peerNetworkId = networkId;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SocketPkgName001
 * @tc.desc: call Socket function with different socket pkgName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPkgName001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = -1;

    // socket name is null pointer
    info.pkgName = nullptr;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket name is zero
    char pkgName[SOCKET_PKG_NAME_INVALID_LEN + 1];
    memset_s(pkgName, SOCKET_PKG_NAME_INVALID_LEN + 1, 0, SOCKET_PKG_NAME_INVALID_LEN + 1);
    info.pkgName = pkgName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);

    // the length of socket name greater than 255
    memset_s(pkgName, SOCKET_PKG_NAME_INVALID_LEN + 1, 'a', SOCKET_PKG_NAME_INVALID_LEN);
    info.name = pkgName;
    socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS