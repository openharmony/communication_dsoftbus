/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "client_trans_socket_option.h"
#include "inner_socket.h"
#include "socket.h"
#include "softbus_error_code.h"

#define SOCKET_NAME_MAX_LEN          255
#define SOCKET_NAME_INVALID_LEN      (SOCKET_NAME_MAX_LEN + 1)
#define SOCKET_PKG_NAME_MAX_LEN      64
#define SOCKET_PKG_NAME_INVALID_LEN  (SOCKET_PKG_NAME_MAX_LEN + 1)
#define SOCKET_NETWORKID_MAX_LEN     64
#define SOCKET_NETWORKID_INVALID_LEN (SOCKET_NETWORKID_MAX_LEN + 1)
#define DATA_LENS 32
#define INVALID_VALUE (-1)

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

/*
 * @tc.name: SocketName001
 * @tc.desc: test Socket with socket name is null pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketName001, TestSize.Level1)
{
    SocketInfo info;
    info.name = nullptr;
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketName002
 * @tc.desc: test Socket with socket name length is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketName002, TestSize.Level1)
{
    SocketInfo info;
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 0, SOCKET_NAME_INVALID_LEN + 1);
    info.name = socketName;
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketName003
 * @tc.desc: test Socket with socket name length greater than max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketName003, TestSize.Level1)
{
    SocketInfo info;
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 'a', SOCKET_NAME_INVALID_LEN);
    info.name = socketName;
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPeerName001
 * @tc.desc: test Socket with peerName length is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerName001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 0, SOCKET_NAME_INVALID_LEN + 1);
    info.peerName = socketName;
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPeerName002
 * @tc.desc: test Socket with peerName length greater than max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerName002, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    char socketName[SOCKET_NAME_INVALID_LEN + 1];
    memset_s(socketName, SOCKET_NAME_INVALID_LEN + 1, 'a', SOCKET_NAME_INVALID_LEN);
    info.peerName = socketName;
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPeerNetworkId001
 * @tc.desc: test Socket with peerNetworkId length is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerNetworkId001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    char networkId[SOCKET_NETWORKID_INVALID_LEN + 1];
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 0, SOCKET_NETWORKID_INVALID_LEN + 1);
    info.peerNetworkId = networkId;
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPeerNetworkId002
 * @tc.desc: test Socket with peerNetworkId length greater than max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPeerNetworkId002, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    char networkId[SOCKET_NETWORKID_INVALID_LEN + 1];
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 'a', SOCKET_NETWORKID_INVALID_LEN);
    info.peerNetworkId = networkId;
    info.pkgName = const_cast<char *>(g_pkgName.c_str());
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPkgName001
 * @tc.desc: test Socket with pkgName is null pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPkgName001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    info.pkgName = nullptr;
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPkgName002
 * @tc.desc: test Socket with pkgName length is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPkgName002, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    char pkgName[SOCKET_PKG_NAME_INVALID_LEN + 1];
    memset_s(pkgName, SOCKET_PKG_NAME_INVALID_LEN + 1, 0, SOCKET_PKG_NAME_INVALID_LEN + 1);
    info.pkgName = pkgName;
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketPkgName003
 * @tc.desc: test Socket with pkgName length greater than max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SocketPkgName003, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = const_cast<char *>(g_socketPeerName.c_str());
    info.peerNetworkId = const_cast<char *>(g_networkId.c_str());
    char pkgName[SOCKET_PKG_NAME_INVALID_LEN + 1];
    memset_s(pkgName, SOCKET_PKG_NAME_INVALID_LEN + 1, 'a', SOCKET_PKG_NAME_INVALID_LEN);
    info.pkgName = pkgName;
    info.dataType = DATA_TYPE_MESSAGE;

    int32_t socketId = Socket(info);
    ASSERT_EQ(socketId, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DataType001
 * @tc.desc: test Socket with different data types, all produce ADDPKG_FAILED
 *           when no session server is created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DataType001, TestSize.Level1)
{
    SocketInfo info;
    info.name = const_cast<char *>(g_socketName.c_str());
    info.peerName = nullptr;
    info.peerNetworkId = nullptr;
    info.pkgName = const_cast<char *>(g_pkgName.c_str());

    for (int32_t type = DATA_TYPE_MESSAGE; type < DATA_TYPE_BUTT; type++) {
        info.dataType = static_cast<TransDataType>(type);
        int32_t socketId = Socket(info);
        EXPECT_EQ(socketId, SOFTBUS_TRANS_SESSION_ADDPKG_FAILED);
    }
}

static void OnShutdown(int32_t socket, ShutdownReason reason)
{
    return;
}

/*
 * @tc.name: DfsBind001
 * @tc.desc: test DfsBind with invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind001, TestSize.Level1)
{
    ISocketListener listener;
    int32_t ret = DfsBind(-1, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DfsBind002
 * @tc.desc: test DfsBind with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind002, TestSize.Level1)
{
    int32_t ret = DfsBind(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DfsBind003
 * @tc.desc: test DfsBind with listener that has no OnShutdown callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind003, TestSize.Level1)
{
    ISocketListener listener = { 0 };
    int32_t ret = DfsBind(1, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DfsBind004
 * @tc.desc: test DfsBind with valid listener but session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind004, TestSize.Level1)
{
    ISocketListener listener = { .OnShutdown = OnShutdown };
    int32_t ret = DfsBind(1, &listener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: SetSocketOpt001
 * @tc.desc: test SetSocketOpt with invalid level
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelInvalid = OPT_LEVEL_BUTT;
    OptType optTypeInvalid = (OptType)-1;
    int32_t ret = SetSocketOpt(socket, levelInvalid, optTypeInvalid, nullptr, -1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetSocketOpt002
 * @tc.desc: test SetSocketOpt with valid level but invalid optType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt002, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeInvalid = (OptType)-1;
    int32_t ret = SetSocketOpt(socket, levelValid, optTypeInvalid, nullptr, -1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetSocketOpt003
 * @tc.desc: test SetSocketOpt with valid level and optType but null optValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt003, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t ret = SetSocketOpt(socket, levelValid, optTypeValid, nullptr, -1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetSocketOpt004
 * @tc.desc: test SetSocketOpt with valid params but invalid optValueSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt004, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t optValueValid = 1234;
    void *temp = &optValueValid;
    int32_t ret = SetSocketOpt(socket, levelValid, optTypeValid, temp, -1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetSocketOpt005
 * @tc.desc: test SetSocketOpt with all valid params, optType in common range,
 *           SetOpt for OPT_TYPE_MAX_BUFFER is NULL so returns NOT_IMPLEMENT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt005, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t optValueValid = 1234;
    void *temp = &optValueValid;
    int32_t optValueSizeValid = sizeof(int32_t);
    int32_t ret = SetSocketOpt(socket, levelValid, optTypeValid, temp, optValueSizeValid);
    ASSERT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SetSocketOpt006
 * @tc.desc: test SetSocketOpt with OPT_TYPE_FIRST_PACKAGE (SetOpt is NULL),
 *           returns NOT_IMPLEMENT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt006, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_SOFTBUS;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    uint32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t valueSize = sizeof(uint32_t);
    int32_t ret = SetSocketOpt(socket, level, optType, temp, valueSize);
    ASSERT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: GetSocketOpt001
 * @tc.desc: test GetSocketOpt with invalid level
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelInvalid = OPT_LEVEL_BUTT;
    OptType optTypeInvalid = (OptType)-1;
    int32_t ret = GetSocketOpt(socket, levelInvalid, optTypeInvalid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOpt002
 * @tc.desc: test GetSocketOpt with valid level but invalid optType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt002, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeInvalid = (OptType)-1;
    int32_t ret = GetSocketOpt(socket, levelValid, optTypeInvalid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOpt003
 * @tc.desc: test GetSocketOpt with valid level and optType but null optValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt003, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t ret = GetSocketOpt(socket, levelValid, optTypeValid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOpt004
 * @tc.desc: test GetSocketOpt with valid params but null optValueSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt004, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t ret = GetSocketOpt(socket, levelValid, optTypeValid, temp, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOpt005
 * @tc.desc: test GetSocketOpt with all valid params, param check passes,
 *           optType in common range, result depends on session state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt005, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t valueSize = 0;
    int32_t *optValueSizeValid = &valueSize;
    int32_t ret = GetSocketOpt(socket, levelValid, optTypeValid, temp, optValueSizeValid);
    ASSERT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOpt006
 * @tc.desc: test GetSocketOpt with OPT_TYPE_FIRST_PACKAGE (GetOpt is NULL),
 *           returns NOT_IMPLEMENT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt006, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_SOFTBUS;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    uint32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t valueSize = sizeof(uint32_t);
    int32_t *optValueSizeValid = &valueSize;
    int32_t ret = GetSocketOpt(socket, level, optType, temp, optValueSizeValid);
    ASSERT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RegisterRelationChecker001
 * @tc.desc: test RegisterRelationChecker with null relationChecker
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, RegisterRelationChecker001, TestSize.Level1)
{
    int32_t ret = RegisterRelationChecker(nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCommonSocketOpt001
 * @tc.desc: test SetCommonSocketOpt with null optValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCommonSocketOpt002
 * @tc.desc: test SetCommonSocketOpt with zero optValueSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt002, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCommonSocketOpt003
 * @tc.desc: test SetCommonSocketOpt with OPT_TYPE_FIRST_PACKAGE (SetOpt is NULL)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt003, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SetCommonSocketOpt004
 * @tc.desc: test SetCommonSocketOpt with OPT_TYPE_MAX_IDLE_TIMEOUT and invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt004, TestSize.Level1)
{
    int32_t socket = INVALID_VALUE;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCommonSocketOpt005
 * @tc.desc: test SetCommonSocketOpt with OPT_TYPE_MAX_IDLE_TIMEOUT and valid socket,
 *           session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt005, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: SetCommonSocketOpt006
 * @tc.desc: test SetCommonSocketOpt with OPT_TYPE_NEED_ACK and invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt006, TestSize.Level1)
{
    int32_t socket = INVALID_VALUE;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_NEED_ACK;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCommonSocketOpt007
 * @tc.desc: test SetCommonSocketOpt with OPT_TYPE_NEED_ACK and valid socket,
 *           wrong optValueSize (not sizeof(bool))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt007, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_NEED_ACK;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetCommonSocketOpt001
 * @tc.desc: test GetCommonSocketOpt with null optValue and null optValueSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetCommonSocketOpt002
 * @tc.desc: test GetCommonSocketOpt with null optValue and valid optValueSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt002, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetCommonSocketOpt003
 * @tc.desc: test GetCommonSocketOpt with OPT_TYPE_FIRST_PACKAGE (GetOpt is NULL)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt003, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: GetCommonSocketOpt004
 * @tc.desc: test GetCommonSocketOpt with OPT_TYPE_SUPPORT_ACK and invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt004, TestSize.Level1)
{
    int32_t socket = INVALID_VALUE;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_SUPPORT_ACK;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetCommonSocketOpt005
 * @tc.desc: test GetCommonSocketOpt with OPT_TYPE_SUPPORT_ACK and valid socket,
 *           session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt005, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_SUPPORT_ACK;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: GetCommonSocketOpt006
 * @tc.desc: test GetCommonSocketOpt with OPT_TYPE_MAX_IDLE_TIMEOUT and invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt006, TestSize.Level1)
{
    int32_t socket = INVALID_VALUE;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetCommonSocketOpt007
 * @tc.desc: test GetCommonSocketOpt with OPT_TYPE_MAX_IDLE_TIMEOUT and valid socket,
 *           session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt007, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: BindAsync001
 * @tc.desc: test BindAsync with Socket returning ADDPKG_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, BindAsync001, TestSize.Level1)
{
    SocketInfo info = {
        .name = const_cast<char *>(g_socketName.c_str()),
        .pkgName = const_cast<char *>(g_pkgName.c_str()),
        .peerName = const_cast<char *>(g_socketPeerName.c_str()),
        .peerNetworkId = nullptr,
        .dataType = DATA_TYPE_MESSAGE,
    };

    int32_t socket = Socket(info);
    EXPECT_EQ(socket, SOFTBUS_TRANS_SESSION_ADDPKG_FAILED);
}

/*
 * @tc.name: BindAsync002
 * @tc.desc: test BindAsync with invalid socket, timer returns INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, BindAsync002, TestSize.Level1)
{
    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
    };
    int32_t ret = BindAsync(INVALID_VALUE, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: EvaluateQos001
 * @tc.desc: test EvaluateQos with valid params, access token denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, EvaluateQos001, TestSize.Level1)
{
    TransDataType dataType = DATA_TYPE_BYTES;
    QosTV qos;
    uint32_t qosCount = 1;
    int32_t ret = EvaluateQos(const_cast<char *>(g_networkId.c_str()), dataType, &qos, qosCount);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: EvaluateQos002
 * @tc.desc: test EvaluateQos with null networkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, EvaluateQos002, TestSize.Level1)
{
    TransDataType dataType = DATA_TYPE_BYTES;
    uint32_t qosCount = 1;
    int32_t ret = EvaluateQos(nullptr, dataType, nullptr, qosCount);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetMtuSize001
 * @tc.desc: test GetMtuSize with invalid socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetMtuSize001, TestSize.Level1)
{
    int32_t socket = INVALID_VALUE;
    uint32_t mtuSize = 0;
    int32_t ret = GetMtuSize(socket, &mtuSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PrivilegeShutdown001
 * @tc.desc: test PrivilegeShutdown with null peerNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, PrivilegeShutdown001, TestSize.Level1)
{
    uint64_t tokenId = 0;
    int32_t pid = 0;
    int32_t ret = PrivilegeShutdown(tokenId, pid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PrivilegeShutdown002
 * @tc.desc: test PrivilegeShutdown with valid params, access token denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, PrivilegeShutdown002, TestSize.Level1)
{
    uint64_t tokenId = 0;
    int32_t pid = 0;
    int32_t ret = PrivilegeShutdown(tokenId, pid, const_cast<char *>(g_networkId.c_str()));
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: SetAccessInfo001
 * @tc.desc: test SetAccessInfo with invalid socket, session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetAccessInfo001, TestSize.Level1)
{
    int32_t socket = 1;
    SocketAccessInfo accessInfo = {
        .userId = 1,
        .businessAccountId = (char *)"accountId",
    };

    int32_t ret = SetAccessInfo(socket, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ServiceSocketPeerNetworkId001
 * @tc.desc: test ServiceSocket with null peerNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, ServiceSocketPeerNetworkId001, TestSize.Level1)
{
    ServiceSocketInfo info;
    info.peerNetworkId = nullptr;
    int32_t socket = ServiceSocket(info);
    EXPECT_EQ(socket, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ServiceSocketPeerNetworkId002
 * @tc.desc: test ServiceSocket with peerNetworkId length is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, ServiceSocketPeerNetworkId002, TestSize.Level1)
{
    ServiceSocketInfo info;
    char networkId[SOCKET_NETWORKID_INVALID_LEN + 1];
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 0, SOCKET_NETWORKID_INVALID_LEN + 1);
    info.peerNetworkId = networkId;
    info.dataType = static_cast<TransDataType>(DATA_TYPE_BYTES);
    info.serviceId = 50;
    info.peerServiceId = 58;
    int32_t socket = ServiceSocket(info);
    EXPECT_EQ(socket, SOFTBUS_TRANS_SESSION_ADDPKG_FAILED);
}

/*
 * @tc.name: ServiceSocketPeerNetworkId003
 * @tc.desc: test ServiceSocket with peerNetworkId length greater than max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, ServiceSocketPeerNetworkId003, TestSize.Level1)
{
    ServiceSocketInfo info;
    char networkId[SOCKET_NETWORKID_INVALID_LEN + 1];
    memset_s(networkId, SOCKET_NETWORKID_INVALID_LEN + 1, 'a', SOCKET_NETWORKID_INVALID_LEN);
    info.peerNetworkId = networkId;
    info.dataType = static_cast<TransDataType>(DATA_TYPE_BYTES);
    info.serviceId = 50;
    info.peerServiceId = 58;
    int32_t socket = ServiceSocket(info);
    ASSERT_EQ(socket, SOFTBUS_TRANS_SESSION_ADDPKG_FAILED);
}

/*
 * @tc.name: SetSocketOptKeyTypeInvalidParamTest001
 * @tc.desc: test SetSocketOpt with OPT_TYPE_KEY_TYPE invalid param combinations that
 *           hit the SOFTBUS_INVALID_PARAM branch (invalid socket, level, null optValue,
 *           invalid optValueSize)
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOptKeyTypeInvalidParamTest001, TestSize.Level1)
{
    KeyType keyType = KEY_TYPE_NORMAL;
    int32_t keyTypeSize = static_cast<int32_t>(sizeof(KeyType));
    int32_t ret = SetSocketOpt(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, &keyType, keyTypeSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(1, OPT_LEVEL_BUTT, OPT_TYPE_KEY_TYPE, &keyType, keyTypeSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(1, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, nullptr, keyTypeSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(1, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, &keyType, -1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetSocketOptKeyTypeInvalidParamTest001
 * @tc.desc: test GetSocketOpt with OPT_TYPE_KEY_TYPE invalid param combinations that
 *           hit the SOFTBUS_INVALID_PARAM branch (invalid socket, level, null optValue,
 *           null optValueSize)
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOptKeyTypeInvalidParamTest001, TestSize.Level1)
{
    KeyType keyType = KEY_TYPE_DEFAULT;
    int32_t optValueSize = 0;
    int32_t ret = GetSocketOpt(0, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, &keyType, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(1, OPT_LEVEL_BUTT, OPT_TYPE_KEY_TYPE, &keyType, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(1, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(1, OPT_LEVEL_SOFTBUS, OPT_TYPE_KEY_TYPE, &keyType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
