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

/**
 * @tc.name: SocketPkgName001
 * @tc.desc: call Socket function with different data type.
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

/**
 * @tc.name: DfsBind001
 * @tc.desc: call DfsBind function with invalid socket or listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind001, TestSize.Level1)
{
    ISocketListener listener;
    int32_t ret = DfsBind(-1, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DfsBind(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DfsBind(1, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

static void OnShutdown(int32_t socket, ShutdownReason reason)
{
    return;
}

/**
 * @tc.name: DfsBind002
 * @tc.desc: call DfsBind function with offline socket.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, DfsBind002, TestSize.Level1)
{
    ISocketListener listener = { .OnShutdown = OnShutdown };
    int32_t ret = DfsBind(1, &listener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: SetSocketOpt001
 * @tc.desc: call SetSocketOpt function with with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetSocketOpt001, TestSize.Level1)
{
    OptLevel levelInvalid = OPT_LEVEL_BUTT;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeInvalid = (OptType)-1;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t socket = 1;
    int32_t optValueValid = 1234;
    void *temp = &optValueValid;
    int32_t optValueSizeInvalid = -1;
    int32_t optValueSizeValid = sizeof(int32_t);
    int32_t ret = SetSocketOpt(socket, levelInvalid, optTypeInvalid, nullptr, optValueSizeInvalid);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(socket, levelValid, optTypeInvalid, nullptr, optValueSizeInvalid);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(socket, levelValid, optTypeValid, nullptr, optValueSizeInvalid);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(socket, levelValid, optTypeValid, temp, optValueSizeInvalid);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSocketOpt(socket, levelValid, optTypeValid, temp, optValueSizeValid);
    ASSERT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetSocketOpt001
 * @tc.desc: call GetSocketOpt function with with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt001, TestSize.Level1)
{
    OptLevel levelInvalid = OPT_LEVEL_BUTT;
    OptLevel levelValid = OPT_LEVEL_SOFTBUS;
    OptType optTypeInvalid = (OptType)-1;
    OptType optTypeValid = OPT_TYPE_MAX_BUFFER;
    int32_t socket = 1;
    int32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t valueSize = 0;
    int32_t *optValueSizeValid = &valueSize;
    int32_t ret = GetSocketOpt(socket, levelInvalid, optTypeInvalid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(socket, levelValid, optTypeInvalid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(socket, levelValid, optTypeValid, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(socket, levelValid, optTypeValid, temp, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketOpt(socket, levelValid, optTypeValid, temp, optValueSizeValid);
    ASSERT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetSocketOpt002
 * @tc.desc: call GetSocketOpt function with with valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetSocketOpt002, TestSize.Level1)
{
    OptLevel level = OPT_LEVEL_SOFTBUS;
    OptType optType = OPT_TYPE_MAX_BUFFER;
    int socketId = 1;
    uint32_t optValueValid = 0;
    void *temp = &optValueValid;
    int32_t valueSize = sizeof(uint32_t);
    int32_t *optValueSizeValid = &valueSize;
    int32_t ret = SetSocketOpt(socketId, level, optType, temp, valueSize);
    ASSERT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = GetSocketOpt(socketId, level, optType, temp, optValueSizeValid);
    ASSERT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: RegisterRelationChecker001
 * @tc.desc: call RegisterRelationChecker function with with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, RegisterRelationChecker001, TestSize.Level1)
{
    int32_t ret = RegisterRelationChecker(nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SetCommonSocketOpt001
 * @tc.desc: call SetCommonSocketOpt function with with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetCommonSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = SetCommonSocketOpt(socket, level, optType, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SetCommonSocketOpt(socket, level, optType, optValue, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    socket = INVALID_VALUE;
    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    optType = OPT_TYPE_NEED_ACK;
    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    socket = 1;
    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetCommonSocketOpt001
 * @tc.desc: call GetCommonSocketOpt function with with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, GetCommonSocketOpt001, TestSize.Level1)
{
    int32_t socket = 1;
    OptLevel level = OPT_LEVEL_KERNEL;
    OptType optType = OPT_TYPE_FIRST_PACKAGE;
    int32_t optValueSize = DATA_LENS;
    void *optValue = &optValueSize;
    int32_t ret = GetCommonSocketOpt(socket, level, optType, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetCommonSocketOpt(socket, level, optType, nullptr, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    optType = OPT_TYPE_SUPPORT_ACK;
    ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    socket = INVALID_VALUE;
    ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    optType = OPT_TYPE_MAX_IDLE_TIMEOUT;
    ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    socket = 1;
    ret = GetCommonSocketOpt(socket, level, optType, optValue, &optValueSize);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: BindAsync001
 * @tc.desc: call BindAsync function with with valid parameter.
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

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
    };
    int32_t ret = BindAsync(socket, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: EvaluateQos001
 * @tc.desc: call EvaluateQos function with with valid parameter.
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

    ret = EvaluateQos(nullptr, dataType, nullptr, qosCount);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetMtuSize001
 * @tc.desc: call GetMtuSize function with with valid parameter.
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

/**
 * @tc.name: PrivilegeShutdown001
 * @tc.desc: call PrivilegeShutdown function with with valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, PrivilegeShutdown001, TestSize.Level1)
{
    uint64_t tokenId = 0;
    int32_t pid = 0;

    int32_t ret = PrivilegeShutdown(tokenId, pid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PrivilegeShutdown(tokenId, pid, const_cast<char *>(g_networkId.c_str()));
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/**
 * @tc.name: SetAccessInfo001
 * @tc.desc: call SetAccessInfo function with with valid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSocketServiceTest, SetAccessInfo001, TestSize.Level1)
{
    int32_t socket = 1;
    SocketAccessInfo accessInfo = {
        .userId = 1,
        .accountId = (char *)"accountId",
    };

    int32_t ret = SetAccessInfo(socket, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}
} // namespace OHOS