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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_mintp_socket.c"

using namespace testing::ext;

namespace OHOS {
class SoftBusMintpSocketTest : public testing::Test {
public:
    SoftBusMintpSocketTest() { }
    ~SoftBusMintpSocketTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftBusMintpSocketTest::SetUpTestCase(void) { }

void SoftBusMintpSocketTest::TearDownTestCase(void) { }

/*
 * @tc.name: SetMintpSocketTest001
 * @tc.desc: test setsockopt function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, SetMintpSocketTest001, TestSize.Level1)
{
    int32_t ret = SetMintpSocketMsgSize(-1);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetMintpSocketTos(-1, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetMintpSocketTransType(-1, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetMintpSocketKeepAlive(-1, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetMintpSocketKeepAlive(-1, 1000);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetMintpSocketTimeSync(-1, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    MintpTimeSync timeSync;
    ret = SetMintpSocketTimeSync(-1, &timeSync);
    EXPECT_NE(ret, SOFTBUS_OK);
    SetMintpOption(-1, 0);
    SetMintpOption(-1, 1);
}

/*
 * @tc.name:BindMintpTest002
 * @tc.desc: test BindMintp function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, BindMintpTest002, TestSize.Level1)
{
    int32_t ret = BindMintp(SOFTBUS_AF_INET, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
    ret = BindMintp(SOFTBUS_AF_INET6, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
    const char *localIp = "127.30.1.1";
    ret = BindMintp(SOFTBUS_AF_INET, 0, localIp);
    EXPECT_NE(ret, SOFTBUS_SOCKET_ADDR_ERR);
    const char *localIp6 = "12:34:56:78:90:ab";
    ret = BindMintp(SOFTBUS_AF_INET6, 0, localIp6);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name:OpenMintpServerSocketTest003
 * @tc.desc: test OpenMintpServerSocket function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, OpenMintpServerSocketTest003, TestSize.Level1)
{
    int32_t ret = OpenMintpServerSocket(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LocalListenerInfo option;
    option.type = CONNECT_TCP;
    ret = OpenMintpServerSocket(&option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    option.type = CONNECT_HML;
    option.socketOption.port = -1;
    ret = OpenMintpServerSocket(&option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    option.socketOption.port = 0;
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "127.30.1.1");
    ret = OpenMintpServerSocket(&option);
}

/*
 * @tc.name:MintpSocketConnectTest004
 * @tc.desc: test MintpSocketConnect function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, MintpSocketConnectTest004, TestSize.Level1)
{
    ConnectOption option;
    option.type = CONNECT_HML;
    option.socketOption.port = 1;
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "127.30.1.1");
    int32_t ret = MintpSocketConnect(0, SOFTBUS_AF_INET, &option);
    EXPECT_NE(ret, SOFTBUS_ADAPTER_OK);
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "12:34:56:78:90:ab");
    ret = MintpSocketConnect(0, SOFTBUS_PF_INET6, &option);
    EXPECT_NE(ret, SOFTBUS_ADAPTER_OK);
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "\0");
    ret = MintpSocketConnect(0, SOFTBUS_AF_INET, &option);
    EXPECT_NE(ret, SOFTBUS_ADAPTER_OK);
    ret = MintpSocketConnect(0, SOFTBUS_PF_INET6, &option);
    EXPECT_NE(ret, SOFTBUS_ADAPTER_OK);
}

/*
 * @tc.name: OpenMintpClientSocketTest005
 * @tc.desc: test OpenMintpClientSocket function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, OpenMintpClientSocketTest005, TestSize.Level1)
{
    int32_t ret = OpenMintpClientSocket(nullptr, nullptr, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnectOption option;
    ret = OpenMintpClientSocket(&option, nullptr, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    option.type = CONNECT_TCP;
    const char *myIp = "127.29.1.1";
    ret = OpenMintpClientSocket(&option, myIp, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    option.type = CONNECT_HML;
    option.socketOption.port = -1;
    ret = OpenMintpClientSocket(&option, myIp, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    option.socketOption.port = 1;
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "\0");
    ret = OpenMintpClientSocket(&option, myIp, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)strcpy_s(option.socketOption.addr, IP_LEN, "127.29.1.2");
    ret = OpenMintpClientSocket(&option, myIp, false);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenMintpClientSocket(&option, myIp, true);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetMintpSockPortTest006
 * @tc.desc: test GetMintpSockPort function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, GetMintpSockPortTest006, TestSize.Level1)
{
    int32_t ret = GetMintpSockPort(-1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: AcceptDettpClientTest007
 * @tc.desc: test AcceptDettpClient function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, AcceptDettpClientTest007, TestSize.Level1)
{
    int32_t ret = AcceptDettpClient(-1, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnectOption clientAddr;
    ret = AcceptDettpClient(-1, &clientAddr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t cfd = -1;
    ret = AcceptDettpClient(-1, &clientAddr, &cfd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: AcceptClientWithProtocolTest008
 * @tc.desc: test AcceptClientWithProtocol function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, AcceptMintpClientTest008, TestSize.Level1)
{
    int32_t ret = AcceptMintpClient(-1, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnectOption clientAddr;
    ret = AcceptMintpClient(-1, &clientAddr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t cfd = -1;
    ret = AcceptMintpClient(-1, &clientAddr, &cfd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: AcceptDettpClientTest009
 * @tc.desc: test AcceptDettpClient function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, AcceptDettpClientTest009, TestSize.Level1)
{
    ConnectOption clientAddr;
    int32_t cfd = -1;
    int32_t ret = AcceptClientWithProtocol(-1, nullptr, nullptr, LNN_PROTOCOL_DETTP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptClientWithProtocol(-1, &clientAddr, nullptr, LNN_PROTOCOL_DETTP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptClientWithProtocol(-1, &clientAddr, &cfd, LNN_PROTOCOL_DETTP);
    EXPECT_NE(ret, SOFTBUS_OK);
    
    ret = AcceptClientWithProtocol(-1, nullptr, nullptr, LNN_PROTOCOL_MINTP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptClientWithProtocol(-1, &clientAddr, nullptr, LNN_PROTOCOL_MINTP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptClientWithProtocol(-1, &clientAddr, &cfd, LNN_PROTOCOL_MINTP);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: GetDetTpProtocolTest010
 * @tc.desc: test GetDetTpProtocol function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, GetDetTpProtocolTest010, TestSize.Level1)
{
    const SocketInterface *interface = GetDetTpProtocol();
    EXPECT_NE(interface, nullptr);
}

/**
 * @tc.name: GetMintpProtocolTest011
 * @tc.desc: test GetMintpProtocol function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMintpSocketTest, GetMintpProtocolTest011, TestSize.Level1)
{
    const SocketInterface *interface = GetMinTpProtocol();
    EXPECT_NE(interface, nullptr);
}
} // namespace OHOS
