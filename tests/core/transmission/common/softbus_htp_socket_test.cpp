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

#include "softbus_adapter_mem.h"
#include "softbus_htp_socket.c"
#include "softbus_htp_socket.h"

using namespace testing::ext;

namespace OHOS {
class SoftBusHtpSocketTest : public testing::Test {
public:
    SoftBusHtpSocketTest() { }
    ~SoftBusHtpSocketTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftBusHtpSocketTest::SetUpTestCase(void) { }

void SoftBusHtpSocketTest::TearDownTestCase(void) { }

/*
 * @tc.name: SoftBusHtpSocketTest001
 * @tc.desc: test GetHtpProtocol function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest001, TestSize.Level1)
{
    const SocketInterface *interface = GetHtpProtocol();
    EXPECT_NE(interface, nullptr);
}

/*
 * @tc.name: SoftBusHtpSocketTest002
 * @tc.desc: test GetHtpSockPort function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest002, TestSize.Level1)
{
    int32_t fd = 1;

    int32_t ret = GetHtpSockPort(fd);
    EXPECT_EQ(ret, SOFTBUS_ADAPTER_ERR);
}

/*
 * @tc.name: SoftBusHtpSocketTest003
 * @tc.desc: test OpenHtpServerSocket function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest003, TestSize.Level1)
{
    LocalListenerInfo *option =
        static_cast<LocalListenerInfo *>(SoftBusCalloc(sizeof(LocalListenerInfo)));
    EXPECT_TRUE(option != nullptr);

    int32_t ret = OpenHtpServerSocket(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_P2P;
    ret = OpenHtpServerSocket(option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_HML;
    option->socketOption.port = SOFTBUS_ADAPTER_ERR;
    ret = OpenHtpServerSocket(option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_HML;
    option->socketOption.port = 0;
    ret = OpenHtpServerSocket(option);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(option);
}

/*
 * @tc.name: SoftBusHtpSocketTest004
 * @tc.desc: test OpenHtpClientSocket function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest004, TestSize.Level1)
{
    ConnectOption *option =
        static_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    EXPECT_TRUE(option != nullptr);
    const char *myIp = "1111"; // test value
    bool isNonBlock = true;

    int32_t ret = OpenHtpClientSocket(nullptr, myIp, isNonBlock);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_P2P;
    ret = OpenHtpClientSocket(option, myIp, isNonBlock);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_HML;
    option->socketOption.port = 0;
    ret = OpenHtpClientSocket(option, myIp, isNonBlock);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_HML;
    option->socketOption.port = 1;
    option->socketOption.addr[0] = '\0';
    ret = OpenHtpClientSocket(option, myIp, isNonBlock);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    option->type = CONNECT_HML;
    option->socketOption.port = 1;
    option->socketOption.addr[0] = '1';
    ret = OpenHtpClientSocket(option, myIp, isNonBlock);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(option);
}

/*
 * @tc.name: SoftBusHtpSocketTest005
 * @tc.desc: test AcceptHtpClient function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest005, TestSize.Level1)
{
    int32_t fd = 1;
    int32_t cfd = 1;
    ConnectOption *clientAddr = static_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    EXPECT_TRUE(clientAddr != nullptr);

    int32_t ret = AcceptHtpClient(fd, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptHtpClient(fd, clientAddr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AcceptHtpClient(fd, clientAddr, &cfd);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(clientAddr);
}

/*
 * @tc.name: SoftBusHtpSocketTest006
 * @tc.desc: test MacToHtpAddr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest006, TestSize.Level1)
{
    SoftBusSockAddrHtp *addr = static_cast<SoftBusSockAddrHtp *>(SoftBusCalloc(sizeof(SoftBusSockAddrHtp)));
    EXPECT_TRUE(addr != nullptr);
    const char *mac = "1111"; // test value
    uint16_t port = 1;

    int32_t ret = MacToHtpAddr(nullptr, nullptr, port);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = MacToHtpAddr(mac, nullptr, port);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = MacToHtpAddr(mac, addr, port);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(addr);
}

/*
 * @tc.name: SoftBusHtpSocketTest007
 * @tc.desc: test HtpConnect function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest007, TestSize.Level1)
{
    int32_t fd = 1;
    const char *mac = "1111"; // test value
    uint16_t port = 1;

    int32_t ret = HtpConnect(fd, mac, port);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusHtpSocketTest008
 * @tc.desc: test BindLocalMac function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest008, TestSize.Level1)
{
    int32_t fd = 1;
    const char *mac = "1111"; // test value
    uint16_t port = 1;

    int32_t ret = BindLocalMac(fd, mac, port);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusHtpSocketTest009
 * @tc.desc: test GetHtpSockPort function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusHtpSocketTest, SoftBusHtpSocketTest009, TestSize.Level1)
{
    int32_t fd = 1;

    int32_t ret = GetHtpSockPort(fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}
}
