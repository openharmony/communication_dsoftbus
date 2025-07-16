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

#include "softbus_error_code.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "softbus_htp_socket_mock.h"
#include "softbus_htp_socket.c"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class SoftbusHtpSocketMockTest : public testing::Test {
public:
    SoftbusHtpSocketMockTest() { }
    ~SoftbusHtpSocketMockTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftbusHtpSocketMockTest::SetUpTestCase(void) { }

void SoftbusHtpSocketMockTest::TearDownTestCase(void) { }

/**
 * @tc.name: SoftbusHtpSocketMockTest001
 * @tc.desc: test AcceptHtpClient function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusHtpSocketMockTest, SoftbusHtpSocketMockTest001, TestSize.Level1)
{
    int32_t fd = 1;
    int32_t cfd = 1;
    ConnectOption *clientAddr = static_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    EXPECT_TRUE(clientAddr != nullptr);

    NiceMock<SoftbusHtpSocketMock> softbusHtpSocketMock;
    EXPECT_CALL(softbusHtpSocketMock, SoftBusSocketAccept).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = AcceptHtpClient(fd, clientAddr, &cfd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(clientAddr);
}

/**
 * @tc.name: SoftbusHtpSocketMockTest001
 * @tc.desc: test AcceptHtpClient function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusHtpSocketMockTest, SoftbusHtpSocketMockTest002, TestSize.Level1)
{
    int32_t fd = 1;

    NiceMock<SoftbusHtpSocketMock> softbusHtpSocketMock;
    EXPECT_CALL(softbusHtpSocketMock, SoftBusSocketGetLocalName).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = GetHtpSockPort(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}
