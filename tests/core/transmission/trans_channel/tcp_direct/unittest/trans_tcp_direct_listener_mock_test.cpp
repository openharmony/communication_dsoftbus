
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

#include "trans_tcp_direct_listener.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_error_code.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "trans_tcp_direct_listener.c"
#include "trans_tcp_direct_listener_test_mock.h"
#include "trans_tcp_direct_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransTcpDirectListenerMockTest : public testing::Test {
public:
    TransTcpDirectListenerMockTest()
    {}
    ~TransTcpDirectListenerMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectListenerMockTest::SetUpTestCase(void)
{}

void TransTcpDirectListenerMockTest::TearDownTestCase(void)
{}


/**
 * @tc.name: SwitchAuthLinkTypeToFlagTypeTest001
 * @tc.desc: SwitchAuthLinkTypeToFlagType test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerMockTest, SwitchAuthLinkTypeToFlagTypeTest001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_SLE;
    uint32_t ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_SLE, ret);

    type = AUTH_LINK_TYPE_SESSION_KEY;
    ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_SESSION_KEY, ret);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest001
 * @tc.desc: GetCipherFlagByAuthId test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerMockTest, GetCipherFlagByAuthIdTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = GetCipherFlagByAuthId(authHandle, nullptr, nullptr, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint32_t flag;
    bool isAuthServer;
    AuthConnInfo info;
    info.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    NiceMock<TransTcpDirectListenerInterfaceMock> tcpDirectListenerMock;

    EXPECT_CALL(tcpDirectListenerMock, AuthGetServerSide).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(tcpDirectListenerMock, AuthGetConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(info), Return(SOFTBUS_OK)));
    ret = GetCipherFlagByAuthId(authHandle, &flag, &isAuthServer, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransPostBytesTest001
 * @tc.desc: TransPostBytes test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerMockTest, TransPostBytesTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusMalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    NiceMock<TransTcpDirectListenerInterfaceMock> tcpDirectListenerMock;

    EXPECT_CALL(tcpDirectListenerMock, PackRequest).WillOnce(Return(nullptr));
    int32_t ret = TransPostBytes(conn, true, 0);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_REQUEST_FAILED, ret);
    if (conn != nullptr) {
        SoftBusFree(conn);
    }
}

/**
 * @tc.name: TransPostBytesTest002
 * @tc.desc: TransPostBytes test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerMockTest, TransPostBytesTest002, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusMalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    conn->isMeta = true;
    NiceMock<TransTcpDirectListenerInterfaceMock> tcpDirectListenerMock;
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    char *data = cJSON_PrintUnformatted(json);
    ASSERT_TRUE(data != nullptr);
    cJSON_Delete(json);

    EXPECT_CALL(tcpDirectListenerMock, PackRequest).WillRepeatedly(Return(data));
    EXPECT_CALL(tcpDirectListenerMock, TransTdcPostBytes).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransPostBytes(conn, true, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (conn != nullptr) {
        SoftBusFree(conn);
    }
}

/**
 * @tc.name: TransGetRouteTypeByModuleTest001
 * @tc.desc: TransGetRouteTypeByModule test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerMockTest, TransGetRouteTypeByModuleTest001, TestSize.Level1)
{
    int32_t ret = TransGetRouteTypeByModule(DIRECT_CHANNEL_SERVER_USB);
    EXPECT_EQ(WIFI_USB, ret);
}
} // OHOS

