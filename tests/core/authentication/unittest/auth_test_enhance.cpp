/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <sys/time.h>
#include <cinttypes>

#include "auth_common.h"
#include "auth_connection_mock.h"
#include "auth_hichain.h"
#include "auth_hichain_mock.h"
#include "auth_interface.h"
#include "auth_net_ledger_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_access_token_test.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
class AuthTestEnhance : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTestEnhance::SetUpTestCase()
{
    SetAceessTokenPermission("AuthTestEnhance");
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void AuthTestEnhance::TearDownTestCase()
{
    LooperDeinit();
}

void AuthTestEnhance::SetUp()
{
    LOG_INFO("AuthTest start.");
}

void AuthTestEnhance::TearDown()
{
}

/*
* @tc.name: AUTH_START_LISTENING_Test_001
* @tc.desc: auth common test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTestEnhance, AUTH_START_LISTENING_Test_001, TestSize.Level0)
{
    AuthConnectInterfaceMock connMock;
    {
        EXPECT_CALL(connMock, ConnStartLocalListening(_)).WillRepeatedly(Return(SOFTBUS_OK));
        int32_t port = 5566;
        int32_t ret = AuthStartListening(AUTH_LINK_TYPE_P2P, "192.168.78.1", port);
        printf("ret %d\n", ret);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    {
        EXPECT_CALL(connMock, ConnStartLocalListening(_)).WillRepeatedly(Return(SOFTBUS_ERR));
        int32_t port = 5566;
        int32_t ret = AuthStartListening(AUTH_LINK_TYPE_P2P, "192.168.78.1", port);
        printf("ret %d\n", ret);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
    }
}

/*
* @tc.name: AUTH_HICHAIN_START_AUTH_Test_001
* @tc.desc: auth common test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTestEnhance, AUTH_HICHAIN_START_AUTH_Test_001, TestSize.Level0)
{
    const char *udid = "1111222233334444";
    const char *uid = "8888";
    int64_t authSeq = 5678;
    AuthHichainInterfaceMock hichainMock;
    GroupAuthManager authManager;
    authManager.authDevice = AuthHichainInterfaceMock::InvokeAuthDevice;
    EXPECT_CALL(hichainMock, InitDeviceAuthService()).WillRepeatedly(Return(0));
    EXPECT_CALL(hichainMock, GetGaInstance()).WillRepeatedly(Return(&authManager));
    int32_t ret = HichainStartAuth(authSeq, udid, uid);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_INIT_Test_001
* @tc.desc: auth common test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTestEnhance, AUTH_INIT_Test_001, TestSize.Level0)
{
    AuthConnectInterfaceMock connMock;
    AuthHichainInterfaceMock hichainMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    groupManager.regDataChangeListener = AuthHichainInterfaceMock::InvokeDataChangeListener;
    EXPECT_CALL(connMock, ConnSetConnectCallback(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, InitDeviceAuthService()).WillRepeatedly(Return(0));
    EXPECT_CALL(hichainMock, GetGaInstance()).WillRepeatedly(Return(&authManager));
    EXPECT_CALL(hichainMock, GetGmInstance()).WillRepeatedly(Return(&groupManager));
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
