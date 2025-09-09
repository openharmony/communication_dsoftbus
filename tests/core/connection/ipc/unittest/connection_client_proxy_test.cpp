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

#include "general_connection_client_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "softbus_client_info_manager.h"
#include "softbus_error_code.h"
#include "softbus_server_death_recipient.h"

#define TEST_PID 2
const char *g_pkgName = "dms";

using namespace testing::ext;
namespace OHOS {
namespace {
class ConnectionClientProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConnectionClientProxyTest::SetUpTestCase() { }

void ConnectionClientProxyTest::TearDownTestCase() { }

void ConnectionClientProxyTest::SetUp() { }

void ConnectionClientProxyTest::TearDown() { }

/*
 * @tc.name: ConnectionClientProxyTest001
 * @tc.desc: test clientProxy is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionClientProxyTest, ConnectionClientProxyTest001, TestSize.Level0)
{
    int32_t ret = ClientIpcOnConnectionStateChange(nullptr, 0, 0, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnConnectionStateChange("test", 0, 0, 0, 0);
    EXPECT_EQ(SOFTBUS_IPC_ERR, ret);

    ret = ClientIpcOnAcceptConnect(nullptr, 0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnAcceptConnect("test", 0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnAcceptConnect("test", 0, "test", 0);
    EXPECT_EQ(SOFTBUS_IPC_ERR, ret);

    ret = ClientIpcOnDataReceived(nullptr, 0, 0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnDataReceived("test", 0, 0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnDataReceived("test", 0, 0, reinterpret_cast<const uint8_t *>("test"), strlen("test"));
    EXPECT_EQ(SOFTBUS_IPC_ERR, ret);
}

/*
 * @tc.name: ConnectionClientProxyTest002
 * @tc.desc: test clientProxy is not null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionClientProxyTest, ConnectionClientProxyTest002, TestSize.Level0)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    int32_t ret =
        SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientIpcOnConnectionStateChange("test", 0, 0, 0, 0);
    EXPECT_NE(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);

    ret = ClientIpcOnAcceptConnect("test", 0, "test", 0);
    EXPECT_NE(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);

    ret = ClientIpcOnDataReceived("test", 0, 0, reinterpret_cast<const uint8_t *>("test"), strlen("test"));
    EXPECT_NE(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);
}
}
}