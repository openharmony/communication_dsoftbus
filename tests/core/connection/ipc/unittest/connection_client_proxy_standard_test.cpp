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

#include "general_connection_client_proxy_standard.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

using namespace std;
using namespace testing::ext;

#define TEST_TMP_DATE 1
#define TEST_ERRTMP_DATE (-1)

namespace OHOS {
class ConnectionClientProxyStandardTest : public testing::Test {
public:
    ConnectionClientProxyStandardTest() {}
    ~ConnectionClientProxyStandardTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ConnectionClientProxyStandardTest::SetUpTestCase(void) {}
void ConnectionClientProxyStandardTest::TearDownTestCase(void) {}

/*
 * @tc.name: ConnectionClientProxyStandardTest001
 * @tc.desc: trans client proxy standard test, use the normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionClientProxyStandardTest, ConnectionClientProxyStandardTest001, TestSize.Level0)
{
    int32_t ret;
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<ConnectionClientProxy> clientProxy = new (std::nothrow) ConnectionClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    ret = clientProxy->OnConnectionStateChange(0, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnAcceptConnect("test", 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnDataReceived(0, reinterpret_cast<const uint8_t *>("test"), strlen("test"));
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS