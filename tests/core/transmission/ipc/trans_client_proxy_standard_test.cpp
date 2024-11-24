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

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "trans_client_proxy_standard.h"

using namespace std;
using namespace testing::ext;

#define TEST_TMP_DATE 1
#define TEST_ERRTMP_DATE (-1)

namespace OHOS {
class TransClientProxyStandardTest : public testing::Test {
public:
    TransClientProxyStandardTest() {}
    ~TransClientProxyStandardTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void TransClientProxyStandardTest::SetUpTestCase(void) {}
void TransClientProxyStandardTest::TearDownTestCase(void) {}

/**
 * @tc.name: InformPermissionChangeTest001
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest001, TestSize.Level0)
{
    #define TEST_INVALID 0
    int32_t ret;

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t tmp = TEST_INVALID;

    void *addr = nullptr;
    uint32_t addrTypeLen = TEST_INVALID;
    void *metaInfo = nullptr;
    uint32_t infoLen = TEST_INVALID;
    const char *networkId = nullptr;
    ret = clientProxy->OnJoinLNNResult(addr, addrTypeLen, networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnJoinMetaNodeResult(addr, addrTypeLen, metaInfo, infoLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnLeaveLNNResult(networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnLeaveMetaNodeResult(networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    bool isOnline = false;
    ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, addr, addrTypeLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnNodeBasicInfoChanged("test", addr, addrTypeLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnTimeSyncResult(addr, addrTypeLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    clientProxy->OnPublishLNNResult(tmp, tmp);

    clientProxy->OnRefreshLNNResult(tmp, tmp);

    clientProxy->OnRefreshDeviceFound(addr, addrTypeLen);
}

/**
 * @tc.name: InformPermissionChangeTest002
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest002, TestSize.Level0)
{
    int32_t ret;
    const char *pkgName = "dms";
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    ret = clientProxy->OnChannelLinkDown(nullptr, TEST_TMP_DATE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = clientProxy->OnClientPermissonChange(nullptr, TEST_TMP_DATE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = clientProxy->OnClientPermissonChange(pkgName, TEST_ERRTMP_DATE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS