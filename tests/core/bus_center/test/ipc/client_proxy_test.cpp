/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bus_center_client_proxy.h"
#include "bus_center_client_proxy_standard.h"
#include "if_system_ability_manager.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

#define TEST_NETWORK_ID    "6542316a57d"
#define TEST_ADDR          "1111222233334444"
#define TEST_ADDR_TYPE_LEN 17
#define TEST_RET_CODE      0
#define TEST_TYPE          1
constexpr char TEST_PKGNAME[] = "testname";
constexpr uint32_t DEVICELEN = 5;
constexpr int32_t REFRESHID = 7;
constexpr int32_t REASON = 8;
constexpr int32_t PUBLISHID = 8;
class ClientProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientProxyTest::SetUpTestCase() { }

void ClientProxyTest::TearDownTestCase() { }

void ClientProxyTest::SetUp() { }

void ClientProxyTest::TearDown() { }

/*
 * @tc.name: OnJoinLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnJoinLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnJoinLNNResult(nullptr, TEST_ADDR_TYPE_LEN, TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = clientProxy->OnJoinLNNResult(addrInput, TEST_ADDR_TYPE_LEN, nullptr, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = clientProxy->OnJoinLNNResult(addrInput, TEST_ADDR_TYPE_LEN, TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnLeaveLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnLeaveLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnLeaveLNNResult(nullptr, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnLeaveLNNResult(TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeOnlineStateChanged
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeOnlineStateChangedTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    bool isOnline = false;
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, nullptr, TEST_ADDR_TYPE_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, addrInput, TEST_ADDR_TYPE_LEN);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeBasicInfoChanged
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeBasicInfoChangedTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeBasicInfoChanged("test", nullptr, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeBasicInfoChanged("test", addrInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnTimeSyncResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnTimeSyncResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnTimeSyncResult(nullptr, TEST_ADDR_TYPE_LEN, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnTimeSyncResult(addrInput, TEST_ADDR_TYPE_LEN, TEST_RET_CODE);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnPublishLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnPublishLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    clientProxy->OnPublishLNNResult(TEST_RET_CODE, TEST_RET_CODE);

    int32_t ret = ClientOnRefreshLNNResult(TEST_PKGNAME, 0, PUBLISHID, REASON);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnRefreshLNNResult
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshLNNResult_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    clientProxy->OnRefreshLNNResult(TEST_RET_CODE, TEST_RET_CODE);

    int32_t ret = ClientOnRefreshLNNResult(TEST_PKGNAME, 0, REFRESHID, REASON);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnRefreshDeviceFound
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshDeviceFound_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    clientProxy->OnRefreshDeviceFound(addrInput, TEST_ADDR_TYPE_LEN);

    const void *device = "1234";
    uint32_t deviceLen = DEVICELEN;
    int32_t ret = ClientOnRefreshDeviceFound(TEST_PKGNAME, 0, device, deviceLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS