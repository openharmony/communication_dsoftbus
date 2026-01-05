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

#include <functional>
#include <gtest/gtest.h>
#include <string>

#include "data/interface_manager.h"
#include "p2p_adapter_mock.h"
#include "p2p_entity_mock.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "wifi_direct_p2p_adapter.h"

using namespace testing::ext;
using testing::_;
using ::testing::Return;

namespace OHOS::SoftBus {
class WifiDirectP2pAdapterTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

static void NotifyP2pStateChange(int32_t retCode)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "p2p go is removed, ret=%{public}d", retCode);
    (void)retCode;
}

/*
 * @tc.name: ConnCreateGoOwnerTest001
 * @tc.desc: test create go success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest001 in");
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [](InterfaceInfo &interface) {
            interface.SetIsEnable(true);
            return SOFTBUS_OK;
        });
    
    P2pAdapterMock adapterMock;
    P2pEntityMock entityMock;
    EXPECT_CALL(adapterMock, GetRecommendChannel).WillOnce(Return(36));
    EXPECT_CALL(adapterMock, GetCoexConflictCode).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(adapterMock, GetGroupConfig(_)).WillOnce([this](std::string &groupConfigString) {
        groupConfigString = "test\nFF:FF:FF:FF:FF:FF\ntest\n5180";
        return SOFTBUS_OK;
    });
    EXPECT_CALL(adapterMock, GetIpAddress).WillOnce(Return(SOFTBUS_OK));
    P2pOperationResult createResult{};
    createResult.errorCode_ = SOFTBUS_OK;
    EXPECT_CALL(entityMock, CreateGroup).WillOnce(Return(createResult));

    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    P2pOperationResult destroyResult{};
    destroyResult.errorCode_ = SOFTBUS_OK;
    EXPECT_CALL(entityMock, Disconnect).WillOnce(Return(destroyResult));
    WifiDirectP2pAdapter::GetInstance()->ConnDestroyGoOwner("");
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest001 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest002
 * @tc.desc: test create go fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest002 in");
    P2pAdapterMock adapterMock;
    P2pEntityMock entityMock;
    EXPECT_CALL(adapterMock, GetRecommendChannel).WillOnce(Return(36));
    EXPECT_CALL(adapterMock, GetCoexConflictCode).WillOnce(Return(SOFTBUS_OK));
    P2pOperationResult createResult{};
    createResult.errorCode_ = SOFTBUS_CONN_CREATE_GROUP_FAILED;
    EXPECT_CALL(entityMock, CreateGroup).WillOnce(Return(createResult));

    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_CREATE_GROUP_FAILED);
}

/*
 * @tc.name: ConnCreateGoOwnerTest003
 * @tc.desc: test create go 3vap conflict fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest003 in");
    P2pAdapterMock adapterMock;
    EXPECT_CALL(adapterMock, GetRecommendChannel).WillOnce(Return(36));
    EXPECT_CALL(adapterMock, GetCoexConflictCode).WillOnce(Return(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT));

    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT);
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest003 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest004
 * @tc.desc: test reuse go success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest004 in");
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [](InterfaceInfo &interface) {
            interface.SetIsCreateGo(true);
            interface.SetRole(LinkInfo::LinkMode::GO);
            return SOFTBUS_OK;
        });

    P2pAdapterMock adapterMock;
    P2pEntityMock entityMock;
    EXPECT_CALL(adapterMock, GetGroupConfig(_)).WillOnce([this](std::string &groupConfigString) {
        groupConfigString = "test\nFF:FF:FF:FF:FF:FF\ntest\n5180";
        return SOFTBUS_OK;
    });
    EXPECT_CALL(adapterMock, GetIpAddress).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(entityMock, ReuseLink).WillOnce(Return(SOFTBUS_OK));
    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_OK);
    P2pOperationResult destroyResult{};
    destroyResult.errorCode_ = SOFTBUS_OK;
    EXPECT_CALL(entityMock, Disconnect).WillOnce(Return(destroyResult));
    WifiDirectP2pAdapter::GetInstance()->ConnDestroyGoOwner("");
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest004 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest005
 * @tc.desc: test reuse go fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest005 in");
    P2pEntityMock entityMock;
    EXPECT_CALL(entityMock, ReuseLink).WillOnce(Return(SOFTBUS_CONN_CREATE_GROUP_FAILED));
    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_CREATE_GROUP_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest005 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest006
 * @tc.desc: test reuse other go fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest006 in");
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [](InterfaceInfo &interface) {
            interface.SetIsCreateGo(false);
            return SOFTBUS_OK;
        });
    
    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_GO_IS_NOT_CREATED_SOFTBUS);
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest006 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest007
 * @tc.desc: test create go fail when p2p role is gc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest007 in");
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [](InterfaceInfo &interface) {
            interface.SetRole(LinkInfo::LinkMode::GC);
            return SOFTBUS_OK;
        });
    
    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_P2P_ROLE_IS_GC);
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest007 out");
}

/*
 * @tc.name: ConnCreateGoOwnerTest008
 * @tc.desc: test create go fail when role is error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectP2pAdapterTest, ConnCreateGoOwnerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest008 in");
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [](InterfaceInfo &interface) {
            interface.SetRole(LinkInfo::LinkMode::STA);
            return SOFTBUS_OK;
        });
    
    const struct GroupOwnerConfig config{};
    struct GroupOwnerResult result{};
    auto ret = WifiDirectP2pAdapter::GetInstance()->ConnCreateGoOwner("", &config, &result, NotifyP2pStateChange);
    EXPECT_EQ(ret, SOFTBUS_CONN_P2P_ROLE_INVALID);
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnCreateGoOwnerTest008 out");
}
} // namespace OHOS::SoftBus
