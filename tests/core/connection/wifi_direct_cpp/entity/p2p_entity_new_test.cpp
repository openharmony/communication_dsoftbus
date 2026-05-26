/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <securec.h>
#include <thread>

#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "dfx/p2p_entity_snapshot.h"
#include "entity/p2p_available_state.h"
#include "entity/p2p_entity.h"
#include "softbus_error_code.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace OHOS::SoftBus {

static constexpr int P2P_WAIT_CLIENT_JOIN_MS = 100;
static constexpr int P2P_ASYNC_WAIT_MS = 1000;
static constexpr int P2P_TEST_FREQUENCY = 5180;
static constexpr char P2P_TEST_MAC[] = "AA:BB:CC:DD:EE:FF";
static constexpr char P2P_TEST_MAC_2[] = "11:22:33:44:55:66";
static constexpr char P2P_TEST_DEVICE_ID[] = "TEST123456789ABC";
static constexpr char P2P_TEST_CONN_INFO[] = "test\nAA:BB:CC:DD:EE:FF\n555\n16\n1";

class P2pEntityNewTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiDirectInterfaceMock mock;
        EXPECT_CALL(mock, GetP2pEnableStatus).WillRepeatedly(Return(WIFI_SUCCESS));
        P2pEntity::Init();
    }

    static void TearDownTestCase()
    {
        // No-op: cleanup handled by individual test TearDown
    }

    void SetUp() override
    {
        LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
        P2pEntity::GetInstance().ClearJoiningClient();
        P2pEntity::GetInstance().ClearPendingOperation();
    }

    void TearDown() override
    {
        P2pEntity::GetInstance().ClearJoiningClient();
        P2pEntity::GetInstance().ClearPendingOperation();
        LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    }

    void SetupInterfaceForTesting()
    {
        InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetBaseMac(P2P_TEST_MAC);
            info.SetIsEnable(true);
            info.SetReuseCount(1);
            return SOFTBUS_OK;
        });
    }

    void CreateTestLink(const std::string &deviceId, const std::string &mac, InnerLink::LinkState state)
    {
        LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P, deviceId, [&mac, state](InnerLink &link) {
            link.SetRemoteBaseMac(mac);
            link.SetState(state);
        });
    }
};

/*
 * @tc.name: GetInstanceTest001
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, GetInstanceTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------GetInstanceTest001 in---------");
    P2pEntity &instance1 = P2pEntity::GetInstance();
    P2pEntity &instance2 = P2pEntity::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------GetInstanceTest001 out---------");
}

/*
 * @tc.name: InitTest001
 * @tc.desc: Test Init can be called multiple times safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, InitTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------InitTest001 in---------");
    P2pEntity::Init();
    P2pEntity::Init();
    P2pEntity &instance = P2pEntity::GetInstance();
    EXPECT_NE(&instance, nullptr);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------InitTest001 out---------");
}

/*
 * @tc.name: DisconnectLinkTest001
 * @tc.desc: Test DisconnectLink when GetGroupInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectLinkTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest001 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    EXPECT_NO_FATAL_FAILURE(P2pEntity::GetInstance().DisconnectLink(P2P_TEST_MAC));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest001 out---------");
}

/*
 * @tc.name: DisconnectLinkTest002
 * @tc.desc: Test DisconnectLink when GO with multiple clients (should not remove group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectLinkTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest002 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->clientDevicesSize = 2;
        auto ret = memcpy_s(groupInfo->clientDevices[0].devAddr, MAC_LEN, P2P_TEST_MAC, strlen(P2P_TEST_MAC));
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        ret = memcpy_s(groupInfo->clientDevices[1].devAddr, MAC_LEN, P2P_TEST_MAC_2, strlen(P2P_TEST_MAC_2));
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, RemoveGroup()).Times(0);

    EXPECT_NO_FATAL_FAILURE(P2pEntity::GetInstance().DisconnectLink(P2P_TEST_MAC));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest002 out---------");
}

/*
 * @tc.name: DisconnectLinkTest003
 * @tc.desc: Test DisconnectLink when GO with single matching client (should remove group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectLinkTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest003 in---------");
    SetupInterfaceForTesting();
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->clientDevicesSize = 1;
        auto ret = memcpy_s(groupInfo->clientDevices[0].devAddr, MAC_LEN, P2P_TEST_MAC, strlen(P2P_TEST_MAC));
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);

    EXPECT_NO_FATAL_FAILURE(P2pEntity::GetInstance().DisconnectLink(P2P_TEST_MAC));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest003 out---------");
}

/*
 * @tc.name: DisconnectLinkTest004
 * @tc.desc: Test DisconnectLink when GO with empty client list (should remove group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectLinkTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest004 in---------");
    SetupInterfaceForTesting();
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);

    EXPECT_NO_FATAL_FAILURE(P2pEntity::GetInstance().DisconnectLink(P2P_TEST_MAC));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest004 out---------");
}

/*
 * @tc.name: DisconnectLinkTest005
 * @tc.desc: Test DisconnectLink when not GO (should remove group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectLinkTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest005 in---------");
    SetupInterfaceForTesting();
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GC);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 0;
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dRemoveGcGroup(_)).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);

    EXPECT_NO_FATAL_FAILURE(P2pEntity::GetInstance().DisconnectLink(P2P_TEST_MAC));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectLinkTest005 out---------");
}

/*
 * @tc.name: CreateGroupTest001
 * @tc.desc: Test CreateGroup success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CreateGroupTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest001 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupSuccessAction);

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);

    // Clean up: destroy group after successful creation
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);
    P2pDestroyGroupParam destroyParam { IF_NAME_P2P };
    P2pEntity::GetInstance().DestroyGroup(destroyParam);
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest001 out---------");
}

/*
 * @tc.name: CreateGroupTest002
 * @tc.desc: Test CreateGroup failure scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CreateGroupTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest002 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupFailureAction);

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);

    // Clean up: remove link after failure
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest002 out---------");
}

/*
 * @tc.name: CreateGroupTest003
 * @tc.desc: Test CreateGroup timeout scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CreateGroupTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest003 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupTimeOutAction);

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_CREATE_GROUP_TIMEOUT);

    // Clean up: remove link after timeout
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest003 out---------");
}

/*
 * @tc.name: CreateGroupTest004
 * @tc.desc: Test CreateGroup with immediate error from Hid2dCreateGroup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CreateGroupTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest004 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CreateGroupTest004 out---------");
}

/*
 * @tc.name: ConnectTest001
 * @tc.desc: Test Connect success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ConnectTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest001 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectSuccessAction);

    P2pConnectParam param { P2P_TEST_CONN_INFO, false, false };
    P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);

    // Clean up: remove link after successful connection
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest001 out---------");
}

/*
 * @tc.name: ConnectTest002
 * @tc.desc: Test Connect failure scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ConnectTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest002 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectFailureAction);

    P2pConnectParam param { P2P_TEST_CONN_INFO, false, false };
    P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);

    // Clean up: remove link after failure
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest002 out---------");
}

/*
 * @tc.name: ConnectTest003
 * @tc.desc: Test Connect timeout scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ConnectTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest003 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectTimeOutAction);

    P2pConnectParam param { P2P_TEST_CONN_INFO, false, false };
    P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_CONNECT_GROUP_TIMEOUT);

    // Clean up: remove link after timeout
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest003 out---------");
}

/*
 * @tc.name: ConnectTest004
 * @tc.desc: Test Connect with immediate error from Hid2dConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ConnectTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest004 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    P2pConnectParam param { P2P_TEST_CONN_INFO, false, false };
    P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ConnectTest004 out---------");
}

/*
 * @tc.name: ReuseLinkTest001
 * @tc.desc: Test ReuseLink success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ReuseLinkTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ReuseLinkTest001 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSetGroupType(_)).WillOnce(Return(WIFI_SUCCESS));
    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(WIFI_SUCCESS));

    int32_t ret = P2pEntity::GetInstance().ReuseLink();
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ReuseLinkTest001 out---------");
}

/*
 * @tc.name: ReuseLinkTest002
 * @tc.desc: Test ReuseLink failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ReuseLinkTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ReuseLinkTest002 in---------");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSetGroupType(_)).WillOnce(Return(WIFI_SUCCESS));
    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    int32_t ret = P2pEntity::GetInstance().ReuseLink();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ReuseLinkTest002 out---------");
}

/*
 * @tc.name: NotifyNewClientJoiningTest001
 * @tc.desc: Test NotifyNewClientJoining with valid MAC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, NotifyNewClientJoiningTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest001 in---------");
    std::string mac = P2P_TEST_MAC;
    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    size_t count = P2pEntity::GetInstance().GetJoiningClientCount();
    EXPECT_EQ(count, 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest001 out---------");
}

/*
 * @tc.name: NotifyNewClientJoiningTest002
 * @tc.desc: Test NotifyNewClientJoining with empty MAC (should be ignored)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, NotifyNewClientJoiningTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest002 in---------");
    std::string emptyMac = "";
    P2pEntity::GetInstance().NotifyNewClientJoining(emptyMac, P2P_WAIT_CLIENT_JOIN_MS);
    size_t count = P2pEntity::GetInstance().GetJoiningClientCount();
    EXPECT_EQ(count, 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest002 out---------");
}

/*
 * @tc.name: NotifyNewClientJoiningTest003
 * @tc.desc: Test NotifyNewClientJoining with multiple clients
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, NotifyNewClientJoiningTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest003 in---------");
    std::string mac1 = P2P_TEST_MAC;
    std::string mac2 = P2P_TEST_MAC_2;

    P2pEntity::GetInstance().NotifyNewClientJoining(mac1, P2P_WAIT_CLIENT_JOIN_MS);
    P2pEntity::GetInstance().NotifyNewClientJoining(mac2, P2P_WAIT_CLIENT_JOIN_MS);
    size_t count = P2pEntity::GetInstance().GetJoiningClientCount();
    EXPECT_EQ(count, 2);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------NotifyNewClientJoiningTest003 out---------");
}

/*
 * @tc.name: CancelNewClientJoiningTest001
 * @tc.desc: Test CancelNewClientJoining with existing MAC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CancelNewClientJoiningTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest001 in---------");
    std::string mac = P2P_TEST_MAC;
    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().CancelNewClientJoining(mac);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest001 out---------");
}

/*
 * @tc.name: CancelNewClientJoiningTest002
 * @tc.desc: Test CancelNewClientJoining with non-existing MAC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CancelNewClientJoiningTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest002 in---------");
    std::string mac1 = P2P_TEST_MAC;
    std::string mac2 = P2P_TEST_MAC_2;

    P2pEntity::GetInstance().NotifyNewClientJoining(mac1, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().CancelNewClientJoining(mac2);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest002 out---------");
}

/*
 * @tc.name: CancelNewClientJoiningTest003
 * @tc.desc: Test CancelNewClientJoining with empty MAC (should be ignored)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, CancelNewClientJoiningTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest003 in---------");
    std::string mac = P2P_TEST_MAC;
    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().CancelNewClientJoining("");
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------CancelNewClientJoiningTest003 out---------");
}

/*
 * @tc.name: RemoveNewClientJoiningTest001
 * @tc.desc: Test RemoveNewClientJoining with existing MAC and link
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, RemoveNewClientJoiningTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest001 in---------");
    std::string mac = P2P_TEST_MAC;
    CreateTestLink(P2P_TEST_DEVICE_ID, mac, InnerLink::LinkState::CONNECTED);

    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().RemoveNewClientJoining(mac);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest001 out---------");
}

/*
 * @tc.name: RemoveNewClientJoiningTest002
 * @tc.desc: Test RemoveNewClientJoining with non-existing MAC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, RemoveNewClientJoiningTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest002 in---------");
    std::string mac1 = P2P_TEST_MAC;
    std::string mac2 = P2P_TEST_MAC_2;

    P2pEntity::GetInstance().NotifyNewClientJoining(mac1, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().RemoveNewClientJoining(mac2);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest002 out---------");
}

/*
 * @tc.name: RemoveNewClientJoiningTest003
 * @tc.desc: Test RemoveNewClientJoining with empty MAC (should be ignored)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, RemoveNewClientJoiningTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest003 in---------");
    std::string mac = P2P_TEST_MAC;
    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().RemoveNewClientJoining("");
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------RemoveNewClientJoiningTest003 out---------");
}

/*
 * @tc.name: ClearJoiningClientTest001
 * @tc.desc: Test ClearJoiningClient with multiple clients
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ClearJoiningClientTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearJoiningClientTest001 in---------");
    std::string mac1 = P2P_TEST_MAC;
    std::string mac2 = P2P_TEST_MAC_2;

    P2pEntity::GetInstance().NotifyNewClientJoining(mac1, P2P_WAIT_CLIENT_JOIN_MS);
    P2pEntity::GetInstance().NotifyNewClientJoining(mac2, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 2);

    P2pEntity::GetInstance().ClearJoiningClient();
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearJoiningClientTest001 out---------");
}

/*
 * @tc.name: ClearJoiningClientTest002
 * @tc.desc: Test ClearJoiningClient when already empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ClearJoiningClientTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearJoiningClientTest002 in---------");
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    P2pEntity::GetInstance().ClearJoiningClient();
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearJoiningClientTest002 out---------");
}

/*
 * @tc.name: GetJoiningClientCountTest001
 * @tc.desc: Test GetJoiningClientCount returns correct count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, GetJoiningClientCountTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------GetJoiningClientCountTest001 in---------");
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);

    std::string mac = P2P_TEST_MAC;
    P2pEntity::GetInstance().NotifyNewClientJoining(mac, P2P_WAIT_CLIENT_JOIN_MS);
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 1);

    P2pEntity::GetInstance().ClearJoiningClient();
    EXPECT_EQ(P2pEntity::GetInstance().GetJoiningClientCount(), 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------GetJoiningClientCountTest001 out---------");
}

/*
 * @tc.name: DisconnectTest001
 * @tc.desc: Test Disconnect with reuseCount > 1 (share link remove group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest001 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetReuseCount(2);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(WIFI_SUCCESS));

    P2pDestroyGroupParam param;
    P2pOperationResult result = P2pEntity::GetInstance().Disconnect(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest001 out---------");
}

/*
 * @tc.name: DisconnectTest002
 * @tc.desc: Test Disconnect with reuseCount = 1 (normal destroy group)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest002 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    // GetCurrentGroup returns failure (group already removed) when callback is triggered
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(ERROR_WIFI_UNKNOWN));
    // Hid2dSharedlinkDecrease triggers DestroyGroupSuccessAction to complete the operation
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Invoke([]() {
        return WifiDirectInterfaceMock::DestroyGroupSuccessAction();
    }));

    P2pDestroyGroupParam param;
    P2pOperationResult result = P2pEntity::GetInstance().Disconnect(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest002 out---------");
}

/*
 * @tc.name: DisconnectTest003
 * @tc.desc: Test Disconnect with reuseCount > 1 and share link remove group failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DisconnectTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest003 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetReuseCount(2);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    P2pDestroyGroupParam param;
    P2pOperationResult result = P2pEntity::GetInstance().Disconnect(param);
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DisconnectTest003 out---------");
}

/*
 * @tc.name: DestroyGroupTest001
 * @tc.desc: Test DestroyGroup success as GO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DestroyGroupTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest001 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    // GetCurrentGroup returns failure when callback is triggered (group removed)
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(ERROR_WIFI_UNKNOWN));
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);

    P2pDestroyGroupParam param;
    P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest001 out---------");
}

/*
 * @tc.name: DestroyGroupTest002
 * @tc.desc: Test DestroyGroup failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DestroyGroupTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest002 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupFailureAction);

    P2pDestroyGroupParam param;
    P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_SHORT_RANGE_CALLBACK_DESTROY_FAILED);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest002 out---------");
}

/*
 * @tc.name: DestroyGroupTest003
 * @tc.desc: Test DestroyGroup timeout as GC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DestroyGroupTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest003 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GC);
        return SOFTBUS_OK;
    });

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dRemoveGcGroup(_)).WillOnce(WifiDirectInterfaceMock::DestroyGroupTimeOutAction);

    P2pDestroyGroupParam param { IF_NAME_P2P };
    P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
    EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_DESTROY_GROUP_TIMEOUT);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DestroyGroupTest003 out---------");
}

/*
 * @tc.name: PushOperationTest001
 * @tc.desc: Test PushOperation adds to pending queue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, PushOperationTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------PushOperationTest001 in---------");
    P2pDestroyGroupParam param;
    auto operation =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param, P2pOperationType::DESTROY_GROUP);

    P2pEntity::GetInstance().PushOperation(operation);
    EXPECT_TRUE(P2pEntity::GetInstance().HasPendingOperation());
    CONN_LOGI(CONN_WIFI_DIRECT, "---------PushOperationTest001 out---------");
}

/*
 * @tc.name: ExecuteNextOperationTest001
 * @tc.desc: Test ExecuteNextOperation with CREATE_GROUP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ExecuteNextOperationTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest001 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    auto operation = std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(param, P2pOperationType::CREATE_GROUP);

    P2pEntity::GetInstance().PushOperation(operation);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupSuccessAction);

    P2pEntity::GetInstance().ExecuteNextOperation();
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));

    auto future = operation->promise_.get_future();
    P2pOperationResult result = future.get();
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest001 out---------");
}

/*
 * @tc.name: ExecuteNextOperationTest002
 * @tc.desc: Test ExecuteNextOperation with CONNECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ExecuteNextOperationTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest002 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    P2pConnectParam param { P2P_TEST_CONN_INFO, false, false };
    auto operation = std::make_shared<P2pOperationWrapper<P2pConnectParam>>(param, P2pOperationType::CONNECT);

    P2pEntity::GetInstance().PushOperation(operation);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectSuccessAction);

    P2pEntity::GetInstance().ExecuteNextOperation();
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));

    auto future = operation->promise_.get_future();
    P2pOperationResult result = future.get();
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest002 out---------");
}

/*
 * @tc.name: ExecuteNextOperationTest003
 * @tc.desc: Test ExecuteNextOperation with DESTROY_GROUP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ExecuteNextOperationTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest003 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTED);

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });

    P2pDestroyGroupParam param;
    auto operation =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param, P2pOperationType::DESTROY_GROUP);

    P2pEntity::GetInstance().PushOperation(operation);

    WifiDirectInterfaceMock mock;
    // GetCurrentGroup returns failure when callback is triggered (group removed)
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(ERROR_WIFI_UNKNOWN));
    EXPECT_CALL(mock, RemoveGroup()).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);

    P2pEntity::GetInstance().ExecuteNextOperation();
    std::this_thread::sleep_for(std::chrono::milliseconds(P2P_ASYNC_WAIT_MS));

    auto future = operation->promise_.get_future();
    P2pOperationResult result = future.get();
    EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest003 out---------");
}

/*
 * @tc.name: ExecuteNextOperationTest004
 * @tc.desc: Test ExecuteNextOperation with empty queue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ExecuteNextOperationTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest004 in---------");
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());
    P2pEntity::GetInstance().ExecuteNextOperation();
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest004 out---------");
}

/*
 * @tc.name: ExecuteNextOperationTest005
 * @tc.desc: Test ExecuteNextOperation with operation failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ExecuteNextOperationTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest005 in---------");
    SetupInterfaceForTesting();
    CreateTestLink(P2P_TEST_DEVICE_ID, P2P_TEST_MAC, InnerLink::LinkState::CONNECTING);

    P2pCreateGroupParam param { P2P_TEST_FREQUENCY, true };
    auto operation = std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(param, P2pOperationType::CREATE_GROUP);

    P2pEntity::GetInstance().PushOperation(operation);

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Invoke([](WifiP2pGroupInfo *groupInfo) {
        groupInfo->isP2pGroupOwner = 1;
        groupInfo->frequency = P2P_TEST_FREQUENCY;
        auto ret = strcpy_s(groupInfo->interface, sizeof(groupInfo->interface), IF_NAME_P2P);
        if (ret != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        groupInfo->clientDevicesSize = 0;
        return WIFI_SUCCESS;
    }));
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));

    P2pEntity::GetInstance().ExecuteNextOperation();

    auto future = operation->promise_.get_future();
    P2pOperationResult result = future.get();
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ExecuteNextOperationTest005 out---------");
}

/*
 * @tc.name: HasPendingOperationTest001
 * @tc.desc: Test HasPendingOperation returns true when queue has operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, HasPendingOperationTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------HasPendingOperationTest001 in---------");
    P2pDestroyGroupParam param;
    auto operation =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param, P2pOperationType::DESTROY_GROUP);

    P2pEntity::GetInstance().PushOperation(operation);
    EXPECT_TRUE(P2pEntity::GetInstance().HasPendingOperation());
    CONN_LOGI(CONN_WIFI_DIRECT, "---------HasPendingOperationTest001 out---------");
}

/*
 * @tc.name: HasPendingOperationTest002
 * @tc.desc: Test HasPendingOperation returns false when queue is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, HasPendingOperationTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------HasPendingOperationTest002 in---------");
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());
    CONN_LOGI(CONN_WIFI_DIRECT, "---------HasPendingOperationTest002 out---------");
}

/*
 * @tc.name: ClearPendingOperationTest001
 * @tc.desc: Test ClearPendingOperation clears all operations with error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ClearPendingOperationTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearPendingOperationTest001 in---------");
    P2pDestroyGroupParam param1;
    auto operation1 =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param1, P2pOperationType::DESTROY_GROUP);
    P2pEntity::GetInstance().PushOperation(operation1);

    P2pCreateGroupParam param2 { P2P_TEST_FREQUENCY, true };
    auto operation2 =
        std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(param2, P2pOperationType::CREATE_GROUP);
    P2pEntity::GetInstance().PushOperation(operation2);

    EXPECT_TRUE(P2pEntity::GetInstance().HasPendingOperation());

    P2pEntity::GetInstance().ClearPendingOperation();
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());

    auto future1 = operation1->promise_.get_future();
    P2pOperationResult result1 = future1.get();
    EXPECT_EQ(result1.errorCode_, SOFTBUS_CONN_ENTITY_UNAVAILABLE);

    auto future2 = operation2->promise_.get_future();
    P2pOperationResult result2 = future2.get();
    EXPECT_EQ(result2.errorCode_, SOFTBUS_CONN_ENTITY_UNAVAILABLE);
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearPendingOperationTest001 out---------");
}

/*
 * @tc.name: ClearPendingOperationTest002
 * @tc.desc: Test ClearPendingOperation when queue is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, ClearPendingOperationTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearPendingOperationTest002 in---------");
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());
    P2pEntity::GetInstance().ClearPendingOperation();
    EXPECT_FALSE(P2pEntity::GetInstance().HasPendingOperation());
    CONN_LOGI(CONN_WIFI_DIRECT, "---------ClearPendingOperationTest002 out---------");
}

/*
 * @tc.name: DumpTest001
 * @tc.desc: Test Dump method without crashing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DumpTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DumpTest001 in---------");
    P2pEntitySnapshot snapshot;
    nlohmann::json output;

    P2pEntity::GetInstance().Dump(snapshot);
    snapshot.Marshalling(output);

    EXPECT_TRUE(output.is_array());
    EXPECT_FALSE(output.empty());
    EXPECT_EQ(output[0]["dumpType"], "p2pEntity");
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DumpTest001 out---------");
}

/*
 * @tc.name: DumpTest002
 * @tc.desc: Test Dump with joining clients
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pEntityNewTest, DumpTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DumpTest002 in---------");
    P2pEntity::GetInstance().NotifyNewClientJoining(P2P_TEST_MAC, P2P_WAIT_CLIENT_JOIN_MS);

    P2pEntitySnapshot snapshot;
    nlohmann::json output;

    P2pEntity::GetInstance().Dump(snapshot);
    snapshot.Marshalling(output);

    EXPECT_TRUE(output.is_array());
    EXPECT_FALSE(output.empty());
    EXPECT_FALSE(output[0]["joiningClientMacList"].empty());

    P2pEntity::GetInstance().ClearJoiningClient();
    CONN_LOGI(CONN_WIFI_DIRECT, "---------DumpTest002 out---------");
}

} // namespace OHOS::SoftBus
