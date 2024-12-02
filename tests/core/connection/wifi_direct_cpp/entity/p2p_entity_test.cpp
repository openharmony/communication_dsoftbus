/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "softbus_error_code.h"
#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "entity/p2p_connect_state.h"
#include "entity/p2p_entity.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS::SoftBus {

class P2pEntityTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiDirectInterfaceMock mock;
        EXPECT_CALL(mock, GetP2pEnableStatus).WillOnce(Return(WIFI_SUCCESS));
        P2pEntity::Init();
    }
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: CreateGroupTest001
* @tc.desc: check create group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, CreateGroupTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupSuccessAction);
        P2pCreateGroupParam param{5180, true};
        P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    }

    {
        EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupFailureAction);
        P2pCreateGroupParam param{5180, true};
        P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);
    }
    sleep(1);
    {
        EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupTimeOutAction);
        P2pCreateGroupParam param{5180, true};
        P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_CREATE_GROUP_TIMEOUT);
    }
}

/*
* @tc.name: CreateGroupTest002
* @tc.desc: check create group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, CreateGroupTest002, TestSize.Level1)
{
    sleep(2);
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo groupInfoOut;
    groupInfoOut.frequency = 5180;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect).WillRepeatedly(Return());
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    P2pCreateGroupParam param{5180, true};
    P2pOperationResult result = P2pEntity::GetInstance().CreateGroup(param);
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
* @tc.name: CreateGroupTest003
* @tc.desc: check create group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, CreateGroupTest003, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info. SetReuseCount(1); // 1 Indicates the number of reference counting .
        return SOFTBUS_OK;
    });
    std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> destroyGroupParam;
    int32_t result = P2pCreateGroupState::Instance()->RemoveLink(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
    auto operation = std::make_shared<P2pOperationWrapper<P2pConnectParam>>(param, P2pOperationType::CONNECT);
    result = P2pCreateGroupState::Instance()->Connect(operation);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    result = P2pCreateGroupState::Instance()->DestroyGroup(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);
}

/*
* @tc.name: ConnectTest001
* @tc.desc: check connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, ConnectTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectSuccessAction);
        P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
        P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    }

    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectSuccessAction);
        EXPECT_CALL(mock, GetInterfaceIpString).WillRepeatedly(Return(SOFTBUS_CONN_OPEN_SOCKET_FAILED));
        P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, true};
        P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    }

    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectSuccessAction);
        EXPECT_CALL(mock, GetInterfaceIpString).WillRepeatedly(Return(SOFTBUS_OK));
        P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, true};
        P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    }

    {
        EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectFailureAction);
        P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
        P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);
    }
    sleep(1);
    {
        EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectTimeOutAction);
        P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
        P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_CONNECT_GROUP_TIMEOUT);
    }
}

/*
* @tc.name: ConnectTest002
* @tc.desc: check connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, ConnectTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
    P2pOperationResult result = P2pEntity::GetInstance().Connect(param);
    EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}


/*
* @tc.name: ConnectTest003
* @tc.desc: check connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, ConnectTest003, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info. SetReuseCount(1); // 1 Indicates the number of reference counting .
        return SOFTBUS_OK;
    });
    std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> destroyGroupParam;
    int32_t result = P2pConnectState::Instance()->RemoveLink(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    result = P2pConnectState::Instance()->DestroyGroup(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);
}

/*
* @tc.name: DestroyGroupTest001
* @tc.desc: check destroy group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, DestroyGroupTest001, TestSize.Level1)
{
    sleep(1);
    WifiDirectInterfaceMock mock;
    {
        EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(ERROR_WIFI_UNKNOWN));
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GO);
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, RemoveGroup).WillOnce(WifiDirectInterfaceMock::DestroyGroupSuccessAction);
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);
    }
    sleep(1);
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GO);
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, RemoveGroup).WillOnce(WifiDirectInterfaceMock::DestroyGroupFailureAction);
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_SHORT_RANGE_CALLBACK_DESTROY_FAILED);
    }
    sleep(1);
    {
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GC);
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, Hid2dRemoveGcGroup).WillOnce(WifiDirectInterfaceMock::DestroyGroupTimeOutAction);
        P2pDestroyGroupParam param{IF_NAME_P2P};
        P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_DESTROY_GROUP_TIMEOUT);
    }
}

/*
* @tc.name: DestroyGroupTest002
* @tc.desc: check destroy group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, DestroyGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    {
        sleep(1);
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GO);
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, RemoveGroup).WillOnce(Return(ERROR_WIFI_UNKNOWN));
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
        EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    }

    {
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GC);
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, Hid2dRemoveGcGroup).WillOnce(Return(ERROR_WIFI_UNKNOWN));
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().DestroyGroup(param);
        EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    }
}

/*
* @tc.name: DestroyGroupTest003
* @tc.desc: check destroy group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, DestroyGroupTest003, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info. SetReuseCount(1); // 1 Indicates the number of reference counting .
        return SOFTBUS_OK;
    });
    std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> destroyGroupParam;
    int32_t result = P2pDestroyGroupState::Instance()->RemoveLink(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
    auto operation = std::make_shared<P2pOperationWrapper<P2pConnectParam>>(param, P2pOperationType::CONNECT);
    result = P2pDestroyGroupState::Instance()->Connect(operation);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    result = P2pDestroyGroupState::Instance()->DestroyGroup(destroyGroupParam);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);

    P2pCreateGroupParam createGroupParam{5180, true};
    auto createGroupOp =
        std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(createGroupParam, P2pOperationType::CREATE_GROUP);
    result = P2pDestroyGroupState::Instance()->CreateGroup(createGroupOp);
    EXPECT_EQ(result, SOFTBUS_CONN_NOT_SUPPORT_FAILED);
}

/*
* @tc.name: ReuseLinkTest001
* @tc.desc: check reuse link
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, ReuseLinkTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(WIFI_SUCCESS));
    auto ret = P2pEntity::GetInstance().ReuseLink();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    ret = P2pEntity::GetInstance().ReuseLink();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
* @tc.name: DisconnectTest001
* @tc.desc: check disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, DisconnectTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    {
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info. SetReuseCount(2); // 2 Indicates the number of reference counting .
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(WIFI_SUCCESS)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().Disconnect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_OK);

        result = P2pEntity::GetInstance().Disconnect(param);
        EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    }

    {
        InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info. SetReuseCount(1); // 1 Indicates the number of reference counting .
            return SOFTBUS_OK;
        });
        EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(ERROR_WIFI_UNKNOWN))
            .WillOnce(WifiDirectInterfaceMock::DestroyGroupFailureAction);
        P2pDestroyGroupParam param;
        P2pOperationResult result = P2pEntity::GetInstance().Disconnect(param);
        EXPECT_EQ(result.errorCode_, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));

        result = P2pEntity::GetInstance().Disconnect(param);
        EXPECT_EQ(result.errorCode_, SOFTBUS_CONN_P2P_SHORT_RANGE_CALLBACK_DESTROY_FAILED);
    }
}

/*
* @tc.name: NotifyNewClientJoining001
* @tc.desc: notify new client joining
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, NotifyNewClientJoining001, TestSize.Level1)
{
    std::string remoteMac = "11:22:33:44:55:66";
    std::string invaildMac = "11:22:33:44:55:dd";
    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    size_t count =P2pEntity::GetInstance().GetJoiningClientCount();
    EXPECT_EQ(count, 1);
    sleep(11);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, "0123456789ABCDEF", [](InnerLink &link) {
        link.SetRemoteBaseMac("11:22:33:44:55:66");
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    P2pEntity::GetInstance().CancelNewClientJoining(remoteMac);
    P2pEntity::GetInstance().CancelNewClientJoining(invaildMac);

    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    P2pEntity::GetInstance().RemoveNewClientJoining(remoteMac);
    P2pEntity::GetInstance().RemoveNewClientJoining(invaildMac);

    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    P2pEntity::GetInstance().ClearJoiningClient();
    P2pEntity::GetInstance().ClearJoiningClient();
    count =P2pEntity::GetInstance().GetJoiningClientCount();
    EXPECT_EQ(count, 0);
}

/*
* @tc.name: PushOperation001
* @tc.desc: push operation
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, PushOperation001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, AuthStopListeningForWifiDirect).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    P2pDestroyGroupParam param1;
    auto destroyGroupOp =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param1, P2pOperationType::DESTROY_GROUP);
    InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::GC);
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, Hid2dRemoveGcGroup).WillOnce(WifiDirectInterfaceMock::DestroyGroupFailureAction);
    P2pEntity::GetInstance().PushOperation(destroyGroupOp);
    P2pEntity::GetInstance().ExecuteNextOperation();
    int32_t ret = destroyGroupOp->promise_.get_future().get().errorCode_;
    EXPECT_EQ(ret, SOFTBUS_CONN_P2P_SHORT_RANGE_CALLBACK_DESTROY_FAILED);


    P2pCreateGroupParam param2;
    auto createGroupOp =
        std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(param2, P2pOperationType::CREATE_GROUP);
    P2pEntity::GetInstance().PushOperation(createGroupOp);
    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(WifiDirectInterfaceMock::CreateGroupFailureAction);
    P2pEntity::GetInstance().ExecuteNextOperation();
    ret = createGroupOp->promise_.get_future().get().errorCode_;
    EXPECT_EQ(ret, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);

    P2pConnectParam param3{"123\n01:02:03:04:05:06\n555\n16\n1", false, false};
    auto connectOp =
        std::make_shared<P2pOperationWrapper<P2pConnectParam>>(param3, P2pOperationType::CONNECT);
    P2pEntity::GetInstance().PushOperation(connectOp);
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(WifiDirectInterfaceMock::ConnectFailureAction);
    P2pEntity::GetInstance().ExecuteNextOperation();
    ret = connectOp->promise_.get_future().get().errorCode_;
    EXPECT_EQ(ret, SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION);
}

/*
* @tc.name: HasPendingOperation001
* @tc.desc: HasPendingOperation
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pEntityTest, HasPendingOperation001, TestSize.Level1)
{
    P2pDestroyGroupParam param1;
    auto operation =
        std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param1, P2pOperationType::DESTROY_GROUP);
    P2pEntity::GetInstance().PushOperation(operation);

    bool ret = P2pEntity::GetInstance().HasPendingOperation();
    EXPECT_EQ(ret, true);

    P2pEntity::GetInstance().ClearPendingOperation();
    ret = P2pEntity::GetInstance().HasPendingOperation();
    EXPECT_EQ(ret, false);
}
}