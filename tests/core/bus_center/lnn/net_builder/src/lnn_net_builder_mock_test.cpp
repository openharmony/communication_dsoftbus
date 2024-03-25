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

#include "lnn_log.h"
#include "lnn_net_builder_deps_mock.h"
#include "lnn_net_builder.c"
#include "lnn_net_builder.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

int32_t LnnInitCipherKeyManager(void)
{
    LNN_LOGI(LNN_TEST, "init virtual lnn cipherkey manager");
    return SOFTBUS_OK;
}

namespace OHOS {
using namespace testing::ext;
constexpr int32_t LOCAL_WEIGHT = 10;
constexpr char NODE_UDID[] = "123456ABCDEF";
constexpr char NODE_NETWORK_ID[] = "235689BNHFCF";
constexpr char NODE1_NETWORK_ID[] = "345678BNHFCF";
constexpr int64_t AUTH_META_ID = 1;
constexpr char INVALID_UDID[] =
    "ASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJK\
    LPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJ\
    KLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLP";
constexpr int64_t AUTH_ID = 10;
constexpr int64_t AUTH_ID_ADD = 11;
constexpr char NODE1_BR_MAC[] = "12345TTU";
constexpr char NODE2_BR_MAC[] = "56789TTU";
constexpr uint32_t REQUEST_ID = 1;
constexpr uint32_t REQUEST_ID_ADD = 2;
constexpr uint16_t FSM_ID = 1;
constexpr uint16_t FSM_ID_ADD = 2;
constexpr char NODE1_IP[] = "10.146.181.134";
constexpr char NODE2_IP[] = "10.147.182.135";
constexpr int32_t CONN_COUNT = 10;
constexpr int32_t CURRENT_COUNT = 11;
constexpr uint32_t CONN_FLAG1 = 128;
constexpr uint32_t CONN_FLAG2 = 255;
constexpr uint32_t CONN_FLAG3 = 1;
constexpr uint32_t MSG_ERR_LEN0 = 0;
constexpr uint32_t MSG_ERR_LEN1 = 1;

using namespace testing;
class LNNNetBuilderMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetBuilderMockTest::SetUpTestCase() {}

void LNNNetBuilderMockTest::TearDownTestCase() {}

void LNNNetBuilderMockTest::SetUp() {}

void LNNNetBuilderMockTest::TearDown() {}

/*
* @tc.name: LNN_INIT_NET_BUILDER_TEST_001
* @tc.desc: lnn init netbuilder test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, LNN_INIT_NET_BUILDER_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnInitSyncInfoManager())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnInitTopoManager()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, RegAuthVerifyListener(_))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnRegSyncInfoHandler(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalNetworkId(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalUuid(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalIrk(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, SoftBusGetBtState()).WillRepeatedly(Return(BLE_ENABLE));
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_ERR);
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_ERR);
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_ERR);
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_ERR);
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_ERR);
}

/*
* @tc.name: CONFIG_LOCAL_LEDGER_TEST_001
* @tc.desc: config local ledger test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, CONFIG_LOCAL_LEDGER_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGenLocalNetworkId(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalUuid(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalIrk(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ConifgLocalLedger() != SOFTBUS_OK);
    EXPECT_TRUE(ConifgLocalLedger() != SOFTBUS_OK);
    EXPECT_TRUE(ConifgLocalLedger() == SOFTBUS_OK);
}

/*
* @tc.name: LNN_INIT_NET_BUILDER_DELAY_TEST_001
* @tc.desc: lnn init netbuilder delay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, LNN_INIT_NET_BUILDER_DELAY_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalWeight()).WillRepeatedly(Return(LOCAL_WEIGHT));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalNumInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnInitFastOffline())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitNetBuilderDelay() == SOFTBUS_ERR);
    EXPECT_TRUE(LnnInitNetBuilderDelay() == SOFTBUS_OK);
    EXPECT_TRUE(LnnInitNetBuilderDelay() == SOFTBUS_OK);
}

/*
* @tc.name: LNN_UPDATE_NODE_ADDR_TEST_001
* @tc.desc: lnn update node addr test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, LNN_UPDATE_NODE_ADDR_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetAllOnlineNodeInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnNotifyNodeAddressChanged(_, _, _)).WillRepeatedly(Return());
    EXPECT_TRUE(LnnUpdateNodeAddr(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnUpdateNodeAddr(NODE_NETWORK_ID) != SOFTBUS_OK);
    EXPECT_TRUE(LnnUpdateNodeAddr(NODE_NETWORK_ID) != SOFTBUS_OK);
    EXPECT_TRUE(LnnUpdateNodeAddr(NODE_NETWORK_ID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnUpdateNodeAddr(NODE_NETWORK_ID) == SOFTBUS_OK);
}

/*
* @tc.name: NODE_INFO_SYNC_TEST_001
* @tc.desc: node info sync test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, NODE_INFO_SYNC_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnInitP2p())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnInitNetworkInfo())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnInitDevicename())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnInitOffline())
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(InitNodeInfoSync() == SOFTBUS_ERR);
    EXPECT_TRUE(InitNodeInfoSync() == SOFTBUS_ERR);
    EXPECT_TRUE(InitNodeInfoSync() == SOFTBUS_ERR);
    EXPECT_TRUE(InitNodeInfoSync() == SOFTBUS_ERR);
    EXPECT_TRUE(InitNodeInfoSync() == SOFTBUS_OK);
}

/*
* @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_001
* @tc.desc: on device not trusted test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    SoftBusLooper loop;
    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, AuthGetLatestAuthSeqList(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSendNotTrustedInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, GetLooper(_)).WillRepeatedly(Return(&loop));
    EXPECT_CALL(NetBuilderMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    OnDeviceNotTrusted(nullptr);
    OnDeviceNotTrusted(INVALID_UDID);
    OnDeviceNotTrusted(NODE_UDID);
    OnDeviceNotTrusted(NODE_UDID);
    OnDeviceNotTrusted(NODE_UDID);
    OnDeviceNotTrusted(NODE_UDID);
    OnDeviceNotTrusted(NODE_UDID);
}

/*
* @tc.name: ON_DEVICE_VERIFY_PASS_TEST_001
* @tc.desc: on device verify pass test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_DEVICE_VERIFY_PASS_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, AuthGetConnInfo(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(NetBuilderMock, LnnConvertAuthConnInfoToAddr(_, _, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    AuthHandle authHandle = { .authId = AUTH_META_ID, .type = AUTH_LINK_TYPE_WIFI};
    OnDeviceVerifyPass(authHandle, &info);
    OnDeviceVerifyPass(authHandle, &info);
    OnDeviceVerifyPass(authHandle, nullptr);
}

/*
* @tc.name: GET_CURRENT_CONNECT_TYPE_TEST_001
* @tc.desc: get current connect type test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, GET_CURRENT_CONNECT_TYPE_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetAddrTypeByIfName(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(GetCurrentConnectType() == CONNECTION_ADDR_MAX);
    EXPECT_TRUE(GetCurrentConnectType() == CONNECTION_ADDR_MAX);
    EXPECT_TRUE(GetCurrentConnectType() == CONNECTION_ADDR_MAX);
}

/*
* @tc.name: PROCESS_LEAVE_SPECIFIC_TEST_001
* @tc.desc: process leave specific test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_SPECIFIC_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendLeaveRequestToConnFsm(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessLeaveSpecific(nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: PROCESS_LEAVE_BY_ADDR_TYPE_TEST_001
* @tc.desc: process leave by addr type test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_BY_ADDR_TYPE_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendLeaveRequestToConnFsm(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnNotifyAllTypeOffline(_)).WillRepeatedly(Return());
    EXPECT_TRUE(ProcessLeaveByAddrType(nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: PROCESS_ELETE_TEST_001
* @tc.desc: process elect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_ELETE_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ElectMsgPara)));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    SoftBusLooper loop;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, RegAuthVerifyListener(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnRegSyncInfoHandler(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalNetworkId(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalUuid(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGenLocalIrk(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnUnregSyncInfoHandler(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, GetLooper(_)).WillRepeatedly(Return(&loop));
    EXPECT_CALL(NetBuilderMock, SoftBusGetBtState()).WillRepeatedly(Return(BLE_ENABLE));
    EXPECT_TRUE(ProcessMasterElect(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnInitBusCenterEvent() == SOFTBUS_OK);
    EXPECT_TRUE(LnnInitNetBuilder() == SOFTBUS_OK);
    EXPECT_TRUE(ProcessMasterElect(para) == SOFTBUS_ERR);
    LnnDeinitNetBuilder();
    LnnDeinitBusCenterEvent();
}

/*
* @tc.name: PROCESS_NODE_STATE_CHANGED_TEST_001
* @tc.desc: process node state changed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_NODE_STATE_CHANGED_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessNodeStateChanged(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessNodeStateChanged(para) == SOFTBUS_ERR);
}

/*
* @tc.name: PROCESS_NODE_STATE_CHANGED_TEST_002
* @tc.desc: process node state changed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_NODE_STATE_CHANGED_TEST_002, TestSize.Level1)
{
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    EXPECT_TRUE(para != nullptr);
    void *para1 = nullptr;
    para1 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    EXPECT_TRUE(para1 != nullptr);
    void *para2 = nullptr;
    para2 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    EXPECT_TRUE(para2 != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById)
        .WillOnce(Return(true))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(ProcessNodeStateChanged(para) == SOFTBUS_OK);
    EXPECT_TRUE(ProcessNodeStateChanged(para1) != SOFTBUS_OK);
    EXPECT_TRUE(ProcessNodeStateChanged(para2) != SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_NODE_STATE_CHANGED_TEST_003
* @tc.desc: process node state changed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_NODE_STATE_CHANGED_TEST_003, TestSize.Level1)
{
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    EXPECT_TRUE(para != nullptr);
    void *para1 = nullptr;
    para1 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(ConnectionAddr)));
    EXPECT_TRUE(para1 != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_OLD_V2;
    connFsm->isDead = false;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnConvertDLidToUdid).WillOnce(Return(NODE_UDID));
    EXPECT_TRUE(ProcessNodeStateChanged(para) == SOFTBUS_OK);
    EXPECT_TRUE(ProcessNodeStateChanged(para1) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_ELECT_NODE_OFFLINE_TEST_001
* @tc.desc: try elect node offline test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_ELECT_NODE_OFFLINE_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm connFsm;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(TryElectMasterNodeOffline(&connFsm) != SOFTBUS_OK);
    EXPECT_TRUE(TryElectMasterNodeOffline(&connFsm) == SOFTBUS_OK);
}

/*
* @tc.name: TRY_ELECT_NODE_ONLINE_TEST_001
* @tc.desc: try elect node online test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_ELECT_NODE_ONLINE_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm connFsm;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalNumInfo(_, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetRemoteStrInfo(_, _, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnCompareNodeWeight(_, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_TRUE(TryElectMasterNodeOnline(&connFsm) != SOFTBUS_OK);
    EXPECT_TRUE(TryElectMasterNodeOnline(&connFsm) != SOFTBUS_OK);
    EXPECT_TRUE(TryElectMasterNodeOnline(&connFsm) != SOFTBUS_OK);
    EXPECT_TRUE(TryElectMasterNodeOnline(&connFsm) != SOFTBUS_OK);
    EXPECT_TRUE(TryElectMasterNodeOnline(&connFsm) == SOFTBUS_OK);
}

/*
* @tc.name: PROCESS_LEAVE_INVALID_CONN_TEST_001
* @tc.desc: process leave invalid conn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_INVALID_CONN_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LeaveInvalidConnMsgPara)));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessLeaveInvalidConn(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessLeaveInvalidConn(para) == SOFTBUS_OK);
}

/*
* @tc.name: IS_INVALID_CONNECTION_FSM_TEST_001
* @tc.desc: is invalid connection fsm test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, IS_INVALID_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm connFsm;
    (void)memset_s(&connFsm, sizeof(LnnConnectionFsm), 0, sizeof(LnnConnectionFsm));
    (void)strncpy_s(connFsm.connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    LeaveInvalidConnMsgPara msgPara;
    (void)memset_s(&msgPara, sizeof(LeaveInvalidConnMsgPara), 0, sizeof(LeaveInvalidConnMsgPara));
    (void)strncpy_s(msgPara.oldNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(IsInvalidConnectionFsm(&connFsm, &msgPara) == false);
    (void)memset_s(&msgPara, sizeof(LeaveInvalidConnMsgPara), 0, sizeof(LeaveInvalidConnMsgPara));
    (void)strncpy_s(msgPara.oldNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    connFsm.isDead = true;
    EXPECT_TRUE(IsInvalidConnectionFsm(&connFsm, &msgPara) == false);
    connFsm.isDead = false;
    msgPara.addrType = CONNECTION_ADDR_WLAN;
    connFsm.connInfo.addr.type = CONNECTION_ADDR_BR;
    EXPECT_TRUE(IsInvalidConnectionFsm(&connFsm, &msgPara) == false);
    msgPara.addrType = CONNECTION_ADDR_MAX;
    connFsm.connInfo.flag = 0;
    EXPECT_TRUE(IsInvalidConnectionFsm(&connFsm, &msgPara) == false);
    connFsm.connInfo.flag = 1;
    EXPECT_TRUE(IsInvalidConnectionFsm(&connFsm, &msgPara) == false);
}

/*
* @tc.name: PROCESS_SYNC_OFFLINE_FINISH_TEST_001
* @tc.desc: process sync offline finish test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_SYNC_OFFLINE_FINISH_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessSyncOfflineFinish(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessSyncOfflineFinish(para) == SOFTBUS_OK);
}

/*
* @tc.name: PROCESS_LEAVE_LNN_REQUEST_TEST_001
* @tc.desc: process leave lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_LNN_REQUEST_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendLeaveRequestToConnFsm(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(NetBuilderMock, LnnNotifyLeaveResult(_, _)).WillRepeatedly(Return());
    EXPECT_TRUE(ProcessLeaveLNNRequest(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessLeaveLNNRequest(para) == SOFTBUS_ERR);
}

/*
* @tc.name: PROCESS_DEVICE_NOT_TRUSTED_TEST_001
* @tc.desc: process device not trusted test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetNetworkIdByUdid(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessDeviceNotTrusted(nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: PROCESS_DEVICE_DISCONNECT_TEST_001
* @tc.desc: process device disconnect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_DISCONNECT_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(int64_t)));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessDeviceDisconnect(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessDeviceDisconnect(para) != SOFTBUS_OK);
}

/*
* @tc.name: PROCESS_DEVICE_VERIFY_PASS_TEST_001
* @tc.desc: process device verify pass test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_VERIFY_PASS_TEST_001, TestSize.Level1)
{
    DeviceVerifyPassMsgPara *msgPara =
        reinterpret_cast<DeviceVerifyPassMsgPara *>(SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara)));
    msgPara->nodeInfo = NULL;
    void *para = reinterpret_cast<void *>(msgPara);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessDeviceVerifyPass(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessDeviceVerifyPass(para) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: PROCESS_VERIFY_RESULT_TEST_001
* @tc.desc: process verify result test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_VERIFY_RESULT_TEST_001, TestSize.Level1)
{
    VerifyResultMsgPara *msgPara1 = reinterpret_cast<VerifyResultMsgPara *>(SoftBusMalloc(sizeof(VerifyResultMsgPara)));
    msgPara1->nodeInfo = NULL;
    void *para1 = reinterpret_cast<void *>(msgPara1);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessVerifyResult(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessVerifyResult(para1) != SOFTBUS_OK);
    VerifyResultMsgPara *msgPara2 = reinterpret_cast<VerifyResultMsgPara *>(SoftBusMalloc(sizeof(VerifyResultMsgPara)));
    msgPara2->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    void *para2 = reinterpret_cast<void *>(msgPara2);
    EXPECT_TRUE(ProcessVerifyResult(para2) != SOFTBUS_OK);
}

/*
* @tc.name: PROCESS_CLEAN_CONNECTION_FSM_TEST_001
* @tc.desc: process clean connection fsm test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_CLEAN_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    void *para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(uint16_t)));
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessCleanConnectionFsm(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(ProcessCleanConnectionFsm(para) == SOFTBUS_ERR);
}

/*
* @tc.name: IS_NODE_ONLINE_TEST_001
* @tc.desc: is node online test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, IS_NODE_ONLINE_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById(_, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    bool ret = IsNodeOnline(NODE_NETWORK_ID);
    EXPECT_TRUE(ret == false);
    ret = IsNodeOnline(NODE_NETWORK_ID);
    EXPECT_TRUE(ret == true);
    ret = IsNodeOnline(NODE_NETWORK_ID);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: UPDATE_LOCAL_NODE_TEST_001
* @tc.desc: update local node test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, UPDATE_LOCAL_NODE_TEST_001, TestSize.Level1)
{
    bool isCurrentNode = false;

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillOnce(Return(SOFTBUS_ERR));
    UpdateLocalMasterNode(isCurrentNode, NODE_UDID, LOCAL_WEIGHT);

    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalNumInfo(_, _)).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(NetBuilderMock, LnnNotifyMasterNodeChanged(_, _, _)).WillOnce(Return());
    UpdateLocalMasterNode(isCurrentNode, NODE_UDID, LOCAL_WEIGHT);

    EXPECT_CALL(NetBuilderMock, LnnSetLocalStrInfo(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnSetLocalNumInfo(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnNotifyMasterNodeChanged(_, _, _)).WillOnce(Return());
    UpdateLocalMasterNode(isCurrentNode, NODE_UDID, LOCAL_WEIGHT);
}

/*
* @tc.name: DUP_NODE_INFO_TEST_001
* @tc.desc: dup node info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, DUP_NODE_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    NetBuilderConfigInit();
    NodeInfo info;
    NodeInfo *ret = nullptr;
    ret = DupNodeInfo(&info);
    EXPECT_TRUE(ret != nullptr);
    if (ret != nullptr) {
        SoftBusFree(ret);
    }
    CleanConnectionFsm(nullptr);
    EXPECT_TRUE(CreateNetworkIdMsgPara(nullptr) == nullptr);
    EXPECT_TRUE(CreateConnectionAddrMsgPara(nullptr) == nullptr);
}

/*
* @tc.name: FIND_CONNECTION_FSM_TEST_001
* @tc.desc: net builder config init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, FIND_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.addr.type = CONNECTION_ADDR_BR;
    connFsm->connInfo.requestId = REQUEST_ID;
    connFsm->connInfo.authHandle.authId = AUTH_ID;
    connFsm->connInfo.authHandle.type = AUTH_LINK_TYPE_BR;
    connFsm->id = FSM_ID;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    MetaJoinRequestNode *requestNode =
        reinterpret_cast<MetaJoinRequestNode *>(SoftBusMalloc(sizeof(MetaJoinRequestNode)));
    ListInit(&requestNode->node);
    (void)strcpy_s(requestNode->addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    requestNode->requestId = REQUEST_ID;

    ConnectionAddr addr;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    addr.type = CONNECTION_ADDR_BR;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillOnce(Return(true));
    EXPECT_TRUE(FindConnectionFsmByAddr(&addr, false) != nullptr);
    addr.type = CONNECTION_ADDR_BLE;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillOnce(Return(false));
    EXPECT_TRUE(FindConnectionFsmByAddr(&addr, false) == nullptr);

    EXPECT_TRUE(FindConnectionFsmByRequestId(REQUEST_ID) != nullptr);
    EXPECT_TRUE(FindConnectionFsmByRequestId(REQUEST_ID_ADD) == nullptr);
    AuthHandle authHandle = { .authId = AUTH_ID, .type = AUTH_LINK_TYPE_BR };
    AuthHandle authHandle2 = {.authId = AUTH_ID_ADD, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_TRUE(FindConnectionFsmByAuthHandle(&authHandle) != nullptr);
    EXPECT_TRUE(FindConnectionFsmByAuthHandle(&authHandle2) == nullptr);
    EXPECT_TRUE(FindConnectionFsmByNetworkId(NODE_NETWORK_ID) != nullptr);
    EXPECT_TRUE(FindConnectionFsmByNetworkId(NODE1_NETWORK_ID) == nullptr);
    EXPECT_TRUE(FindConnectionFsmByConnFsmId(FSM_ID) != nullptr);
    EXPECT_TRUE(FindConnectionFsmByConnFsmId(FSM_ID_ADD) == nullptr);

    ListDelete(&connFsm->node);
    ListDelete(&requestNode->node);
    SoftBusFree(connFsm);
    SoftBusFree(requestNode);
}

/*
* @tc.name: SEND_ELECT_MESSAGE_TO_ALL_TEST_001
* @tc.desc: send elect message to all test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, SEND_ELECT_MESSAGE_TO_ALL_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG1;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    g_netBuilder.maxConcurrentCount = 1;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    EXPECT_TRUE(NeedPendingJoinRequest() == false);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: SEND_ELECT_MESSAGE_TO_ALL_TEST_002
* @tc.desc: send elect message to all test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, SEND_ELECT_MESSAGE_TO_ALL_TEST_002, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG1;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    g_netBuilder.maxConcurrentCount = 1;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, AddStringToJsonObject).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(NetBuilderMock, AddNumberToJsonObject).WillOnce(Return(true)).WillRepeatedly(Return(false));
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    SendElectMessageToAll(NODE1_NETWORK_ID);
    EXPECT_TRUE(NeedPendingJoinRequest() == false);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: INITIATE_NEW_NETWORK_ONLINE_TEST_001
* @tc.desc: initiate new network online test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, INITIATE_NEW_NETWORK_ONLINE_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.addr.type = CONNECTION_ADDR_BR;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG2;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    InitiateNewNetworkOnline(CONNECTION_ADDR_MAX, NODE1_NETWORK_ID);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendNewNetworkOnlineToConnFsm(_)).WillOnce(Return(SOFTBUS_OK));
    InitiateNewNetworkOnline(CONNECTION_ADDR_MAX, NODE_NETWORK_ID);

    EXPECT_CALL(NetBuilderMock, LnnSendNewNetworkOnlineToConnFsm(_)).WillOnce(Return(SOFTBUS_OK));
    InitiateNewNetworkOnline(CONNECTION_ADDR_BR, NODE_NETWORK_ID);
    InitiateNewNetworkOnline(CONNECTION_ADDR_BLE, NODE_NETWORK_ID);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_DISCONNECT_ALL_CONNECTION_TEST_001
* @tc.desc: tyr disconnect all connection test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_DISCONNECT_ALL_CONNECTION_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    connFsm->connInfo.addr.type = CONNECTION_ADDR_BR;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    LnnConnectionFsm fsmTest;
    (void)memset_s(&fsmTest, sizeof(LnnConnectionFsm), 0, sizeof(LnnConnectionFsm));
    fsmTest.connInfo.flag = 1;
    TryDisconnectAllConnection(&fsmTest);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnConvertAddrToOption(_, _)).WillOnce(Return(false));
    fsmTest.connInfo.flag = CONN_FLAG1;
    fsmTest.connInfo.addr.type = CONNECTION_ADDR_BLE;
    TryDisconnectAllConnection(&fsmTest);

    EXPECT_CALL(NetBuilderMock, LnnConvertAddrToOption(_, _)).WillOnce(Return(true));
    EXPECT_CALL(NetBuilderMock, ConnDisconnectDeviceAllConn(_)).WillOnce(Return(SOFTBUS_OK));
    TryDisconnectAllConnection(&fsmTest);

    fsmTest.connInfo.addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(fsmTest.connInfo.addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    TryDisconnectAllConnection(&fsmTest);

    (void)strcpy_s(fsmTest.connInfo.addr.info.br.brMac, BT_MAC_LEN, NODE2_BR_MAC);
    TryDisconnectAllConnection(&fsmTest);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_DISCONNECT_ALL_CONNECTION_TEST_003
* @tc.desc: tyr disconnect all connection test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_DISCONNECT_ALL_CONNECTION_TEST_002, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    connFsm->connInfo.addr.type = CONNECTION_ADDR_WLAN;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    LnnConnectionFsm fsmTest;
    (void)memset_s(&fsmTest, sizeof(LnnConnectionFsm), 0, sizeof(LnnConnectionFsm));
    fsmTest.connInfo.flag = CONN_FLAG1;
    fsmTest.connInfo.addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(fsmTest.connInfo.addr.info.ip.ip, IP_STR_MAX_LEN, NODE2_IP);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnConvertAddrToOption(_, _)).WillOnce(Return(false));
    TryDisconnectAllConnection(&fsmTest);
    TryNotifyAllTypeOffline(&fsmTest);

    (void)strcpy_s(fsmTest.connInfo.addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    TryDisconnectAllConnection(&fsmTest);
    TryNotifyAllTypeOffline(&fsmTest);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_VERIFY_RESULT_TEST_002
* @tc.desc: process verify result test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_VERIFY_RESULT_TEST_002, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    VerifyResultMsgPara *msgPara = reinterpret_cast<VerifyResultMsgPara *>(SoftBusMalloc(sizeof(VerifyResultMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    msgPara->requestId = REQUEST_ID;
    void *para = reinterpret_cast<void *>(msgPara);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    connFsm->connInfo.requestId = REQUEST_ID;
    connFsm->isDead = true;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    EXPECT_TRUE(ProcessVerifyResult(para) != SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_VERIFY_RESULT_TEST_003
* @tc.desc: process verify result test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_VERIFY_RESULT_TEST_003, TestSize.Level1)
{
    VerifyResultMsgPara *msgPara = reinterpret_cast<VerifyResultMsgPara *>(SoftBusMalloc(sizeof(VerifyResultMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    msgPara->requestId = REQUEST_ID;
    msgPara->retCode = SOFTBUS_ERR;
    void *para = reinterpret_cast<void *>(msgPara);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    connFsm->connInfo.requestId = REQUEST_ID;
    connFsm->isDead = false;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendAuthResultMsgToConnFsm(_, _)).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_TRUE(ProcessVerifyResult(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_VERIFY_RESULT_TEST_004
* @tc.desc: process verify result test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_VERIFY_RESULT_TEST_004, TestSize.Level1)
{
    VerifyResultMsgPara *msgPara = reinterpret_cast<VerifyResultMsgPara *>(SoftBusMalloc(sizeof(VerifyResultMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    msgPara->requestId = REQUEST_ID;
    msgPara->retCode = SOFTBUS_ERR;
    void *para = reinterpret_cast<void *>(msgPara);
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    connFsm->connInfo.requestId = REQUEST_ID;
    connFsm->isDead = false;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendAuthResultMsgToConnFsm(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessVerifyResult(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_DEVICE_VERIFY_PASS_TEST_002
* @tc.desc: process device verify pass test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_VERIFY_PASS_TEST_002, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    DeviceVerifyPassMsgPara *msgPara =
        reinterpret_cast<DeviceVerifyPassMsgPara *>(SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    (void)strcpy_s(msgPara->nodeInfo->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    msgPara->authHandle.authId = AUTH_ID;

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.authHandle.authId = AUTH_ID_ADD;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    g_netBuilder.connCount = CURRENT_COUNT;
    g_netBuilder.maxConnCount = CONN_COUNT;
    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessDeviceVerifyPass(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_DEVICE_VERIFY_PASS_TEST_003
* @tc.desc: process device verify pass test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_VERIFY_PASS_TEST_003, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    DeviceVerifyPassMsgPara *msgPara =
        reinterpret_cast<DeviceVerifyPassMsgPara *>(SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    (void)strcpy_s(msgPara->nodeInfo->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    msgPara->authHandle.authId = AUTH_ID;

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.authHandle.authId = AUTH_ID;
    connFsm->isDead = true;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    g_netBuilder.connCount = CURRENT_COUNT;
    g_netBuilder.maxConnCount = CONN_COUNT;
    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessDeviceVerifyPass(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_DEVICE_VERIFY_PASS_TEST_004
* @tc.desc: process device verify pass test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_VERIFY_PASS_TEST_004, TestSize.Level1)
{
    DeviceVerifyPassMsgPara *msgPara =
        reinterpret_cast<DeviceVerifyPassMsgPara *>(SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara)));
    msgPara->nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    (void)strcpy_s(msgPara->nodeInfo->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    msgPara->authHandle.authId = AUTH_ID;

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.authHandle.authId = AUTH_ID;
    connFsm->isDead = false;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessDeviceVerifyPass(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_DEVICE_NOT_TRUSTED_TEST_002
* @tc.desc: process device not trusted test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_DEVICE_NOT_TRUSTED_TEST_002, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    void *msgPara = reinterpret_cast<void *>(SoftBusMalloc(sizeof(char) * UDID_BUF_LEN));
    EXPECT_CALL(NetBuilderMock, LnnGetNetworkIdByUdid(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(NetBuilderMock, LnnGetDeviceUdid(_)).WillRepeatedly(Return(nullptr));

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessDeviceNotTrusted(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_LEAVE_LNN_REQUEST_TEST_002
* @tc.desc: process leave lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_LNN_REQUEST_TEST_002, TestSize.Level1)
{
    char *msgPara = reinterpret_cast<char *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    (void)strcpy_s(msgPara, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnNotifyLeaveResult(_, _)).WillRepeatedly(Return());
    EXPECT_TRUE(ProcessLeaveLNNRequest(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_LEAVE_LNN_REQUEST_TEST_003
* @tc.desc: process leave lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_LNN_REQUEST_TEST_003, TestSize.Level1)
{
    char *msgPara = reinterpret_cast<char *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    (void)strcpy_s(msgPara, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->isDead = true;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnNotifyLeaveResult(_, _)).WillRepeatedly(Return());
    EXPECT_TRUE(ProcessLeaveLNNRequest(para) == SOFTBUS_ERR);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_LEAVE_LNN_REQUEST_TEST_004
* @tc.desc: process leave lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_LNN_REQUEST_TEST_004, TestSize.Level1)
{
    char *msgPara = reinterpret_cast<char *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    (void)strcpy_s(msgPara, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->isDead = false;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnNotifyLeaveResult(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(NetBuilderMock, LnnSendLeaveRequestToConnFsm(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessLeaveLNNRequest(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_SYNC_OFFLINE_FINISH_TEST_002
* @tc.desc: process sync offline finish test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_SYNC_OFFLINE_FINISH_TEST_002, TestSize.Level1)
{
    char *msgPara = reinterpret_cast<char *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    (void)strcpy_s(msgPara, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessSyncOfflineFinish(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_SYNC_OFFLINE_FINISH_TEST_003
* @tc.desc: process sync offline finish test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_SYNC_OFFLINE_FINISH_TEST_003, TestSize.Level1)
{
    char *msgPara = reinterpret_cast<char *>(SoftBusMalloc(sizeof(char) * NETWORK_ID_BUF_LEN));
    (void)strcpy_s(msgPara, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    connFsm->isDead = true;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessSyncOfflineFinish(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_LEAVE_SPECIFIC_TEST_002
* @tc.desc: process leave specific test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_SPECIFIC_TEST_002, TestSize.Level1)
{
    SpecificLeaveMsgPara *msgPara =
        reinterpret_cast<SpecificLeaveMsgPara *>(SoftBusMalloc(sizeof(SpecificLeaveMsgPara)));
    (void)strcpy_s(msgPara->networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);
    msgPara->addrType = CONNECTION_ADDR_BLE;

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    connFsm->connInfo.addr.type = CONNECTION_ADDR_BR;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    void *para = reinterpret_cast<void *>(msgPara);
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(ProcessLeaveSpecific(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: PROCESS_LEAVE_SPECIFIC_TEST_003
* @tc.desc: process leave specific test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_LEAVE_SPECIFIC_TEST_003, TestSize.Level1)
{
    SpecificLeaveMsgPara *msgPara =
        reinterpret_cast<SpecificLeaveMsgPara *>(SoftBusMalloc(sizeof(SpecificLeaveMsgPara)));
    (void)strcpy_s(msgPara->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnSendLeaveRequestToConnFsm(_)).WillRepeatedly(Return(SOFTBUS_OK));
    void *para = reinterpret_cast<void *>(msgPara);
    EXPECT_TRUE(ProcessLeaveSpecific(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: ON_LNN_PROCESS_NOT_TRUSTED_MSG_DELAY_TEST_001
* @tc.desc: on lnn prodecc not trusted msg delay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_LNN_PROCESS_NOT_TRUSTED_MSG_DELAY_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    OnLnnProcessNotTrustedMsgDelay(nullptr);
    void *para1 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(NotTrustedDelayInfo)));
    EXPECT_CALL(NetBuilderMock, AuthGetLatestAuthSeqList(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    OnLnnProcessNotTrustedMsgDelay(para1);

    void *para2 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(NotTrustedDelayInfo)));
    EXPECT_CALL(NetBuilderMock, AuthGetLatestAuthSeqList(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    OnLnnProcessNotTrustedMsgDelay(para2);
}

/*
* @tc.name: PROCESS_ELETE_TEST_002
* @tc.desc: process elect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, PROCESS_ELETE_TEST_002, TestSize.Level1)
{
    ElectMsgPara *msgPara = reinterpret_cast<ElectMsgPara *>(SoftBusMalloc(sizeof(ElectMsgPara)));
    (void)strcpy_s(msgPara->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);

    LnnConnectionFsm *connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    void *para = reinterpret_cast<void *>(msgPara);

    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnGetLocalStrInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_TRUE(ProcessMasterElect(para) == SOFTBUS_OK);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_SEND_JOIN_LNN_REQUEST_TEST_001
* @tc.desc: try send join lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_SEND_JOIN_LNN_REQUEST_TEST_001, TestSize.Level1)
{
    JoinLnnMsgPara *para = nullptr;
    para = reinterpret_cast<JoinLnnMsgPara *>(SoftBusMalloc(sizeof(JoinLnnMsgPara)));
    EXPECT_TRUE(para != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG3;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(false));
    para->isNeedConnect = false;
    (void)strcpy_s(para->pkgName, PKG_NAME_SIZE_MAX, "pkgName");
    EXPECT_TRUE(TrySendJoinLNNRequest(nullptr, true, false) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(TrySendJoinLNNRequest(para, true, false) == SOFTBUS_ERR);

    DfxRecordLnnAuthStart(nullptr, para, 0);
    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_SEND_JOIN_LNN_REQUEST_TEST_002
* @tc.desc: try send join lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_SEND_JOIN_LNN_REQUEST_TEST_002, TestSize.Level1)
{
    JoinLnnMsgPara *para = nullptr;
    para = reinterpret_cast<JoinLnnMsgPara *>(SoftBusMalloc(sizeof(JoinLnnMsgPara)));
    EXPECT_TRUE(para != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG3;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(false));
    para->isNeedConnect = true;
    (void)strcpy_s(para->pkgName, PKG_NAME_SIZE_MAX, "pkgName");
    EXPECT_TRUE(TrySendJoinLNNRequest(para, true, false) == SOFTBUS_OK);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_SEND_JOIN_LNN_REQUEST_TEST_003
* @tc.desc: try send join lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_SEND_JOIN_LNN_REQUEST_TEST_003, TestSize.Level1)
{
    JoinLnnMsgPara *para = nullptr;
    para = reinterpret_cast<JoinLnnMsgPara *>(SoftBusMalloc(sizeof(JoinLnnMsgPara)));
    EXPECT_TRUE(para != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG3;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(true));
    para->isNeedConnect = true;
    (void)strcpy_s(para->pkgName, PKG_NAME_SIZE_MAX, "pkgName");
    EXPECT_TRUE(TrySendJoinLNNRequest(para, true, false) == SOFTBUS_OK);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: TRY_SEND_JOIN_LNN_REQUEST_TEST_004
* @tc.desc: try send join lnn request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_SEND_JOIN_LNN_REQUEST_TEST_004, TestSize.Level1)
{
    JoinLnnMsgPara *para = nullptr;
    para = reinterpret_cast<JoinLnnMsgPara *>(SoftBusMalloc(sizeof(JoinLnnMsgPara)));
    EXPECT_TRUE(para != nullptr);
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG2;
    (void)strcpy_s(connFsm->connInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _)).WillRepeatedly(Return(true));
    para->isNeedConnect = true;
    (void)strcpy_s(para->pkgName, PKG_NAME_SIZE_MAX, "pkgName");
    EXPECT_TRUE(TrySendJoinLNNRequest(para, true, false) == SOFTBUS_OK);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: LNN_PROCESS_COMPLETE_NOT_TRUSTED_MSG_TEST_001
* @tc.desc: lnn process complete not trusted msg test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, LNN_PROCESS_COMPLETE_NOT_TRUSTED_MSG_TEST_001, TestSize.Level1)
{
    char jsonStr[] = "{\"1\":10}";
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnGetOnlineStateById).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, AuthGetLatestAuthSeqList)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, nullptr, nullptr, 0);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_WIFI_DIRECT, NODE_NETWORK_ID, nullptr, MSG_ERR_LEN0);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, NODE_NETWORK_ID, nullptr, MSG_ERR_LEN0);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr), MSG_ERR_LEN0);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr), MSG_ERR_LEN0);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr), strlen(jsonStr) + 1);
    LnnProcessCompleteNotTrustedMsg(LNN_INFO_TYPE_NOT_TRUSTED, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr), strlen(jsonStr) + 1);
}

/*
* @tc.name: ON_RE_AUTH_VERIFY_PASSED_TEST_001
* @tc.desc: on re auth verify passed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_RE_AUTH_VERIFY_PASSED_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, GetAuthRequest)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnConvertAuthConnInfoToAddr)
        .WillOnce(Return(false))
            .WillRepeatedly(Return(true));
    AuthHandle authHandle = { .authId = AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, nullptr);
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, &info);
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, &info);
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, &info);
}

/*
* @tc.name: ON_RE_AUTH_VERIFY_PASSED_TEST_002
* @tc.desc: on re auth verify passed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_RE_AUTH_VERIFY_PASSED_TEST_002, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.version = SOFTBUS_NEW_V1;
    connFsm->isDead = false;
    connFsm->connInfo.flag = CONN_FLAG2;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    NodeInfo info;
    (void)strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE_UDID);

    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, GetAuthRequest).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnConvertAuthConnInfoToAddr).WillRepeatedly(Return(true));
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    AuthHandle authHandle = { .authId = AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, &info);
    OnReAuthVerifyPassed(REQUEST_ID, authHandle, &info);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: FIND_NODE_INFO_BY_RQUESTID_TEST_001
* @tc.desc: find node info by rquestid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, FIND_NODE_INFO_BY_RQUESTID_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, LnnIsSameConnectionAddr(_, _, _))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    ListInit(&connFsm->node);
    connFsm->connInfo.requestId = REQUEST_ID;
    connFsm->isDead = false;
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);

    ConnectionAddr addr;
    uint32_t requestId;
    int32_t ret = FindRequestIdByAddr(&addr, &requestId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = FindRequestIdByAddr(&addr, &requestId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo *info = FindNodeInfoByRquestId(requestId);
    EXPECT_TRUE(info != nullptr);

    ListDelete(&connFsm->node);
    SoftBusFree(connFsm);
}

/*
* @tc.name: ON_RECEIVE_NODE_ADDR_CHANGED_MSG_TEST_001
* @tc.desc: on receive node addr changed msg test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ON_RECEIVE_NODE_ADDR_CHANGED_MSG_TEST_001, TestSize.Level1)
{
    char jsonStr1[] = "{\"NODE_CODE\":1111,\"NODE_ADDR\":\"127.0.0.1\",\"PROXY_PORT\":1000,\"SESSION_PORT\":1001}";
    char jsonStr2[] = "{\"NODE_ADDR\":\"127.0.0.1\",\"PROXY_PORT\":1000,\"SESSION_PORT\":1001}";
    char jsonStr3[] = "{\"NODE_CODE\":1111,\"PROXY_PORT\":1000,\"SESSION_PORT\":1001}";
    char jsonStr4[] = "{\"NODE_CODE\":1111,\"NODE_ADDR\":\"127.0.0.1\",\"SESSION_PORT\":1001}";
    char jsonStr5[] = "{\"NODE_CODE\":1111,\"NODE_ADDR\":\"127.0.0.1\",\"PROXY_PORT\":1000}";
    uint8_t jsonMsg6[] = {0};
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_DEVICE_NAME, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr1), MSG_ERR_LEN0);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr1), MSG_ERR_LEN0);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID, jsonMsg6, MSG_ERR_LEN1);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr2), strlen(jsonStr2) + 1);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr3), strlen(jsonStr3) + 1);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr4), strlen(jsonStr4) + 1);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr5), strlen(jsonStr5) + 1);
    OnReceiveNodeAddrChangedMsg(LNN_INFO_TYPE_NODE_ADDR, NODE_NETWORK_ID,
        reinterpret_cast<uint8_t *>(jsonStr1), strlen(jsonStr1) + 1);
}

/*
* @tc.name: ACCOUNT_STATE_CHANGE_HANDLER_TEST_001
* @tc.desc: account state change handler test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, ACCOUNT_STATE_CHANGE_HANDLER_TEST_001, TestSize.Level1)
{
    LnnEventBasicInfo info;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    AccountStateChangeHandler(nullptr);
    AccountStateChangeHandler(&info);
    info.event = LNN_EVENT_ACCOUNT_CHANGED;
    AccountStateChangeHandler(&info);
    UpdatePCInfoWithoutSoftbus();
    UpdatePCInfoWithoutSoftbus();
    UpdatePCInfoWithoutSoftbus();
}

/*
* @tc.name: TRY_INITIATE_NEW_NETWORK_ONLINE_TEST_001
* @tc.desc: try initiate new network online test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, TRY_INITIATE_NEW_NETWORK_ONLINE_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm1 = nullptr;
    connFsm1 = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm1 != nullptr);
    connFsm1->connInfo.flag = CONN_FLAG1;
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    TryInitiateNewNetworkOnline(connFsm1);
    SoftBusFree(connFsm1);
}

/*
* @tc.name: LNN_REQUEST_LEAVE_ALL_ONLINE_NODES_TEST_001
* @tc.desc: lnn request leave all online nodes test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetBuilderMockTest, LNN_REQUEST_LEAVE_ALL_ONLINE_NODES_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> NetBuilderMock;
    EXPECT_CALL(NetBuilderMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetBuilderMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    LnnRequestLeaveAllOnlineNodes();
    LnnRequestLeaveAllOnlineNodes();
}
} // namespace OHOS
