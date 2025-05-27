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
#include <securec.h>

#include "lnn_net_ledger_deps_mock.h"
#include "lnn_net_ledger.c"
#include "dsoftbus_enhance_interface.h"
#include "g_enhance_lnn_func.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint8_t IRK1[LFINDER_IRK_LEN] = "tmpIrk1";
constexpr uint8_t IRK2[LFINDER_IRK_LEN] = "tmpIrk2";
constexpr uint8_t KEY1[SESSION_KEY_LENGTH] = "tmpKey1";
constexpr uint8_t KEY2[SESSION_KEY_LENGTH] = "tmpKey2";
constexpr uint8_t IV1[BROADCAST_IV_LEN] = "tmpIv1";
constexpr uint8_t IV2[BROADCAST_IV_LEN] = "tmpIv2";
constexpr int32_t FD = 12;

class LNNNetLedgerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetLedgerMockTest::SetUpTestCase()
{
}

void LNNNetLedgerMockTest::TearDownTestCase()
{
}

void LNNNetLedgerMockTest::SetUp() { }

void LNNNetLedgerMockTest::TearDown()
{
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest001
 * @tc.desc: local irk info change test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest002
 * @tc.desc: local irk info change test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest001
 * @tc.desc: local link key change test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest002
 * @tc.desc: local link key change test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_OK))
    .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest003
 * @tc.desc: local link key change test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest003, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), false);
}

/*
 * @tc.name: LnnInitNetLedgerTest001
 * @tc.desc: LnnInitNetLedger  test
 * @tc.type: FUNC
 * @tc.require: IBH09C
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitNetLedgerTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnInitModuleNotifyWithRetrySync).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitLocalLedger).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitDistributedLedger).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitMetaNodeLedger).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnInitMetaNodeExtLedger).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_HUKS_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
    EXPECT_EQ(LnnInitNetLedger(), SOFTBUS_OK);
}

/*
 * @tc.name: IsCapacityChangeTest001
 * @tc.desc: IsCapacityChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsCapacityChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(IsCapacityChange(&info), false);
}

/*
 * @tc.name: IsCapacityChangeTest002
 * @tc.desc: IsCapacityChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsCapacityChangeTest002, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.feature = 1;
    info.authCapacity = 2;
    info.heartbeatCapacity = 3;
    info.staticNetCap = 4;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.feature = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.authCapacity = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.heartbeatCapacity = 0;
    EXPECT_EQ(IsCapacityChange(&info), true);
    info.staticNetCap = 0;
    EXPECT_EQ(IsCapacityChange(&info), false);
}

/*
 * @tc.name: IsLocalIrkInfoChangeTest003
 * @tc.desc: IsLocalIrkInfoChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalIrkInfoChangeTest003, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.rpaInfo.peerIrk, LFINDER_IRK_LEN, IRK1, LFINDER_IRK_LEN), EOK);
    unsigned char localIrk[LFINDER_IRK_LEN] = { 0 };
    EXPECT_EQ(memcpy_s(localIrk, LFINDER_IRK_LEN, IRK2, LFINDER_IRK_LEN), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localIrk), Return(SOFTBUS_OK)));
    EXPECT_EQ(IsLocalIrkInfoChange(&info), true);
}

/*
 * @tc.name: IsLocalBroadcastLinKeyChangeTest004
 * @tc.desc: IsLocalBroadcastLinKeyChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalBroadcastLinKeyChangeTest004, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.cipherInfo.key, SESSION_KEY_LENGTH, KEY1, SESSION_KEY_LENGTH), EOK);
    EXPECT_EQ(memcpy_s(info.cipherInfo.iv, BROADCAST_IV_LEN, IV1, BROADCAST_IV_LEN), EOK);
    unsigned char key[SESSION_KEY_LENGTH] = { 0 };
    unsigned char iv[BROADCAST_IV_LEN] = { 0 };
    EXPECT_EQ(memcpy_s(key, SESSION_KEY_LENGTH, KEY2, SESSION_KEY_LENGTH), EOK);
    EXPECT_EQ(memcpy_s(iv, BROADCAST_IV_LEN, IV2, BROADCAST_IV_LEN), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo)
        .WillOnce(DoAll(SetArgPointee<1>(*key), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*iv), Return(SOFTBUS_OK)));
    EXPECT_EQ(IsLocalBroadcastLinKeyChange(&info), true);
}

/*
 * @tc.name: IsLocalSupportUserKeyChangeTest001
 * @tc.desc: IsLocalSupportUserKeyChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsLocalSupportUserKeyChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.isSupportUkNego = 1;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalBoolInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsLocalSupportUserKeyChange(&info), true);
}

/*
 * @tc.name: IsBleDirectlyOnlineFactorChangeTest001
 * @tc.desc: IsBleDirectlyOnlineFactorChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, IsBleDirectlyOnlineFactorChangeTest001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.deviceInfo.osType = 100;
    info.deviceSecurityLevel = 1;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalBoolInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
    info.deviceInfo.osType = 0;
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), true);
    info.deviceSecurityLevel = 0;
    EXPECT_EQ(IsBleDirectlyOnlineFactorChange(&info), false);
}

/*
 * @tc.name: LnnSetLocalFeatureTest001
 * @tc.desc: LnnSetLocalFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetLocalFeatureTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, IsSupportLpFeature)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
    EXPECT_CALL(netLedgerMock, LnnSetLocalNum64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(LnnSetLocalFeature());
}

/*
 * @tc.name: ProcessLocalDeviceInfoTest001
 * @tc.desc: ProcessLocalDeviceInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, ProcessLocalDeviceInfoTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnDumpNodeInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnDumpNodeInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalBoolInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnSaveLocalDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalNetworkId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalDeviceName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnNotifyNetworkIdChangeEvent).WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
    EXPECT_NO_FATAL_FAILURE(ProcessLocalDeviceInfo());
}

/*
 * @tc.name: LnnInitNetLedgerDelayTest001
 * @tc.desc: LnnInitNetLedgerDelay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitNetLedgerDelayTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, AuthLoadDeviceKey).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnInitLocalLedgerDelay).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(netLedgerMock, LnnInitDecisionDbDelay).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetLedgerDelay(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnInitEventMoniterDelayTest001
 * @tc.desc: LnnInitEventMoniterDelay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnInitEventMoniterDelayTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnInitCommonEventMonitorImpl).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitEventMoniterDelay(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitEventMoniterDelay(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetNodeKeyInfoLocalTest001
 * @tc.desc: LnnGetNodeKeyInfoLocal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoLocalTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetNodeKeyInfoLocal(nullptr, 1, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfoLocal(networkId, 1, nullptr, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetNodeKeyInfoRemoteTest001
 * @tc.desc: LnnGetNodeKeyInfoRemote test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoRemoteTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(nullptr, 1, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, 1, nullptr, 2), SOFTBUS_INVALID_PARAM);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteBoolInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_P2P_IP_ADDRESS, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_DEVICE_SECURITY_LEVEL, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_DEVICE_SCREEN_STATUS, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetNodeKeyInfoRemote(networkId, NODE_KEY_STATIC_NETWORK_CAP, &info, 2), SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetNodeKeyInfoTest001
 * @tc.desc: LnnGetNodeKeyInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetNodeKeyInfoTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnGetNodeKeyInfo(nullptr, NODE_KEY_P2P_IP_ADDRESS, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfo(networkId, NODE_KEY_P2P_IP_ADDRESS, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetNodeKeyInfo(networkId, NODE_KEY_P2P_IP_ADDRESS, &info, 2),
        SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoLocalTest001
 * @tc.desc: LnnGetPrivateNodeKeyInfoLocal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoLocalTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(nullptr, BYTE_KEY_IRK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(networkId, BYTE_KEY_IRK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoLocal(networkId, BYTE_KEY_STATIC_CAPABILITY, &info, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoRemoteTest001
 * @tc.desc: LnnGetPrivateNodeKeyInfoRemote test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoRemoteTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    uint8_t info;
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(nullptr, BYTE_KEY_IRK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_IRK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_IRK, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_BROADCAST_CIPHER_KEY, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_ACCOUNT_HASH, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_OK);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfoRemote(networkId, BYTE_KEY_STATIC_CAPABILITY, &info, 2), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetPrivateNodeKeyInfoTest001
 * @tc.desc: LnnGetPrivateNodeKeyInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnGetPrivateNodeKeyInfoTest001, TestSize.Level1)
{
    const char *networkId = "networkId";
    const char *networkIdNew = "networkIdNew";
    uint8_t info;
    char localNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    EXPECT_EQ(strcpy_s(localNetworkId, NETWORK_ID_BUF_LEN, networkIdNew), EOK);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localNetworkId), Return(SOFTBUS_OK)));
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(nullptr, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, nullptr, 2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_NOT_FIND);
    EXPECT_EQ(LnnGetPrivateNodeKeyInfo(networkId, BYTE_KEY_REMOTE_PTK, &info, 2), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDataLevelTest001
 * @tc.desc: LnnSetDataLevel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnSetDataLevelTest001, TestSize.Level1)
{
    DataLevel dataLevel;
    (void)memset_s(&dataLevel, sizeof(DataLevel), 0, sizeof(DataLevel));
    bool isSwitchLevelChanged = false;
    EXPECT_EQ(LnnSetDataLevel(nullptr, &isSwitchLevelChanged), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, nullptr), SOFTBUS_INVALID_PARAM);
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU32Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged), SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusDumpPrintAccountIdTest001
 * @tc.desc: SoftbusDumpPrintAccountId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpPrintAccountIdTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = FD;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(SoftbusDumpPrintUdid(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintUdid(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintUuid(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintUuid(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintMac(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintMac(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintIp(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintIp(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintDynamicNetCap(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintNetType(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintDeviceLevel(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintDeviceLevel(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintScreenStatus(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintScreenStatus(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintStaticNetCap(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintStaticNetCap(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintIrk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintIrk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintBroadcastCipher(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintBroadcastCipher(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_EQ(SoftbusDumpPrintRemotePtk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintRemotePtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: SoftbusDumpPrintLocalPtkTest001
 * @tc.desc: SoftbusDumpPrintLocalPtk test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpPrintLocalPtkTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = FD;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnAnonymizePtk).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalPtkByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_NOT_FIND);
    EXPECT_CALL(netLedgerMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_BYTE_CONVERT_FAIL);
    EXPECT_EQ(SoftbusDumpPrintLocalPtk(fd, &nodeInfo), SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusDumpDeviceInfoTest001
 * @tc.desc: SoftbusDumpDeviceInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceInfoTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, &nodeInfo));
    fd = FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceInfo(fd, &nodeInfo));
}

/*
 * @tc.name: SoftbusDumpDeviceAddrTest001
 * @tc.desc: SoftbusDumpDeviceAddr test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceAddrTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, &nodeInfo));
    fd = FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceAddr(fd, &nodeInfo));
}

/*
 * @tc.name: SoftbusDumpDeviceCipherTest001
 * @tc.desc: SoftbusDumpDeviceCipher test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, SoftbusDumpDeviceCipherTest001, TestSize.Level1)
{
    NodeBasicInfo nodeInfo;
    int32_t fd = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, &nodeInfo));
    fd = FD;
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, nullptr));
    EXPECT_NO_FATAL_FAILURE(SoftbusDumpDeviceCipher(fd, &nodeInfo));
}

/*
 * @tc.name: LnnUpdateLocalDeviceInfoTest001
 * @tc.desc: LnnUpdateLocalDeviceInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerMockTest, LnnUpdateLocalDeviceInfoTest001, TestSize.Level1)
{
    NetLedgerDepsInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, ClearDeviceInfo).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, AuthClearDeviceKey).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnClearPtkList).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, LnnUpdateLocalUuidAndIrk).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnGenLocalNetworkId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, GenerateNewLocalCipherKey).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnRemoveDb).WillRepeatedly(Return());
    EXPECT_CALL(netLedgerMock, InitTrustedDevInfoTable).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnGenBroadcastCipherInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalDeviceInfo(), SOFTBUS_OK);
}
} // namespace OHOS
