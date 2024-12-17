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
#include <securec.h>

#include "hb_strategy_mock.h"
#include "hb_medium_mgr_static_mock.h"
#include "lnn_heartbeat_medium_mgr.c"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_node_info.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class HeartBeatMediumStaticTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatMediumStaticTest::SetUpTestCase()
{
}

void HeartBeatMediumStaticTest::TearDownTestCase()
{
}

void HeartBeatMediumStaticTest::SetUp() { }

void HeartBeatMediumStaticTest::TearDown() { }

/*
 * @tc.name: HbSaveRecvTimeToRemoveRepeat
 * @tc.desc: HbSaveRecvTimeToRemoveRepeat test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbSaveRecvTimeToRemoveRepeat, TestSize.Level1)
{
    LnnHeartbeatRecvInfo storedInfo;
    DeviceInfo device;
    DeviceInfo device1;
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&device1, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    storedInfo.device = &device1;
    int32_t weight = 0;
    int32_t masterWeight = 0;
    uint64_t recvTime = 0;
    int32_t ret = HbSaveRecvTimeToRemoveRepeat(&storedInfo, &device, weight, masterWeight, recvTime);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: HbGetRepeatThresholdByTypeTest_01
 * @tc.desc: HbGetRepeatThresholdByType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbGetRepeatThresholdByTypeTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    int32_t infoNum = 8;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_NO_ONLINE_DEVICE));
    int64_t ret = HbGetRepeatThresholdByType(HEARTBEAT_TYPE_BLE_V0);
    EXPECT_EQ(ret, HB_REPEAD_RECV_THRESHOLD_MULTI_DEVICE);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    nodeInfo.deviceInfo.deviceTypeId = TYPE_PC_ID;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillOnce(
        DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    char networkId[] = "1123344";
    HbRespData hbResp;
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    UpdateOnlineInfoNoConnection(networkId, &hbResp);
    ret = HbGetRepeatThresholdByType(HEARTBEAT_TYPE_BLE_V0);
    EXPECT_EQ(ret, HB_REPEAD_RECV_THRESHOLD);
    nodeInfo.deviceInfo.deviceTypeId = TYPE_PHONE_ID;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillOnce(
        DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    hbResp.capabiltiy = ENABLE_WIFI_CAP | P2P_GO | DISABLE_BR_CAP;
    UpdateOnlineInfoNoConnection(networkId, &hbResp);
    ret = HbGetRepeatThresholdByType(HEARTBEAT_TYPE_BLE_V3);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: HbGetOnlineNodeByRecvInfoTest_01
 * @tc.desc: HbGetOnlineNodeByRecvInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbGetOnlineNodeByRecvInfoTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    int32_t infoNum = 3;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMediumMock, LnnConvAddrTypeToDiscType).WillRepeatedly(Return(DISCOVERY_TYPE_BLE));
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillOnce(Return(true)).WillRepeatedly(Return(false));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    NodeInfo nodeInfo;
    HbRespData hbResp;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    char recvUdidHash[] = "recvUdidHash";
    int32_t ret = HbGetOnlineNodeByRecvInfo(recvUdidHash, CONNECTION_ADDR_BLE, &nodeInfo, &hbResp);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: HbIsRepeatedRecvInfoTest_01
 * @tc.desc: HbIsRepeatedRecvInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbIsRepeatedRecvInfoTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    LnnHeartbeatRecvInfo storedInfo;
    DeviceInfo device;
    DeviceInfo device1;
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&device1, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    storedInfo.device = &device1;
    storedInfo.lastRecvTime = 0;
    storedInfo.device->isOnline = false;
    device.isOnline = true;
    uint64_t nowTime = 0;
    bool ret = HbIsRepeatedRecvInfo(HEARTBEAT_TYPE_BLE_V0, &storedInfo, &device, nowTime);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: HbIsNeedReAuthTest_01
 * @tc.desc: HbIsNeedReAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbIsNeedReAuthTest_01, TestSize.Level1)
{
    NodeInfo nodeInfo;
    NodeInfo deviceInfo;
    HbRespData hbResp;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    char newAccountHash[] = "newAccountHash";
    hbResp.userIdCheckSum[0] = 11;
    EXPECT_NO_FATAL_FAILURE(UpdateUserIdCheckSum(nullptr, nullptr));
    bool ret = HbIsNeedReAuth(&nodeInfo, newAccountHash);
    EXPECT_TRUE(ret);
    EXPECT_NO_FATAL_FAILURE(UpdateUserIdCheckSum(&deviceInfo, &hbResp));
    EXPECT_EQ(strcpy_s(nodeInfo.accountHash, sizeof(newAccountHash), newAccountHash), EOK);
    ret = HbIsNeedReAuth(&nodeInfo, newAccountHash);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsLocalSupportBleDirectOnlineStaticTest_01
 * @tc.desc: IsLocalSupportBleDirectOnline test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsLocalSupportBleDirectOnlineStaticTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    uint64_t localFeatureCap = (1 << BIT_BLE_DIRECT_ONLINE);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillOnce(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    uint32_t deviceInfoNetCapacity = 0;
    HbRespData hbResp;
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    hbResp.capabiltiy = 0;
    SetDeviceNetCapability(&deviceInfoNetCapacity, &hbResp);
    hbResp.capabiltiy = ENABLE_WIFI_CAP | DISABLE_BR_CAP | P2P_GC;
    SetDeviceNetCapability(&deviceInfoNetCapacity, &hbResp);
    bool ret = IsLocalSupportBleDirectOnline();
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: SetDeviceScreenStatusTest_01
 * @tc.desc: SetDeviceScreenStatus test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, SetDeviceScreenStatusTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NodeInfo nodeInfo;
    HbRespData hbResp;
    uint32_t deviceInfoNetCapacity = 0;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    hbResp.capabiltiy = ENABLE_WIFI_CAP | DISABLE_BR_CAP | P2P_GO;
    SetDeviceNetCapability(&deviceInfoNetCapacity, &hbResp);
    int32_t ret = SetDeviceScreenStatus(nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    hbResp.capabiltiy = ENABLE_WIFI_CAP | DISABLE_BR_CAP | P2P_GC | P2P_GO;
    SetDeviceNetCapability(&deviceInfoNetCapacity, &hbResp);
    ret = SetDeviceScreenStatus(&nodeInfo, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IsStateVersionChangedTest_01
 * @tc.desc: IsStateVersionChanged test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsStateVersionChangedTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    HbRespData hbResp;
    NodeInfo deviceInfo;
    ConnectOnlineReason connectReason;
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&connectReason, sizeof(ConnectOnlineReason), 0, sizeof(ConnectOnlineReason));
    int32_t stateVersion = 2;
    deviceInfo.localStateVersion = 1;
    bool ret = IsStateVersionChanged(&hbResp, &deviceInfo, &stateVersion, &connectReason);
    EXPECT_TRUE(ret);
    deviceInfo.localStateVersion = 2;
    hbResp.stateVersion = 2;
    deviceInfo.stateVersion = 1;
    ret = IsStateVersionChanged(&hbResp, &deviceInfo, &stateVersion, &connectReason);
    EXPECT_TRUE(ret);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = IsStateVersionChanged(&hbResp, &deviceInfo, &stateVersion, &connectReason);
    EXPECT_TRUE(ret);
    deviceInfo.stateVersion = 2;
    deviceInfo.localStateVersion = 2;
    ret = IsStateVersionChanged(&hbResp, &deviceInfo, &stateVersion, &connectReason);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsInvalidBrmacTest_01
 * @tc.desc: IsInvalidBrmac test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsInvalidBrmacTest_01, TestSize.Level1)
{
    LnnBleReportExtra bleExtra;
    LnnEventExtra extra;
    (void)memset_s(&bleExtra, sizeof(LnnBleReportExtra), 0, sizeof(LnnBleReportExtra));
    (void)memset_s(&extra, sizeof(LnnEventExtra), 0, sizeof(LnnEventExtra));
    EXPECT_NO_FATAL_FAILURE(CopyBleReportExtra(nullptr, nullptr));
    bool ret = IsInvalidBrmac("");
    EXPECT_TRUE(ret);
    EXPECT_NO_FATAL_FAILURE(CopyBleReportExtra(&bleExtra, nullptr));
    EXPECT_NO_FATAL_FAILURE(CopyBleReportExtra(nullptr, &extra));
    ret = IsInvalidBrmac(INVALID_BR_MAC_ADDR);
    EXPECT_TRUE(ret);
    EXPECT_NO_FATAL_FAILURE(CopyBleReportExtra(&bleExtra, &extra));
    bleExtra.extra.peerNetworkId[0] = 111;
    EXPECT_NO_FATAL_FAILURE(CopyBleReportExtra(&bleExtra, &extra));
    ret = IsInvalidBrmac("INVALID_BR_MAC_ADDR");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsUuidChangeTest_01
 * @tc.desc: IsUuidChange test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsUuidChangeTest_01, TestSize.Level1)
{
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    char oldUuid[] = "oldUuid";
    HbRespData hbResp;
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    bool ret = IsUuidChange(nullptr, nullptr, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
    ret = IsUuidChange(oldUuid, nullptr, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
    ret = IsUuidChange(nullptr, &hbResp, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
    ret = IsUuidChange(oldUuid, &hbResp, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
    EXPECT_CALL(hbMediumMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    hbResp.shortUuid[0] = 11;
    ret = IsUuidChange(oldUuid, &hbResp, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
    ret = IsUuidChange(oldUuid, &hbResp, HB_SHORT_UUID_LEN);
    EXPECT_TRUE(ret);
    unsigned char shortUuid[HB_SHORT_UUID_LEN];
    (void)memset_s(shortUuid, HB_SHORT_UUID_LEN, 0, HB_SHORT_UUID_LEN);
    shortUuid[0] = 11;
    EXPECT_CALL(hbMediumMock, SoftBusGenerateStrHash)
        .WillRepeatedly(DoAll(SetArgPointee<2>(*shortUuid), Return(SOFTBUS_OK)));
    ret = IsUuidChange(oldUuid, &hbResp, HB_SHORT_UUID_LEN);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsNeedConnectOnLineTest_01
 * @tc.desc: IsNeedConnectOnLine test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsNeedConnectOnLineTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    NodeInfo deviceInfo;
    ConnectOnlineReason connectReason;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&connectReason, sizeof(ConnectOnlineReason), 0, sizeof(ConnectOnlineReason));
    uint64_t localFeatureCap = (1 << BIT_BLE_DIRECT_ONLINE);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillOnce(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_INVALID_PARAM)));
    bool ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    EXPECT_EQ(strcpy_s(deviceInfo.connectInfo.macAddr, MAC_LEN - 1, "macAddr"), EOK);
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillOnce(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_INVALID_PARAM)));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillOnce(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_OK)));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    deviceInfo.stateVersion = 1;
    deviceInfo.deviceInfo.osType = OH_OS_TYPE;
    EXPECT_EQ(strcpy_s(deviceInfo.connectInfo.macAddr, MAC_LEN - 1, "ATTEST_CERTS"), EOK);
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    hbResp.stateVersion = 0;
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    hbResp.stateVersion = 1;
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsNeedConnectOnLineTest_02
 * @tc.desc: IsNeedConnectOnLine test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsNeedConnectOnLineTest_02, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    NodeInfo deviceInfo;
    ConnectOnlineReason connectReason;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&connectReason, sizeof(ConnectOnlineReason), 0, sizeof(ConnectOnlineReason));
    uint64_t localFeatureCap = (1 << BIT_BLE_DIRECT_ONLINE);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    deviceInfo.stateVersion = 1;
    deviceInfo.deviceInfo.osType = OH_OS_TYPE;
    EXPECT_EQ(strcpy_s(deviceInfo.connectInfo.macAddr, MAC_LEN - 1, "ATTEST_CERTS"), EOK);
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    hbResp.stateVersion = 1;
    EXPECT_CALL(hbMediumMock, IsCloudSyncEnabled).WillRepeatedly(Return(false));
    EXPECT_CALL(hbMediumMock, IsFeatureSupport).WillRepeatedly(Return(false));
    EXPECT_CALL(hbMediumMock, AuthFindDeviceKey).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(hbMediumMock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    EXPECT_CALL(hbMediumMock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStategyMock, LnnUpdateRemoteDeviceInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    EXPECT_CALL(hbMediumMock, IsCipherManagerFindKey).WillRepeatedly(Return(false));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_TRUE(ret);
    EXPECT_CALL(hbMediumMock, IsCipherManagerFindKey).WillRepeatedly(Return(true));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_FALSE(ret);
    deviceInfo.deviceInfo.osType = HO_OS_TYPE;
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(deviceInfo), Return(SOFTBUS_OK)));
    unsigned char shortUuid[HB_SHORT_UUID_LEN];
    shortUuid[0] = 11;
    EXPECT_CALL(hbMediumMock, SoftBusGenerateStrHash)
        .WillRepeatedly(DoAll(SetArgPointee<2>(*shortUuid), Return(SOFTBUS_OK)));
    ret = IsNeedConnectOnLine(&device, &hbResp, &connectReason);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: HbIsRepeatedReAuthRequestStaticTest_01
 * @tc.desc: heartbeat medium manger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbIsRepeatedReAuthRequestStaticTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    LnnBleReportExtra bleExtra1;
    EXPECT_CALL(hbStrateMock, GetNodeFromLnnBleReportExtraMap)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(bleExtra1), Return(SOFTBUS_OK)));
    char *udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    ASSERT_TRUE(udidHash != nullptr);
    HbProcessDfxMessage(nullptr);
    HbProcessDfxMessage(static_cast<void*>(udidHash));
    udidHash = nullptr;
    udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    ASSERT_TRUE(udidHash != nullptr);
    HbProcessDfxMessage(static_cast<void*>(udidHash));
    udidHash = nullptr;
    udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    ASSERT_TRUE(udidHash != nullptr);
    bleExtra1.status = BLE_REPORT_EVENT_SUCCESS;
    EXPECT_CALL(hbStrateMock, GetNodeFromLnnBleReportExtraMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(bleExtra1), Return(SOFTBUS_OK)));
    HbProcessDfxMessage(static_cast<void*>(udidHash));
    udidHash = nullptr;
    udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    ASSERT_TRUE(udidHash != nullptr);
    bleExtra1.status = BLE_REPORT_EVENT_INIT;
    EXPECT_CALL(hbStrateMock, GetNodeFromLnnBleReportExtraMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(bleExtra1), Return(SOFTBUS_OK)));
    HbProcessDfxMessage(static_cast<void*>(udidHash));
    LnnHeartbeatRecvInfo storedInfo;
    uint64_t nowTime = HB_RECV_INFO_SAVE_LEN;
    bool ret = HbIsRepeatedReAuthRequest(&storedInfo, nowTime);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: HbAddAsyncProcessCallbackDelayTest_01
 * @tc.desc: heartbeat medium manger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbAddAsyncProcessCallbackDelayTest_01, TestSize.Level1)
{
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    bool isRestrict = false;
    int32_t ret = HbAddAsyncProcessCallbackDelay(nullptr, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(hbMediumMock, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    device.addr[0].type = CONNECTION_ADDR_BLE;
    ret = HbAddAsyncProcessCallbackDelay(&device, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t count = 0;
    EXPECT_CALL(hbStategyMock, GetNodeFromPcRestrictMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(count), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(hbStategyMock, IsExistLnnDfxNodeByUdidHash)
        .WillOnce(Return(true))
        .WillRepeatedly(Return(false));
    ret = HbAddAsyncProcessCallbackDelay(&device, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    count = PC_RESTRICT_TIME;
    EXPECT_CALL(hbStategyMock, GetNodeFromPcRestrictMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(count), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(hbStategyMock, LnnAsyncCallbackDelayHelper)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = HbAddAsyncProcessCallbackDelay(&device, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(hbStategyMock, GetNodeFromPcRestrictMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(count), Return(SOFTBUS_OK)));
    ret = HbAddAsyncProcessCallbackDelay(&device, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    count += PC_RESTRICT_TIME;
    EXPECT_CALL(hbStategyMock, GetNodeFromPcRestrictMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(count), Return(SOFTBUS_OK)));
    ret = HbAddAsyncProcessCallbackDelay(&device, &isRestrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusNetNodeResultTest_01
 * @tc.desc: SoftBusNetNodeResult test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, SoftBusNetNodeResultTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    LnnConnectCondition connectCondition;
    LnnHeartbeatRecvInfo storedInfo;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&connectCondition, sizeof(LnnConnectCondition), 0, sizeof(LnnConnectCondition));
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    EXPECT_CALL(hbStategyMock, LnnNotifyDiscoveryDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    connectCondition.isDirectlyHb = true;
    int32_t ret = SoftBusNetNodeResult(&device, nullptr, &connectCondition, &storedInfo, HB_REPEAD_JOIN_LNN_THRESHOLD);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_DIRECT);
    connectCondition.isDirectlyHb = false;
    connectCondition.isConnect = true;
    storedInfo.lastJoinLnnTime = 0;
    ret = SoftBusNetNodeResult(&device, nullptr, &connectCondition, &storedInfo, HB_REPEAD_JOIN_LNN_THRESHOLD);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);
    connectCondition.isConnect = false;
    storedInfo.lastJoinLnnTime = 0;
    ret = SoftBusNetNodeResult(&device, nullptr, &connectCondition, &storedInfo, HB_REPEAD_JOIN_LNN_THRESHOLD);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_DIRECT_ONLINE);
    device.addr[0].type = CONNECTION_ADDR_BLE;
    EXPECT_CALL(hbMediumMock, ConvertBytesToHexString)
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t count = PC_RESTRICT_TIME;
    EXPECT_CALL(hbStategyMock, GetNodeFromPcRestrictMap)
        .WillRepeatedly(DoAll(SetArgPointee<1>(count), Return(SOFTBUS_OK)));
    ret = SoftBusNetNodeResult(&device, nullptr, &connectCondition, &storedInfo, HB_REPEAD_JOIN_LNN_THRESHOLD);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_PC_RESTRICT);
    DfxRecordHeartBeatAuthStart(nullptr, nullptr, 0);
}

/*
 * @tc.name: HbOnlineNodeAuthTest_01
 * @tc.desc: HbOnlineNodeAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbOnlineNodeAuthTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    LnnHeartbeatRecvInfo storedInfo;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    device.isOnline = false;
    int32_t ret = HbOnlineNodeAuth(&device, &storedInfo, HB_TIME_FACTOR_TWO_HUNDRED_MS);
    EXPECT_EQ(ret, SOFTBUS_OK);
    device.isOnline = true;
    ret = HbOnlineNodeAuth(&device, &storedInfo, HB_TIME_FACTOR_TWO_HUNDRED_MS);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_REPEATED);
    EXPECT_CALL(hbStrateMock, AuthStartVerify)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = HbOnlineNodeAuth(&device, &storedInfo, HB_START_DELAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_AUTH_START_VERIFY_FAIL);
    storedInfo.lastJoinLnnTime = 0;
    ret = HbOnlineNodeAuth(&device, &storedInfo, HB_START_DELAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: HbSuspendReAuthTest_01
 * @tc.desc: HbSuspendReAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbSuspendReAuthTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    NodeInfo nodeInfo;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    device.addr[0].type = CONNECTION_ADDR_BLE;
    EXPECT_CALL(hbMediumMock, ConvertBytesToUpperCaseHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    CheckUserIdCheckSumChange(&hbResp, &nodeInfo);
    int32_t ret = HbSuspendReAuth(&device);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);
    hbResp.userIdCheckSum[0] = 11;
    CheckUserIdCheckSumChange(&hbResp, &nodeInfo);
    EXPECT_CALL(hbStrateMock, IsNeedAuthLimit)
        .WillOnce(Return(true))
        .WillRepeatedly(Return(false));
    ret = HbSuspendReAuth(&device);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BLE_CONNECT_SUSPEND);
    nodeInfo.userIdCheckSum[0] = 11;
    CheckUserIdCheckSumChange(&hbResp, &nodeInfo);
    ret = HbSuspendReAuth(&device);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CheckReceiveDeviceInfoTest_01
 * @tc.desc: CheckReceiveDeviceInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, CheckReceiveDeviceInfoTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    LnnHeartbeatRecvInfo storedInfo;
    DeviceInfo device1;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    (void)memset_s(&device1, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    storedInfo.device = &device1;
    int32_t ret = CheckReceiveDeviceInfo(&device, HEARTBEAT_TYPE_BLE_V0, &storedInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_REPEATED);
    device.isOnline = true;
    device.addr[0].type = CONNECTION_ADDR_BLE;
    EXPECT_CALL(hbMediumMock, ConvertBytesToUpperCaseHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbStrateMock, IsNeedAuthLimit).WillRepeatedly(Return(true));
    ret = CheckReceiveDeviceInfo(&device, HEARTBEAT_TYPE_BLE_V0, &storedInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BLE_CONNECT_SUSPEND);
}

/*
 * @tc.name: CheckJoinLnnRequestTest_01
 * @tc.desc: CheckJoinLnnRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, CheckJoinLnnRequestTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    ProcRespVapChange(nullptr, nullptr);
    ProcRespVapChange(&device, nullptr);
    ProcRespVapChange(nullptr, &hbResp);
    uint64_t localFeatureCap = (1 << BIT_SUPPORT_THREE_STATE);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMediumMock, SoftBusGetBrState).WillRepeatedly(Return(BR_DISABLE));
    int32_t ret = CheckJoinLnnRequest(&device, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_JOIN_REQUEST_ERR);
}

/*
 * @tc.name: IsSupportCloudSyncTest_01
 * @tc.desc: IsSupportCloudSync test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsSupportCloudSyncTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    int32_t infoNum = 0;
    NodeBasicInfo *nodeBasicInfo = nullptr;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ProcRespVapChange(&device, &hbResp);
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = IsSupportCloudSync(&device);
    EXPECT_FALSE(ret);
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo));
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ProcRespVapChange(&device, &hbResp);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = IsSupportCloudSync(&device);
    EXPECT_FALSE(ret);
    infoNum = 3;
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ProcRespVapChange(&device, &hbResp);
    EXPECT_CALL(hbMediumMock, IsFeatureSupport).WillRepeatedly(Return(true));
    ret = IsSupportCloudSync(&device);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsDirectlyHeartBeatTest_01
 * @tc.desc: IsDirectlyHeartBeat test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, IsDirectlyHeartBeatTest_01, TestSize.Level1)
{
    DeviceInfo device;
    HbRespData hbResp;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    bool ret = IsDirectlyHeartBeat(nullptr, nullptr);
    EXPECT_FALSE(ret);
    ret = IsDirectlyHeartBeat(nullptr, &hbResp);
    EXPECT_FALSE(ret);
    ret = IsDirectlyHeartBeat(&device, nullptr);
    EXPECT_FALSE(ret);
    hbResp.hbVersion = HB_VERSION_V2;
    ret = IsDirectlyHeartBeat(&device, &hbResp);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: CheckJoinLnnConnectResultTest_01
 * @tc.desc: CheckJoinLnnConnectResult test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, CheckJoinLnnConnectResultTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStategyMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    DeviceInfo device;
    HbRespData hbResp;
    LnnHeartbeatRecvInfo storedInfo;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)memset_s(&hbResp, sizeof(HbRespData), 0, sizeof(HbRespData));
    (void)memset_s(&storedInfo, sizeof(LnnHeartbeatRecvInfo), 0, sizeof(LnnHeartbeatRecvInfo));
    uint64_t localFeatureCap = (1 << BIT_SUPPORT_THREE_STATE);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStategyMock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hbMediumMock, SoftBusGetBrState).WillOnce(Return(BR_DISABLE))
        .WillRepeatedly(Return(BR_ENABLE));
    int32_t ret = CheckJoinLnnConnectResult(&device, &hbResp, false, &storedInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_JOIN_REQUEST_ERR);
    device.isOnline = false;
    EXPECT_CALL(hbMediumMock, IsFeatureSupport).WillRepeatedly(Return(true));
    ret = CheckJoinLnnConnectResult(&device, &hbResp, false, &storedInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_PEER_NODE_CONNECT);
    device.isOnline = true;
    ret = CheckJoinLnnConnectResult(&device, &hbResp, false, &storedInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HEARTBEAT_REPEATED);
}

/*
 * @tc.name: HbMediumMgrRecvHigherWeightStaticTest_01
 * @tc.desc: HbMediumMgrRecvHigherWeight test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbMediumMgrRecvHigherWeightStaticTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    HbMediumMgrRecvLpInfo("networkId", 0);
    int32_t ret = HbMediumMgrRecvProcess(nullptr, nullptr, HEARTBEAT_TYPE_BLE_V0, false, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = HbMediumMgrRecvProcess(&device, nullptr, HEARTBEAT_TYPE_BLE_V0, false, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t infoNum = 1;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbMediumMock, LnnConvAddrTypeToDiscType).WillRepeatedly(Return(DISCOVERY_TYPE_BLE));
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(false));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    char udidhash[HB_SHORT_UDID_HASH_HEX_LEN];
    (void)memset_s(udidhash, HB_SHORT_UDID_HASH_HEX_LEN, 0, HB_SHORT_UDID_HASH_HEX_LEN);
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t weight = 1000;
    ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, false, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR);
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStrateMock, LnnNotifyMasterElect).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, false, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, false, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: HbMediumMgrRecvHigherWeightStaticTest_02
 * @tc.desc: HbMediumMgrRecvHigherWeight test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, HbMediumMgrRecvHigherWeightStaticTest_02, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    int32_t infoNum = 1;
    EXPECT_CALL(hbMediumMock, LnnConvAddrTypeToDiscType).WillRepeatedly(Return(DISCOVERY_TYPE_BLE));
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(false));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    char udidhash[HB_SHORT_UDID_HASH_HEX_LEN];
    (void)memset_s(udidhash, HB_SHORT_UDID_HASH_HEX_LEN, 0, HB_SHORT_UDID_HASH_HEX_LEN);
    char masterUdid[UDID_BUF_LEN];
    masterUdid[0] = 11;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*masterUdid), Return(SOFTBUS_OK)));
    EXPECT_CALL(hbStrateMock, LnnNotifyMasterElect).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    int32_t weight = 1000;
    int32_t ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, false, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, true, false);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOTIFY_MASTER_ELECT_ERR);
    EXPECT_CALL(hbStrateMock, LnnNotifyMasterElect).WillRepeatedly(Return(SOFTBUS_OK));
    nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ret = HbMediumMgrRecvHigherWeight(udidhash, weight, CONNECTION_ADDR_BLE, true, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnHbMediumMgrInitTest_01
 * @tc.desc: LnnHbMediumMgrInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, LnnHbMediumMgrInitTest_01, TestSize.Level1)
{
    NiceMock<HbMediumMgrInterfaceMock> hbMediumMock;
    EXPECT_CALL(hbMediumMock, LnnRegistBleHeartbeatMediumMgr).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    CheckUserIdCheckSumChange(nullptr, nullptr);
    int32_t ret = LnnHbMediumMgrInit();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_MGR_REG_FAIL);
}

/*
 * @tc.name: VisitHbMediumMgrSendBeginTest_01
 * @tc.desc: VisitHbMediumMgrSendBegin test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, VisitHbMediumMgrSendBeginTest_01, TestSize.Level1)
{
    LnnHeartbeatSendBeginData data;
    LnnHeartbeatType typeSet;
    (void)memset_s(&data, sizeof(LnnHeartbeatSendBeginData), 0, sizeof(LnnHeartbeatSendBeginData));
    (void)memset_s(&typeSet, sizeof(LnnHeartbeatType), 0, sizeof(LnnHeartbeatType));
    bool ret = VisitHbMediumMgrSendBegin(&typeSet, HEARTBEAT_TYPE_MAX, &data);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: VisitHbMediumMgrSendEndTest_01
 * @tc.desc: VisitHbMediumMgrSendEnd test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, VisitHbMediumMgrSendEndTest_01, TestSize.Level1)
{
    LnnHeartbeatSendBeginData data;
    LnnHeartbeatType typeSet;
    (void)memset_s(&data, sizeof(LnnHeartbeatSendBeginData), 0, sizeof(LnnHeartbeatSendBeginData));
    (void)memset_s(&typeSet, sizeof(LnnHeartbeatType), 0, sizeof(LnnHeartbeatType));
    bool ret = VisitHbMediumMgrSendEnd(&typeSet, HEARTBEAT_TYPE_MAX, &data);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnHbMediumMgrStopTest_01
 * @tc.desc: LnnHbMediumMgrStop test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, LnnHbMediumMgrStopTest_01, TestSize.Level1)
{
    LnnHeartbeatType type = HEARTBEAT_TYPE_MAX;
    int32_t ret = LnnHbMediumMgrStop(&type);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL);
}

/*
 * @tc.name: VisitRegistHeartbeatMediumMgrTest_01
 * @tc.desc: VisitRegistHeartbeatMediumMgr test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, VisitRegistHeartbeatMediumMgrTest_01, TestSize.Level1)
{
    LnnHeartbeatSendBeginData data;
    LnnHeartbeatType typeSet;
    (void)memset_s(&data, sizeof(LnnHeartbeatSendBeginData), 0, sizeof(LnnHeartbeatSendBeginData));
    (void)memset_s(&typeSet, sizeof(LnnHeartbeatType), 0, sizeof(LnnHeartbeatType));
    bool ret = VisitRegistHeartbeatMediumMgr(&typeSet, HEARTBEAT_TYPE_MAX, &data);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnRegistHeartbeatMediumMgrTest_01
 * @tc.desc: LnnRegistHeartbeatMediumMgr test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumStaticTest, LnnRegistHeartbeatMediumMgrTest_01, TestSize.Level1)
{
    LnnHeartbeatMediumMgr mgr;
    (void)memset_s(&mgr, sizeof(LnnHeartbeatMediumMgr), 0, sizeof(LnnHeartbeatMediumMgr));
    mgr.supportType = HEARTBEAT_TYPE_MAX;
    int32_t ret = LnnRegistHeartbeatMediumMgr(&mgr);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_HB_MGR_REG_FAIL);
    mgr.supportType = HEARTBEAT_TYPE_BLE_V0;
    mgr.init = nullptr;
    ret = LnnRegistHeartbeatMediumMgr(&mgr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
