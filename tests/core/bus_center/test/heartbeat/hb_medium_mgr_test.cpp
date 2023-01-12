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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "distribute_net_ledger_mock.h"
#include "hb_strategy_mock.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_heartbeat_medium_mgr.c"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_ledger_mock.h"
#include "softbus_common.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

#define TEST_WEIGHT         2
#define TEST_DEVID          "5987321652"
#define TEST_NETWORK_ID     "6542316a57d"
#define TEST_WEIGHT2        3
#define TEST_RECVTIME_FIRST 0
#define TEST_RECVTIME_LAST  5
#define TEST_DISC_TYPE      5321
#define TEST_UDID_HASH      "1111222233334444"

class HeartBeatMediumTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatMediumTest::SetUpTestCase()
{
    HbInitRecvList();
}

void HeartBeatMediumTest::TearDownTestCase()
{
    HbDeinitRecvList();
}

void HeartBeatMediumTest::SetUp() { }

void HeartBeatMediumTest::TearDown() { }

int32_t onUpdateSendInfo1(LnnHeartbeatUpdateInfoType type)
{
    return SOFTBUS_OK;
}

int32_t onUpdateSendInfo2(LnnHeartbeatUpdateInfoType type)
{
    return SOFTBUS_ERR;
}

/*
 * @tc.name: HbFirstSaveRecvTime
 * @tc.desc: heart beat first save
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, HbFirstSaveRecvTimeTest_01, TestSize.Level1)
{
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    int32_t weight = TEST_WEIGHT;
    int32_t masterWeight = TEST_WEIGHT2;
    uint64_t recvTime = TEST_RECVTIME_FIRST;
    int32_t ret = HbFirstSaveRecvTime(&device, weight, masterWeight, recvTime);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: RemoveRepeatRecvTime
 * @tc.desc: remove repeat received time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, RemoveRepeatRecvTimeTest_01, TestSize.Level1)
{
    DeviceInfo device1;
    (void)memset_s(&device1, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device1.devId, DISC_MAX_DEVICE_ID_LEN, TEST_DEVID);
    device1.addr->type = CONNECTION_ADDR_BR;
    int32_t weight = TEST_WEIGHT;
    int32_t masterWeight = TEST_WEIGHT2;
    uint64_t recvTime1 = TEST_RECVTIME_FIRST;
    int32_t ret = HbFirstSaveRecvTime(&device1, weight, masterWeight, recvTime1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = HbSaveRecvTimeToRemoveRepeat(&device1, weight, masterWeight, recvTime1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DeviceInfo device2;
    (void)memset_s(&device2, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device2.devId, DISC_MAX_DEVICE_ID_LEN, TEST_DEVID);
    device2.addr->type = CONNECTION_ADDR_WLAN;
    uint64_t recvTime2 = TEST_RECVTIME_LAST;
    ret = HbSaveRecvTimeToRemoveRepeat(&device2, weight, masterWeight, recvTime2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    uint64_t recvTime3 = TEST_RECVTIME_LAST + HB_RECV_INFO_SAVE_LEN;
    ret = HbSaveRecvTimeToRemoveRepeat(&device2, weight, masterWeight, recvTime3);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: IsRepeatedRecvInfo
 * @tc.desc: determine whether the message is repeated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, IsRepeatedRecvInfoTest_01, TestSize.Level1)
{
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device.devId, sizeof(TEST_DEVID), TEST_DEVID);
    device.addr->type = CONNECTION_ADDR_BR;
    int32_t weight = TEST_WEIGHT;
    int32_t masterWeight = TEST_WEIGHT2;
    uint64_t recvTime1 = TEST_RECVTIME_FIRST;
    int32_t ret1 = HbFirstSaveRecvTime(&device, weight, masterWeight, recvTime1);
    EXPECT_TRUE(ret1 == SOFTBUS_OK);
    bool ret2 = HbIsRepeatedRecvInfo(TEST_UDID_HASH, CONNECTION_ADDR_BR, TEST_RECVTIME_FIRST);
    EXPECT_FALSE(ret2);
    ret2 = HbIsRepeatedRecvInfo(TEST_DEVID, CONNECTION_ADDR_BLE, TEST_RECVTIME_LAST);
    EXPECT_FALSE(ret2);
    uint64_t nowTime = TEST_RECVTIME_LAST + HB_RECV_INFO_SAVE_LEN;
    ret2 = HbIsRepeatedRecvInfo(TEST_DEVID, CONNECTION_ADDR_BR, nowTime);
    EXPECT_FALSE(ret2);
}

/*
 * @tc.name: GetOnlineNodeByRecvInfo
 * @tc.desc: get online node by received info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, GetOnlineNodeByRecvInfoTest_01, TestSize.Level1)
{
    NodeInfo nodeInfo = {
        .discoveryType = TEST_DISC_TYPE,
        .deviceInfo.deviceUdid = TEST_UDID_HASH,
    };
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];
    (void)memset_s(udidHash, sizeof(udidHash), 0, sizeof(udidHash));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    ON_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(ledgerMock, LnnGetNodeInfoById).WillByDefault(Return(&nodeInfo));
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    LnnGenerateHexStringHash(
        reinterpret_cast<const unsigned char *>(TEST_UDID_HASH), udidHash, HB_SHORT_UDID_HASH_HEX_LEN);
    auto ret = HbGetOnlineNodeByRecvInfo(udidHash, CONNECTION_ADDR_BR);
    EXPECT_TRUE(ret != nullptr);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ret = HbGetOnlineNodeByRecvInfo(TEST_UDID_HASH, CONNECTION_ADDR_BR);
    EXPECT_TRUE(ret == nullptr);
    EXPECT_CALL(ledgerMock, LnnGetNodeInfoById).WillOnce(Return(nullptr));
    ret = HbGetOnlineNodeByRecvInfo(TEST_UDID_HASH, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == nullptr);
}

/*
 * @tc.name: HbUpdateOfflineTiming
 * @tc.desc: updata offline timing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, HbUpdateOfflineTimingTest_01, TestSize.Level1)
{
    NiceMock<DistributeLedgerInterfaceMock> disLedgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    ON_CALL(disLedgerMock, LnnSetDLHeartbeatTimestamp).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbStrateMock, LnnStopOfflineTimingStrategy).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbStrateMock, LnnStartOfflineTimingStrategy).WillByDefault(Return(SOFTBUS_OK));
    int ret =
        HbUpdateOfflineTimingByRecvInfo(TEST_NETWORK_ID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1, TEST_RECVTIME_LAST);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(disLedgerMock, LnnSetDLHeartbeatTimestamp)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        HbUpdateOfflineTimingByRecvInfo(TEST_NETWORK_ID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1, TEST_RECVTIME_LAST);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(hbStrateMock, LnnStopOfflineTimingStrategy)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        HbUpdateOfflineTimingByRecvInfo(TEST_NETWORK_ID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1, TEST_RECVTIME_LAST);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(hbStrateMock, LnnStartOfflineTimingStrategy)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        HbUpdateOfflineTimingByRecvInfo(TEST_NETWORK_ID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1, TEST_RECVTIME_LAST);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: HbMediumMgrRecvProcess
 * @tc.desc: medium manger received process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, HbMediumMgrRecvProcessTest_01, TestSize.Level1)
{
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<DistributeLedgerInterfaceMock> disLedgerMock;
    NiceMock<HeartBeatStategyInterfaceMock> hbStrateMock;
    NodeInfo nodeInfo = {
        .discoveryType = TEST_DISC_TYPE,
        .deviceInfo.deviceUdid = TEST_UDID_HASH,
    };
    ON_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(ledgerMock, LnnGetNodeInfoById).WillByDefault(Return(&nodeInfo));
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    ON_CALL(hbStrateMock, LnnNotifyDiscoveryDevice).WillByDefault(Return(SOFTBUS_OK));
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];
    LnnGenerateHexStringHash(
        reinterpret_cast<const unsigned char *>(TEST_UDID_HASH), udidHash, HB_SHORT_UDID_HASH_HEX_LEN);
    (void)strcpy_s(device.devId, DISC_MAX_DEVICE_ID_LEN, udidHash);
    device.addr->type = CONNECTION_ADDR_BR;
    device.devType = SMART_PHONE;
    int32_t weight = TEST_WEIGHT;
    int32_t masterWeight = TEST_WEIGHT2;
    int32_t ret1 = HbFirstSaveRecvTime(&device, weight, masterWeight, TEST_RECVTIME_FIRST);
    EXPECT_TRUE(ret1 == SOFTBUS_OK);
    ON_CALL(disLedgerMock, LnnSetDLHeartbeatTimestamp).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbStrateMock, LnnStopOfflineTimingStrategy).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hbStrateMock, LnnStartOfflineTimingStrategy).WillByDefault(Return(SOFTBUS_OK));
    int ret = HbMediumMgrRecvProcess(&device, weight, masterWeight, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    HbFirstSaveRecvTime(&device, weight, masterWeight, TEST_RECVTIME_FIRST);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = HbMediumMgrRecvProcess(&device, weight, masterWeight, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret != SOFTBUS_ERR);
    ret = HbMediumMgrRecvProcess(nullptr, weight, masterWeight, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    ret = HbMediumMgrRecvProcess(&device, weight, masterWeight, HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_NODE_OFFLINE);
}

/*
 * @tc.name: HbMediumMgrRecvHigherWeight
 * @tc.desc: after receive highter weight data process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, HbMediumMgrRecvHigherWeightTest_01, TestSize.Level1)
{
    NiceMock<HeartBeatStategyInterfaceMock> hbStrategyMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NodeInfo nodeInfo = {
        .discoveryType = TEST_DISC_TYPE,
        .deviceInfo.deviceUdid = TEST_UDID_HASH,
    };
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];
    (void)memset_s(udidHash, sizeof(udidHash), 0, sizeof(udidHash));
    ON_CALL(hbStrategyMock, LnnNotifyMasterElect).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(ledgerMock, LnnGetNodeInfoById).WillByDefault(Return(&nodeInfo));
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    ON_CALL(ledgerMock, LnnGetLocalStrInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo);
    EXPECT_CALL(hbStrategyMock, LnnSetHbAsMasterNodeState).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnConvertIdToDeviceType).WillRepeatedly(Return(const_cast<char *>(TYPE_PAD)));
    LnnGenerateHexStringHash(
        reinterpret_cast<const unsigned char *>(TEST_UDID_HASH), udidHash, HB_SHORT_UDID_HASH_HEX_LEN);
    int32_t ret = HbMediumMgrRecvHigherWeight(udidHash, TEST_WEIGHT, CONNECTION_ADDR_BR, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ret = HbMediumMgrRecvHigherWeight(udidHash, TEST_WEIGHT, CONNECTION_ADDR_BR, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = HbMediumMgrRecvHigherWeight(nullptr, TEST_WEIGHT, CONNECTION_ADDR_BR, true);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(hbStrategyMock, LnnNotifyMasterElect).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = HbMediumMgrRecvHigherWeight(udidHash, TEST_WEIGHT, CONNECTION_ADDR_BR, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(50);
}

/*
 * @tc.name: HbMediumMgrRelayProcess
 * @tc.desc: receive relay data process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, HbMediumMgrRelayProcess, TestSize.Level1)
{
    HeartBeatStategyInterfaceMock hbStrategyMock;
    EXPECT_CALL(hbStrategyMock, LnnStartHbByTypeAndStrategy)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    HbMediumMgrRelayProcess(TEST_DEVID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1);
    HbMediumMgrRelayProcess(TEST_DEVID, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1);
    HbMediumMgrRelayProcess(nullptr, CONNECTION_ADDR_BR, HEARTBEAT_TYPE_BLE_V1);
}

/*
 * @tc.name: LnnDumpHbMgrRecvList
 * @tc.desc: dump hearbeat manger received list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, LnnDumpHbMgrRecvList_TEST01, TestSize.Level1)
{
    DeviceInfo device1;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertIdToDeviceType)
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Return(const_cast<char *>(TYPE_PAD)));
    (void)memset_s(&device1, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device1.devId, DISC_MAX_DEVICE_ID_LEN, TEST_DEVID);
    device1.addr->type = CONNECTION_ADDR_BR;
    int32_t weight = TEST_WEIGHT;
    int32_t masterWeight = TEST_WEIGHT2;
    uint64_t recvTime1 = TEST_RECVTIME_FIRST;
    int32_t ret = HbFirstSaveRecvTime(&device1, weight, masterWeight, recvTime1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DeviceInfo device2;
    (void)memset_s(&device2, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device1.devId, DISC_MAX_DEVICE_ID_LEN, TEST_NETWORK_ID);
    device2.addr->type = CONNECTION_ADDR_MAX;
    ret = HbFirstSaveRecvTime(&device2, weight, masterWeight, TEST_RECVTIME_LAST);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDumpHbMgrRecvList();
    SoftBusSleepMs(50);
}

/*
 * @tc.name: LnnDumpHbOnlineNodeList
 * @tc.desc: dump heartbeat online nodelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, LnnDumpHbOnlineNodeList_TEST01, TestSize.Level1)
{
    NodeInfo nodeInfo = {
        .discoveryType = TEST_DISC_TYPE,
        .deviceInfo.deviceUdid = TEST_UDID_HASH,
    };
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<DistributeLedgerInterfaceMock> distrLedgerMock;
    ON_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(ledgerMock, LnnGetNodeInfoById).WillByDefault(Return(&nodeInfo));
    ON_CALL(distrLedgerMock, LnnGetDLHeartbeatTimestamp).WillByDefault(Return(SOFTBUS_OK));
    LnnDumpHbOnlineNodeList();
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    LnnDumpHbOnlineNodeList();
    LnnDumpHbOnlineNodeList();
    EXPECT_CALL(distrLedgerMock, LnnGetDLHeartbeatTimestamp)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnDumpHbOnlineNodeList();
}

/*
 * @tc.name: VisitHbMediumMgrSendBegin
 * @tc.desc: visit heartbeat medium manger send begin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, VisitHbMediumMgrSendBegin_TEST01, TestSize.Level1)
{
    bool ret = VisitHbMediumMgrSendBegin(nullptr, HEARTBEAT_TYPE_MAX, nullptr);
    EXPECT_FALSE(ret);
    LnnHeartbeatCustSendData data = {
        .hbType = HEARTBEAT_TYPE_BLE_V1,
        .wakeupFlag = false,
        .isRelay = false,
    };
    ret = VisitHbMediumMgrSendBegin(nullptr, HEARTBEAT_TYPE_MAX, nullptr);
    EXPECT_FALSE(ret);
    LnnHbMediumMgrInit();
    ret = VisitHbMediumMgrSendBegin(nullptr, HEARTBEAT_TYPE_BLE_V0, reinterpret_cast<void *>(&data));
    EXPECT_FALSE(ret);
    int id = LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V0);
    g_hbMeidumMgr[id] = nullptr;
    ret = VisitHbMediumMgrSendBegin(nullptr, HEARTBEAT_TYPE_BLE_V0, reinterpret_cast<void *>(&data));
    EXPECT_TRUE(ret);
    LnnHbMediumMgrInit();
    g_hbMeidumMgr[id]->onSendOneHbBegin = nullptr;
    ret = VisitHbMediumMgrSendBegin(nullptr, HEARTBEAT_TYPE_BLE_V0, reinterpret_cast<void *>(&data));
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LnnHbMediumMgrSendBegin
 * @tc.desc: heartbeat medium manger send begin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, LnnHbMediumMgrSendBegin_TEST01, TestSize.Level1)
{
    LnnHeartbeatCustSendData data = {
        .hbType = HEARTBEAT_TYPE_MAX,
        .wakeupFlag = false,
        .isRelay = false,
    };
    LnnHbMediumMgrInit();
    int32_t ret = LnnHbMediumMgrSendBegin(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnHbMediumMgrSendBegin(&data);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: VisitHbMediumMgrSendEnd
 * @tc.desc: visit heartbeat medium manger send end
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, VisitHbMediumMgrSendEnd_TEST01, TestSize.Level1)
{
    bool ret = VisitHbMediumMgrSendEnd(nullptr, HEARTBEAT_TYPE_MAX, nullptr);
    EXPECT_FALSE(ret);
    LnnHbMediumMgrInit();
    int id = LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V0);
    g_hbMeidumMgr[id] = nullptr;
    ret = VisitHbMediumMgrSendEnd(nullptr, HEARTBEAT_TYPE_BLE_V0, nullptr);
    EXPECT_TRUE(ret);
    LnnHbMediumMgrInit();
    g_hbMeidumMgr[id]->onSendOneHbEnd = nullptr;
    ret = VisitHbMediumMgrSendEnd(nullptr, HEARTBEAT_TYPE_BLE_V0, nullptr);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: VisitHbMediumMgrStop
 * @tc.desc: visit heartbeat medium manger stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, VisitHbMediumMgrStop_TEST01, TestSize.Level1)
{
    LnnHeartbeatMediumMgr medMgr1 = {
        .supportType = HEARTBEAT_TYPE_BLE_V1,
    };
    bool ret = VisitHbMediumMgrStop(nullptr, HEARTBEAT_TYPE_MAX, nullptr);
    EXPECT_FALSE(ret);
    int id = LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V1);
    g_hbMeidumMgr[id] = nullptr;
    ret = VisitHbMediumMgrStop(nullptr, HEARTBEAT_TYPE_BLE_V1, nullptr);
    EXPECT_TRUE(ret);
    g_hbMeidumMgr[id] = &medMgr1;
    ret = VisitHbMediumMgrStop(nullptr, HEARTBEAT_TYPE_BLE_V1, nullptr);
    EXPECT_TRUE(ret);
    LnnHeartbeatMediumMgr medMgr2 = {
        .supportType = HEARTBEAT_TYPE_MAX,
    };
    g_hbMeidumMgr[id] = &medMgr2;
    ret = VisitHbMediumMgrStop(nullptr, HEARTBEAT_TYPE_BLE_V1, nullptr);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LnnHbMediumMgrSetParam
 * @tc.desc: heartbeat medium manger set param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, LnnHbMediumMgrSetParam_TEST01, TestSize.Level1)
{
    int id = LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V1);
    int32_t ret = LnnHbMediumMgrSetParam(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnHeartbeatMediumParam param = {
        .type = HEARTBEAT_TYPE_MAX,
    };
    ret = LnnHbMediumMgrSetParam(&param);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    param.type = HEARTBEAT_TYPE_BLE_V1;
    g_hbMeidumMgr[id] = nullptr;
    ret = LnnHbMediumMgrSetParam(&param);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LnnHbMediumMgrUpdateSendInfo
 * @tc.desc: medium manger updata send info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, LnnHbMediumMgrUpdateSendInfo_TEST01, TestSize.Level1)
{
    int id = LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V1);
    int32_t ret = LnnHbMediumMgrUpdateSendInfo(UPDATE_HB_NETWORK_INFO);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    LnnHeartbeatMediumMgr medMgr1 = {
        .supportType = HEARTBEAT_TYPE_BLE_V1,
    };
    g_hbMeidumMgr[id] = &medMgr1;
    ret = LnnHbMediumMgrUpdateSendInfo(UPDATE_HB_NETWORK_INFO);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    LnnHeartbeatMediumMgr medMgr2 = {
        .supportType = HEARTBEAT_TYPE_BLE_V1,
        .onUpdateSendInfo = onUpdateSendInfo1,
    };
    g_hbMeidumMgr[id] = &medMgr2;
    ret = LnnHbMediumMgrUpdateSendInfo(UPDATE_HB_NETWORK_INFO);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    medMgr2.onUpdateSendInfo = onUpdateSendInfo2;
    ret = LnnHbMediumMgrUpdateSendInfo(UPDATE_HB_NETWORK_INFO);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnRegistHeartbeatMediumMgr(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: VisitUnRegistHeartbeatMediumMgr
 * @tc.desc: unregist heartbeat medium manger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, VisitUnRegistHeartbeatMediumMgr_TEST01, TestSize.Level1)
{
    bool ret = VisitUnRegistHeartbeatMediumMgr(nullptr, HEARTBEAT_TYPE_BLE_V1, nullptr);
    EXPECT_TRUE(ret);
    ret = VisitUnRegistHeartbeatMediumMgr(nullptr, HEARTBEAT_TYPE_MAX, nullptr);
    EXPECT_FALSE(ret);
}

void DeInit(void) { }
/*
 * @tc.name: LnnUnRegistHeartbeatMediumMgr
 * @tc.desc: unregist heartbeat medium manger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatMediumTest, UnRegistHeartbeatMediumMgr_TEST01, TestSize.Level1)
{
    int32_t ret = LnnUnRegistHeartbeatMediumMgr(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnHeartbeatMediumMgr mgr = {
        .supportType = HEARTBEAT_TYPE_BLE_V1,
        .deinit = DeInit,
    };
    ret = LnnUnRegistHeartbeatMediumMgr(&mgr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    mgr.supportType = HEARTBEAT_TYPE_MAX;
    ret = LnnUnRegistHeartbeatMediumMgr(&mgr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    mgr.supportType = HEARTBEAT_TYPE_BLE_V1;
    mgr.deinit = nullptr;
    ret = LnnUnRegistHeartbeatMediumMgr(&mgr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS