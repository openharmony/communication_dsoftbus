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
#include "securec.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "disc_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_mock.h"
#include "softbus_broadcast_utils.h"
#include "softbus_error_code.h"
#include "softbus_broadcast_mgr_mock.h"

using namespace testing::ext;
using ::testing::Return;
using namespace testing;

#define BC_ADV_FLAG             0x2
#define BC_ADV_TX_POWER_DEFAULT (-6)
#define BC_CHANNLE_MAP          0x0
#define BC_INTERNAL             48
#define MANUFACTURE_COMPANY_ID  0x027D
#define SERVICE_UUID            0xFDEE
#define SRV_TYPE_INVALID        (-1)

namespace OHOS {
const uint8_t *BASE_FUZZ_DATA = nullptr;
size_t g_baseFuzzPos;
size_t g_baseFuzzSize = 0;
const int32_t listenderId = 15;

class SoftbusBroadcastMgrTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        LooperInit();
    }

    static void TearDownTestCase()
    {
        LooperDeinit();
    }

    void SetUp() override { }
    void TearDown() override { }

    static inline uint8_t BC_DATA_PAYLOAD[] = { 0x04, 0x05, 0x90, 0x00, 0x00, 0x10, 0x00, 0x18, 0xB9, 0x13, 0x3D, 0x28,
        0xFC, 0x0D, 0x7F, 0xAB, 0x21, 0x00, 0x30, 0x4F, 0x70, 0x65, 0x6E, 0x48 };
    static inline uint8_t RSP_DATA_PAYLOAD[] = { 0x61, 0x72, 0x6D, 0x6F, 0x6E, 0x79, 0x20, 0x33, 0x2E, 0x32, 0x00 };
};

static void ActionOfSoftbusBleAdapterInitNull()
{
    DISC_LOGI(DISC_TEST, "enter");
    static SoftbusBroadcastMediumInterface interface = {};
    if (RegisterBroadcastMediumFunction(BROADCAST_PROTOCOL_BLE, &interface) != 0) {
        DISC_LOGE(DISC_TEST, "Register gatt interface failed.");
    }
}

static void BuildBroadcastParam(BroadcastParam *bcParam)
{
    bcParam->minInterval = BC_INTERNAL;
    bcParam->maxInterval = BC_INTERNAL;
    bcParam->advType = SOFTBUS_BC_ADV_IND;
    bcParam->ownAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    bcParam->peerAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    bcParam->channelMap = BC_CHANNLE_MAP;
    bcParam->txPower = BC_ADV_TX_POWER_DEFAULT;
}

static void BuildBroadcastPacketExceptPayload(BroadcastPacket *packet)
{
    packet->bcData.type = BC_DATA_TYPE_SERVICE;
    packet->bcData.id = SERVICE_UUID;
    packet->rspData.type = BC_DATA_TYPE_MANUFACTURER;
    packet->rspData.id = MANUFACTURE_COMPANY_ID;
    packet->isSupportFlag = true;
    packet->flag = BC_ADV_FLAG;
}

static void BuildScanParam(BcScanParams *scanParam)
{
    scanParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
    scanParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    scanParam->scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE;
    scanParam->scanPhy = SOFTBUS_BC_SCAN_PHY_1M;
    scanParam->scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL;
}

static void ConvertBcParams(const BroadcastParam *srcParam, SoftbusBroadcastParam *dstParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter covert bc param");
    dstParam->minInterval = srcParam->minInterval;
    dstParam->maxInterval = srcParam->maxInterval;
    dstParam->advType = srcParam->advType;
    dstParam->advFilterPolicy = srcParam->advFilterPolicy;
    dstParam->ownAddrType = srcParam->ownAddrType;
    dstParam->peerAddrType = srcParam->peerAddrType;
    if (memcpy_s(dstParam->peerAddr.addr, SOFTBUS_ADDR_MAC_LEN, srcParam->peerAddr.addr, BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy peerAddr failed");
        return;
    }
    dstParam->channelMap = srcParam->channelMap;
    dstParam->duration = srcParam->duration;
    dstParam->txPower = srcParam->txPower;
    dstParam->isSupportRpa = srcParam->isSupportRpa;
    if (memcpy_s(dstParam->ownIrk, SOFTBUS_IRK_LEN, srcParam->ownIrk, BC_IRK_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy ownIrk failed");
        return;
    }
    if (memcpy_s(dstParam->ownUdidHash, SOFTBUS_UDID_HASH_LEN, srcParam->ownUdidHash, BC_UDID_HASH_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy ownUdidHash failed");
        return;
    }
    if (memcpy_s(dstParam->localAddr.addr, BC_ADDR_MAC_LEN, srcParam->localAddr.addr,
        BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy localAddr failed");
        return;
    }
}

template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (BASE_FUZZ_DATA == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, BASE_FUZZ_DATA + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

static LpScanParam BuildLpScanParam()
{
    LpScanParam lpScanParam;
    g_baseFuzzPos = 0;
    BcScanParams scanParam;
    scanParam.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
    scanParam.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    scanParam.scanType = GetData<bool>();
    scanParam.scanPhy = GetData<uint8_t>() % SOFTBUS_BC_SCAN_PHY_CODED;
    scanParam.scanFilterPolicy = GetData<uint8_t>() % SOFTBUS_BC_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA;
    lpScanParam.scanParam = scanParam;

    return lpScanParam;
}

static int32_t BuildLpBroadcastParam(LpBroadcastParam *lpBcParam)
{
    g_baseFuzzPos = 0;
    lpBcParam->bcHandle = GetData<int32_t>();
    BuildBroadcastParam(&lpBcParam->bcParam);
    BuildBroadcastPacketExceptPayload(&lpBcParam->packet);
    lpBcParam->packet.bcData.payloadLen = sizeof(SoftbusBroadcastMgrTest::BC_DATA_PAYLOAD);
    lpBcParam->packet.bcData.payload = SoftbusBroadcastMgrTest::BC_DATA_PAYLOAD;
    lpBcParam->packet.rspData.payloadLen = sizeof(SoftbusBroadcastMgrTest::RSP_DATA_PAYLOAD);
    lpBcParam->packet.rspData.payload = SoftbusBroadcastMgrTest::RSP_DATA_PAYLOAD;
    return SOFTBUS_OK;
}

// filter is released in UnRegisterScanListener
static BcScanFilter *GetBcScanFilter(void)
{
    unsigned char serviceData[] = { 0x04, 0x05, 0x90 };
    unsigned char serviceDataMask[] = { 0xFF, 0xFF, 0xFF };
    int32_t serviceDataLength = sizeof(serviceData);

    BcScanFilter *filter = static_cast<BcScanFilter *>(SoftBusCalloc(sizeof(BcScanFilter)));
    DISC_CHECK_AND_RETURN_RET_LOGW(filter != nullptr, nullptr, DISC_TEST, "malloc filter failed");

    unsigned char *data = static_cast<unsigned char *>(SoftBusCalloc(serviceDataLength));
    unsigned char *mask = static_cast<unsigned char *>(SoftBusCalloc(serviceDataLength));
    if (data == nullptr || mask == nullptr) {
        goto EXIT;
    }
    if (memcpy_s(data, serviceDataLength, serviceData, serviceDataLength) != EOK) {
        goto EXIT;
    }
    if (memcpy_s(mask, serviceDataLength, serviceDataMask, serviceDataLength) != EOK) {
        goto EXIT;
    }

    filter->serviceId = SERVICE_UUID;
    filter->serviceData = data;
    filter->serviceDataMask = mask;
    filter->serviceDataLength = serviceDataLength;
    return filter;
EXIT:
    SoftBusFree(filter);
    SoftBusFree(data);
    SoftBusFree(mask);
    return nullptr;
}

static void BleBcEnableCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BleBcDisableCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BleBcUpdateCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BleBcDataCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BcSetBroadcastingParamCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BcDisableBroadcastingCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BcEnableBroadcastingCallback(int32_t channel, int32_t status)
{
    DISC_LOGI(DISC_TEST, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BleOnScanStart(int32_t listenerId, int32_t status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGI(DISC_TEST, "BleOnScanStart");
}

static void BleOnScanStop(int32_t listenerId, int32_t status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGI(DISC_TEST, "BleOnScanStop");
}

static void BleScanResultCallback(int32_t listenerId, const BroadcastReportInfo *reportInfo)
{
    (void)listenerId;
}

static BroadcastCallback *GetBroadcastCallback()
{
    static BroadcastCallback g_bcCallback = {
        .OnStartBroadcastingCallback = BleBcEnableCallback,
        .OnStopBroadcastingCallback = BleBcDisableCallback,
        .OnUpdateBroadcastingCallback = BleBcUpdateCallback,
        .OnSetBroadcastingCallback = BleBcDataCallback,
        .OnSetBroadcastingParamCallback = BcSetBroadcastingParamCallback,
        .OnDisableBroadcastingCallback = BcDisableBroadcastingCallback,
        .OnEnableBroadcastingCallback = BcEnableBroadcastingCallback,
    };
    return &g_bcCallback;
}

static ScanCallback *GetScanCallback()
{
    static ScanCallback g_scanListener = {
        .OnStartScanCallback = BleOnScanStart,
        .OnStopScanCallback = BleOnScanStop,
        .OnReportScanDataCallback = BleScanResultCallback,
    };
    return &g_scanListener;
}

/*
 * @tc.name: SoftbusBroadcastMgrInit001
 * @tc.desc: Init successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastMgrInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastMgrInit002
 * @tc.desc: Repeated initializations successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastMgrInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastMgrInit003
 * @tc.desc: Init successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastMgrInit003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit003 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, BleAsyncCallbackDelayHelper)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrInit003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastMgrDeInit001
 * @tc.desc: Repeated deinitializations successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastMgrDeInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrDeInit001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrDeInit001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastMgrDeInit002
 * @tc.desc: Deinit without initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastMgrDeInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrDeInit002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastMgrDeInit002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastInterface001
 * @tc.desc: Calls the interfaces without initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastInterface001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastInterface001 begin ----");
    ManagerMock managerMock;

    int32_t bcId = -1;
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_NO_FUNC_REGISTERED, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_EQ(SOFTBUS_LOCK_ERR, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_BC_MGR_NO_FUNC_REGISTERED, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_LOCK_ERR, UnRegisterScanListener(listenerId));

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_LOCK_ERR, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_LOCK_ERR, SetBroadcastingData(bcId, &packet));
    EXPECT_EQ(SOFTBUS_LOCK_ERR, StopBroadcasting(bcId));

    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_LOCK_ERR, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_LOCK_ERR, StopScan(listenerId));
    EXPECT_FALSE(BroadcastIsLpDeviceAvailable());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastInterface001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastInterface002
 * @tc.desc: Calls the interface when the function registered is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastInterface002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastInterface002 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftbusBleAdapterInit).WillRepeatedly(ActionOfSoftbusBleAdapterInitNull);

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_FUNC_NULL, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_BC_MGR_FUNC_NULL, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterScanListener(listenerId));

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingData(bcId, &packet));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StopBroadcasting(bcId));

    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StopScan(listenerId));
    EXPECT_FALSE(BroadcastIsLpDeviceAvailable());

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastInterface002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterBroadcaster001
 * @tc.desc: Invalid parameter, register broadcaster fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterBroadcaster001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_SRV, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        static_cast<BaseServiceType>(SRV_TYPE_INVALID), &bcId, GetBroadcastCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, nullptr, GetBroadcastCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, nullptr));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterBroadcaster002
 * @tc.desc: Register broadcaster and unregister broadcaster success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterBroadcaster002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterBroadcaster003
 * @tc.desc: Duplicate registration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterBroadcaster003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId[BC_NUM_MAX + 1] = { -1 };
    for (int32_t i = 0; i < BC_NUM_MAX; i++) {
        EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
            SRV_TYPE_DIS, &bcId[i], GetBroadcastCallback()));
        EXPECT_TRUE(bcId[i] >= 0);
    }

    EXPECT_EQ(SOFTBUS_BC_MGR_REG_NO_AVAILABLE_BC_ID,
        RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId[BC_NUM_MAX], GetBroadcastCallback()));

    for (int32_t i = 0; i < BC_NUM_MAX; i++) {
        EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId[i]));
    }

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterBroadcaster003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUnRegisterBroadcaster001
 * @tc.desc: Unregister without registration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUnRegisterBroadcaster001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterBroadcaster001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t invalidId = -1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterBroadcaster(invalidId));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterBroadcaster(BC_NUM_MAX));
    invalidId = 1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterBroadcaster(invalidId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterBroadcaster001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUnRegisterBroadcaster002
 * @tc.desc: Unregister when broadcasting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUnRegisterBroadcaster002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterBroadcaster002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;
    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterBroadcaster002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterScanListener001
 * @tc.desc: Invalid parameter, register listener fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterScanListener001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_SRV, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        static_cast<BaseServiceType>(SRV_TYPE_INVALID), &listenerId, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, nullptr, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, RegisterScanListener(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &listenerId, nullptr));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterScanListener002
 * @tc.desc: Register listener and unregister listener success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterScanListener002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastRegisterScanListener003
 * @tc.desc: Duplicate registration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastRegisterScanListener003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);
    EXPECT_EQ(SOFTBUS_BC_MGR_REG_DUP, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_LP_BURST, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);
    EXPECT_EQ(SOFTBUS_BC_MGR_REG_DUP, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_LP_BURST, &listenerId, GetScanCallback()));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastRegisterScanListener003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUnRegisterScanListener001
 * @tc.desc: Unregister without registration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUnRegisterScanListener001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterScanListener001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t invalidId = -1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterScanListener(invalidId));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterScanListener(SCAN_NUM_MAX));
    invalidId = 0;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterScanListener(invalidId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterScanListener001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUnRegisterScanListener002
 * @tc.desc: Unregister when scanning
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUnRegisterScanListener002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterScanListener002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, StartScan(listenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUnRegisterScanListener002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartBroadcasting001
 * @tc.desc: Invalid parameter, start broadcasting fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartBroadcasting001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBroadcasting(bcId, nullptr, &packet));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBroadcasting(bcId, &bcParam, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBroadcasting(bcId, &bcParam, &packet));

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;
    int32_t invalidBcId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StartBroadcasting(invalidBcId, &bcParam, &packet));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartBroadcasting002
 * @tc.desc: Start broadcasting and stop broadcasting success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartBroadcasting002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, StopBroadcasting(bcId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartBroadcasting003
 * @tc.desc: Duplicate start broadcasting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartBroadcasting003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, StopBroadcasting(bcId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartBroadcasting003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUpdateBroadcasting001
 * @tc.desc: Invalid parameter, update broadcasting fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUpdateBroadcasting001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUpdateBroadcasting001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateBroadcasting(bcId, nullptr, &packet));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateBroadcasting(bcId, &bcParam, nullptr));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUpdateBroadcasting001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastUpdateBroadcasting002
 * @tc.desc: Update broadcasting success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastUpdateBroadcasting002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUpdateBroadcasting002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, UpdateBroadcasting(bcId, &bcParam, &packet));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastUpdateBroadcasting002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetBroadcastingData001
 * @tc.desc: Invalid parameter, set broadcasting data fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetBroadcastingData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t invalidId = -1;
    BroadcastPacket packet = {};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetBroadcastingData(invalidId, nullptr));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingData(invalidId, &packet));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingData(BC_NUM_MAX, &packet));
    invalidId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingData(invalidId, &packet));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetBroadcastingData002
 * @tc.desc: Set broadcasting data without start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetBroadcastingData002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastPacket packet = {};
    EXPECT_EQ(SOFTBUS_BC_MGR_NOT_BROADCASTING, SetBroadcastingData(bcId, &packet));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetBroadcastingData003
 * @tc.desc: Set broadcasting data success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetBroadcastingData003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, SetBroadcastingData(bcId, &packet));
    EXPECT_EQ(SOFTBUS_OK, StopBroadcasting(bcId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingData003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetBroadcastingParam001
 * @tc.desc: Invalid parameter, set broadcasting param fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetBroadcastingParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingParam001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t invalidId = -1;
    BroadcastParam param = {};

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetBroadcastingParam(invalidId, nullptr));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingParam(invalidId, &param));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingParam(BC_NUM_MAX, &param));
    invalidId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, SetBroadcastingParam(invalidId, &param));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingParam001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetBroadcastingParam002
 * @tc.desc: Set broadcasting param without start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetBroadcastingParam002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingParam002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    BroadcastParam param = {};
    EXPECT_EQ(SOFTBUS_BC_MGR_NOT_BROADCASTING, SetBroadcastingParam(bcId, &param));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetBroadcastingParam002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStopBroadcasting001
 * @tc.desc: Invalid parameter, stop broadcasting fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStopBroadcasting001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopBroadcasting001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t invalidId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StopBroadcasting(invalidId));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StopBroadcasting(BC_NUM_MAX));
    invalidId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, StopBroadcasting(invalidId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopBroadcasting001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStopBroadcasting002
 * @tc.desc: Stop broadcasting without start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStopBroadcasting002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopBroadcasting002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_OK, StopBroadcasting(bcId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopBroadcasting002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetScanFilter001
 * @tc.desc: Invalid parameter, set filter fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetScanFilter001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 0;
    BcScanFilter filter = {};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetScanFilter(listenerId, &filter, filterNum));

    filterNum = 1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetScanFilter(listenerId, nullptr, filterNum));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, SetScanFilter(listenerId, &filter, filterNum));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, SetScanFilter(SCAN_NUM_MAX, &filter, filterNum));
    listenerId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, SetScanFilter(listenerId, &filter, filterNum));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetScanFilter001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastSetScanFilter002
 * @tc.desc: Set filter success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastSetScanFilter002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetScanFilter002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastSetScanFilter002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan001
 * @tc.desc: Invalid parameter, start scan fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StartScan(listenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartScan(listenerId, nullptr));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan002
 * @tc.desc: Start scan without filter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);
    int32_t ret = StartScan(listenerId, &scanParam);
    EXPECT_EQ(ret == SOFTBUS_INVALID_PARAM || ret == SOFTBUS_BC_MGR_START_SCAN_NO_FILTER, true);

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan003
 * @tc.desc: Start scan and stop scan success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_OK, StopScan(listenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan004
 * @tc.desc: Duplicate start scan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan004 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftbusBleAdapterInit).WillRepeatedly(ActionOfSoftbusBleAdapterInitNull);

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_BC_MGR_FUNC_NULL, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StopScan(listenerId));

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan004 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan005
 * @tc.desc: freq is SCAN_FREQ_P2_30_1500
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan005, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan005 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);
    // SCAN_FREQ_P2_30_1500
    scanParam.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2_FAST;
    scanParam.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2_FAST;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_OK, StopScan(listenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan005 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStartScan006
 * @tc.desc: freq is SCAN_FREQ_LOW_POWER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStartScan006, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan006 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);
    // SCAN_FREQ_LOW_POWER
    scanParam.scanInterval = 0;
    scanParam.scanWindow = 0;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, StartScan(listenerId, &scanParam));
    EXPECT_EQ(SOFTBUS_OK, StopScan(listenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStartScan006 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStopScan001
 * @tc.desc: Invalid parameter, stop scan fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStopScan001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopScan001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t invalidId = -1;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StopScan(invalidId));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StopScan(SCAN_NUM_MAX));
    invalidId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, StopScan(invalidId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopScan001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastStopScan002
 * @tc.desc: Stop scan without start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastStopScan002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopScan002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);
    EXPECT_EQ(SOFTBUS_OK, StopScan(listenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastStopScan002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest001
 * @tc.desc: Scanner start scan success when new listenerId is added
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    int32_t connListenerId = -1;
    int32_t lpListenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *discFilter = GetBcScanFilter();
    BcScanFilter *connFilter = GetBcScanFilter();
    BcScanFilter *lpFilter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_CONN, &connListenerId, GetScanCallback()));
    EXPECT_TRUE(connListenerId >= 0);
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_LP_HB, &lpListenerId, GetScanCallback()));
    EXPECT_TRUE(lpListenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, discFilter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(connListenerId, connFilter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(lpListenerId, lpFilter, filterNum));

    // First call, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Scanning, new listenerId is added, stop and start.
    EXPECT_EQ(SOFTBUS_OK, StartScan(connListenerId, &scanParam));
    // Another scanner, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(lpListenerId, &scanParam));

    // Another listenerId is scanning, stop and start.
    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));
    // Stop scan.
    EXPECT_EQ(SOFTBUS_OK, StopScan(connListenerId));
    // Another scanner, stop scan.
    EXPECT_EQ(SOFTBUS_OK, StopScan(lpListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(connListenerId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(lpListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest001 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest002
 * @tc.desc: Two Scanner stop and start success without interfering with each other
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    int32_t connListenerId = -1;
    int32_t lpListenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *discFilter = GetBcScanFilter();
    BcScanFilter *connFilter = GetBcScanFilter();
    BcScanFilter *lpFilter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_CONN, &connListenerId, GetScanCallback()));
    EXPECT_TRUE(connListenerId >= 0);
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_LP_HB, &lpListenerId, GetScanCallback()));
    EXPECT_TRUE(lpListenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, discFilter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(connListenerId, connFilter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(lpListenerId, lpFilter, filterNum));

    // First call, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Scanning, new listenerId is added, stop and start.
    EXPECT_EQ(SOFTBUS_OK, StartScan(connListenerId, &scanParam));
    // A listenerId is removed, stop and start.
    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));
    // Another scanner, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(lpListenerId, &scanParam));
    // Scanning, new listenerId is added, stop and start.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));
    EXPECT_EQ(SOFTBUS_OK, StopScan(connListenerId));
    EXPECT_EQ(SOFTBUS_OK, StopScan(lpListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(connListenerId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(lpListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest002 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest003
 * @tc.desc: Scanner start scan success when updating frequency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *discFilter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, discFilter, filterNum));

    // First call, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Scanning, update frequency, stop and start
    scanParam.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10;
    scanParam.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10;
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest003 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest004
 * @tc.desc: Scanner start scan success when setting a new filter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest004 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *discFilter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, discFilter, filterNum));

    // First call, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Scanning, set a new filter, stop and start.
    // Last filter is released in SetScanFilter.
    BcScanFilter *newFilter = GetBcScanFilter();
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, newFilter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest004 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest005
 * @tc.desc: Scanner not start scan with same params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest005, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest005 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *discFilter = GetBcScanFilter();
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, discFilter, filterNum));

    // First call, start scan.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Scanning, not start with same params.
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest005 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest006
 * @tc.desc: StartScan -> StartScanStub -> CheckChannelScan addSize == deleteSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest006, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest006 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    uint8_t filterNum = 2;

    BcScanFilter *firstDiscFilter = (BcScanFilter *)SoftBusCalloc(sizeof(BcScanFilter) * filterNum);
    firstDiscFilter[0] = *GetBcScanFilter();
    firstDiscFilter[1] = *GetBcScanFilter();
    unsigned char serviceData1[] = { 0x06, 0x05, 0x90 };
    EXPECT_EQ(EOK, memcpy_s(firstDiscFilter[1].serviceData, sizeof(serviceData1), serviceData1, sizeof(serviceData1)));

    BcScanFilter *secondDiscFilter = (BcScanFilter *)SoftBusCalloc(sizeof(BcScanFilter) * filterNum);
    secondDiscFilter[0] = *GetBcScanFilter();
    secondDiscFilter[1] = *GetBcScanFilter();
    unsigned char serviceData2[] = { 0x05, 0x05, 0x90 };
    EXPECT_EQ(EOK, memcpy_s(secondDiscFilter[1].serviceData, sizeof(serviceData2), serviceData2, sizeof(serviceData2)));

    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);
    // First SetScanFilter call
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, firstDiscFilter, filterNum));
    // First StartScan call, set isScanning = true, isFliterChanged = false
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Second SetScanFilter call, must be different filter, set isScanning = true, isFliterChanged = true
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, secondDiscFilter, filterNum));
    // Second StartScan
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest006 end ----");
}

/*
 * @tc.name: SoftbusBroadcastScannerTest007
 * @tc.desc: StartScan -> StartScanStub -> CheckChannelScan -> CheckNotScaning
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, SoftbusBroadcastScannerTest007, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest007 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t discListenerId = -1;
    uint8_t filterNum = 2;
    uint8_t secondFilterNum = 3;

    BcScanFilter *firstDiscFilter = (BcScanFilter *)SoftBusCalloc(sizeof(BcScanFilter) * filterNum);
    firstDiscFilter[0] = *GetBcScanFilter();
    firstDiscFilter[1] = *GetBcScanFilter();
    unsigned char serviceData1[] = { 0x05, 0x05, 0x90 };
    EXPECT_EQ(EOK, memcpy_s(firstDiscFilter[1].serviceData, sizeof(serviceData1), serviceData1, sizeof(serviceData1)));

    BcScanFilter *secondDiscFilter = (BcScanFilter *)SoftBusCalloc(sizeof(BcScanFilter) * secondFilterNum);
    secondDiscFilter[0] = *GetBcScanFilter();
    secondDiscFilter[1] = *GetBcScanFilter();
    secondDiscFilter[2] = *GetBcScanFilter();
    unsigned char serviceData2[] = { 0x06, 0x05, 0x90 };
    EXPECT_EQ(EOK, memcpy_s(secondDiscFilter[1].serviceData, sizeof(serviceData2), serviceData2, sizeof(serviceData2)));
    unsigned char serviceData3[] = { 0x07, 0x05, 0x90 };
    EXPECT_EQ(EOK, memcpy_s(secondDiscFilter[2].serviceData, sizeof(serviceData3), serviceData3, sizeof(serviceData3)));

    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &discListenerId, GetScanCallback()));
    EXPECT_TRUE(discListenerId >= 0);
    // First SetScanFilter call
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, firstDiscFilter, filterNum));
    // First StartScan call, set isScanning = true, isFliterChanged = false
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));
    // Second SetScanFilter call, must be different filter, set isScanning = true, isFliterChanged = true
    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(discListenerId, secondDiscFilter, secondFilterNum));
    // Second StartScan
    EXPECT_EQ(SOFTBUS_OK, StartScan(discListenerId, &scanParam));

    EXPECT_EQ(SOFTBUS_OK, StopScan(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(discListenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());

    DISC_LOGI(DISC_TEST, "SoftbusBroadcastScannerTest007 end ----");
}

/*
 * @tc.name: TestGetScanFilter001
 * @tc.desc: GetScanFilter Error branching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, TestGetScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "TestGetScanFilter001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = -1;
    BcScanFilter *scanFilter = nullptr;
    uint8_t filterNum = 0;

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetScanFilter(listenerId, &scanFilter, nullptr));

    filterNum = 1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetScanFilter(listenerId, nullptr, &filterNum));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, GetScanFilter(listenerId, &scanFilter, &filterNum));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, GetScanFilter(SCAN_NUM_MAX, &scanFilter, &filterNum));

    listenerId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, GetScanFilter(listenerId, &scanFilter, &filterNum));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "TestGetScanFilter001 end ----");
}

/*
 * @tc.name: TestGetScanFilter002
 * @tc.desc: GetScanFilter Proper branching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, TestGetScanFilter002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "TestGetScanFilter002 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    BcScanFilter *scanFilter = nullptr;
    BcScanParams scanParam = {};
    BuildScanParam(&scanParam);

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, GetScanFilter(listenerId, &scanFilter, &filterNum));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "TestGetScanFilter002 end ----");
}

/*
 * @tc.name: BroadcastGetBroadcastHandle001
 * @tc.desc: BroadcastGetBroadcastHandle Proper branching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastGetBroadcastHandle001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastGetBroadcastHandle001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    int32_t Handle = 1;

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, BroadcastGetBroadcastHandle(bcId, &Handle));

    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);
    EXPECT_EQ(SOFTBUS_OK, BroadcastGetBroadcastHandle(bcId, &Handle));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastGetBroadcastHandle001 end ----");
}

/*
 * @tc.name: BroadcastSetScanReportChannelToLpDevice001
 * @tc.desc: BroadcastSetScanReportChannelToLpDevice Error branching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetScanReportChannelToLpDevice001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetScanReportChannelToLpDevice001 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t listenerId = 1;
    bool enable = true;

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, BroadcastSetScanReportChannelToLpDevice(listenerId, enable));
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, BroadcastSetScanReportChannelToLpDevice(SCAN_NUM_MAX, false));

    listenerId = 0;
    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_LISN_ID, BroadcastSetScanReportChannelToLpDevice(listenerId, enable));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetScanReportChannelToLpDevice001 end ----");
}

/*
 * @tc.name: BroadcastSetScanReportChannelToLpDevice002
 * @tc.desc: BroadcastSetScanReportChannelToLpDevice CheckScanIdIsValid is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetScanReportChannelToLpDevice002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetScanReportChannelToLpDevice002 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t listenerId = -1;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();

    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &listenerId, GetScanCallback()));
    EXPECT_TRUE(listenerId >= 0);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(listenerId, filter, filterNum));
    EXPECT_EQ(SOFTBUS_OK, BroadcastSetScanReportChannelToLpDevice(listenerId, true));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(listenerId));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetScanReportChannelToLpDevice002 end ----");
}

/*
 * @tc.name: CompareSameFilter001
 * @tc.desc: CompareSameFilter001 CompareSameFilter is FALSE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, CompareSameFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CompareSameFilter001 begin ----");
    ManagerMock managerMock;

    EXPECT_FALSE(CompareSameFilter(NULL, NULL));

    DISC_LOGI(DISC_TEST, "CompareSameFilter001 end ----");
}

/*
 * @tc.name: CompareSameFilter002
 * @tc.desc: CompareSameFilter002 CompareSameFilter is FALSE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, CompareSameFilter002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CompareSameFilter002 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    BcScanFilter *filter = GetBcScanFilter();

    EXPECT_FALSE(CompareSameFilter(filter, NULL));

    DISC_LOGI(DISC_TEST, "CompareSameFilter002 end ----");
}

/*
 * @tc.name: CompareSameFilter003
 * @tc.desc: CompareSameFilter003 CompareSameFilter is TRUE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, CompareSameFilter003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CompareSameFilter003 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    BcScanFilter *filter = GetBcScanFilter();
    BcScanFilter *filter2 = GetBcScanFilter();

    EXPECT_TRUE(CompareSameFilter(filter, filter2));

    DISC_LOGI(DISC_TEST, "CompareSameFilter003 end ----");
}

/*
 * @tc.name: CompareSameFilter004
 * @tc.desc: CompareSameFilter004 CompareSameFilter is FALSE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, CompareSameFilter004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "CompareSameFilter004 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    BcScanFilter *filter = GetBcScanFilter();
    BcScanFilter *filter2 = GetBcScanFilter();

    BcScanFilter srcFilter = *filter;
    BcScanFilter dstFilter = *filter2;
    if (srcFilter.serviceData != NULL && dstFilter.serviceData != NULL &&
    srcFilter.serviceDataMask != NULL && dstFilter.serviceDataMask != NULL &&
    memcmp(srcFilter.serviceData, dstFilter.serviceData, srcFilter.serviceDataLength) == 0 &&
    memcmp(srcFilter.serviceDataMask, dstFilter.serviceDataMask, srcFilter.serviceDataLength) == 0) {
        std::cout << "srcFilter.serviceData != NULL" << std::endl;
        srcFilter.serviceData = NULL;
        dstFilter.serviceData = NULL;
        srcFilter.serviceDataMask = NULL;
        dstFilter.serviceDataMask = NULL;
    }

    if (srcFilter.manufactureData == NULL && dstFilter.manufactureData == NULL &&
    srcFilter.manufactureDataMask == NULL && dstFilter.manufactureDataMask == NULL) {
        std::cout << "srcFilter.manufactureData == NULL" << std::endl;
        uint8_t test[] = {1, 2};
        srcFilter.manufactureDataLength = sizeof(test) / sizeof(test[0]);
        srcFilter.manufactureData = test;
        srcFilter.manufactureDataMask = test;
        dstFilter.manufactureDataLength = sizeof(test) / sizeof(test[0]);
        dstFilter.manufactureData = test;
        dstFilter.manufactureDataMask = test;
    }
    EXPECT_TRUE(CompareSameFilter(&srcFilter, &dstFilter));

    DISC_LOGI(DISC_TEST, "CompareSameFilter004 end ----");
}

/*
 * @tc.name: PerformSetBroadcastingParam001
 * @tc.desc: PerformSetBroadcastingParam001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, PerformSetBroadcastingParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam001 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_OK));
    BroadcastParam bcParam = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_BC_MGR_NOT_BROADCASTING, PerformSetBroadcastingParam(bcId, &adapterParam));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam001 end ----");
}

/*
 * @tc.name: PerformSetBroadcastingParam002
 * @tc.desc: PerformSetBroadcastingParam002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, PerformSetBroadcastingParam002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam002 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_OK));
    BroadcastParam bcParam = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);
    int32_t bcIdTest = bcId + 1;

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, PerformSetBroadcastingParam(bcIdTest, &adapterParam));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam002 end ----");
}

/*
 * @tc.name: PerformSetBroadcastingParam003
 * @tc.desc: PerformSetBroadcastingParam003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, PerformSetBroadcastingParam003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam003 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_OK));
    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, PerformSetBroadcastingParam(bcId, &adapterParam));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam003 end ----");
}

/*
 * @tc.name: PerformSetBroadcastingParam004
 * @tc.desc: PerformSetBroadcastingParam004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, PerformSetBroadcastingParam004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam004 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_OK, StartBroadcasting(bcId, &bcParam, &packet));
    EXPECT_EQ(SOFTBUS_OK, PerformSetBroadcastingParam(bcId, &adapterParam));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "PerformSetBroadcastingParam004 end ----");
}

/*
 * @tc.name: EnableBroadcasting001
 * @tc.desc: EnableBroadcasting001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, EnableBroadcasting001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "EnableBroadcasting001 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);
    int32_t bcIdTest = bcId + 1;

    EXPECT_EQ(SOFTBUS_BC_MGR_INVALID_BC_ID, EnableBroadcasting(bcIdTest));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "EnableBroadcasting001 end ----");
}

/*
 * @tc.name: EnableBroadcasting002
 * @tc.desc: EnableBroadcasting002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, EnableBroadcasting002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "EnableBroadcasting002 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    BroadcastParam bcParam = {};
    BroadcastPacket packet = {};
    BuildBroadcastParam(&bcParam);
    SoftbusBroadcastParam adapterParam = {};
    ConvertBcParams(&bcParam, &adapterParam);
    BuildBroadcastPacketExceptPayload(&packet);

    packet.bcData.payloadLen = sizeof(BC_DATA_PAYLOAD);
    packet.bcData.payload = BC_DATA_PAYLOAD;
    packet.rspData.payloadLen = sizeof(RSP_DATA_PAYLOAD);
    packet.rspData.payload = RSP_DATA_PAYLOAD;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_EQ(SOFTBUS_BC_MGR_NOT_BROADCASTING, EnableBroadcasting(bcId));
    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "EnableBroadcasting002 end ----");
}

/*
 * @tc.name: QueryBroadcastStatus001
 * @tc.desc: QueryBroadcastStatus001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, QueryBroadcastStatus001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "QueryBroadcastStatus001 begin ----");
    ManagerMock managerMock;
    EXPECT_CALL(managerMock, SoftBusCondWait)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, QueryBroadcastStatus(bcId, &bcId));
    DISC_LOGI(DISC_TEST, "QueryBroadcastStatus001 end ----");
}

/*
 * @tc.name: BroadcastSetAdvDeviceParam001
 * @tc.desc: BroadcastSetAdvDeviceParam001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetAdvDeviceParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam001 begin ----");
    ManagerMock managerMock;

    g_baseFuzzPos = 0;
    uint8_t type = GetData<uint8_t>();
    LpScanParam lpScanParam = BuildLpScanParam();
    lpScanParam.listenerId = listenderId;
    LpBroadcastParam lpBcParam;
    BuildLpBroadcastParam(&lpBcParam);

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, GetBroadcastCallback()));
    EXPECT_TRUE(bcId >= 0);

    EXPECT_FALSE(BroadcastSetAdvDeviceParam(static_cast<LpServerType>(type), &lpBcParam, &lpScanParam));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterBroadcaster(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam001 end ----");
}

/*
 * @tc.name: BroadcastSetAdvDeviceParam002
 * @tc.desc: BroadcastSetAdvDeviceParam002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetAdvDeviceParam002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam002 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetScanCallback()));
    EXPECT_TRUE(bcId >= 0);

    g_baseFuzzPos = 0;
    uint8_t type = GetData<uint8_t>();
    LpScanParam lpScanParam = BuildLpScanParam();
    lpScanParam.listenerId = bcId;
    uint8_t filterNum = 1;
    BcScanFilter *filter = GetBcScanFilter();
    LpBroadcastParam lpBcParam;
    BuildLpBroadcastParam(&lpBcParam);

    EXPECT_EQ(SOFTBUS_OK, SetScanFilter(bcId, filter, filterNum));
    EXPECT_FALSE(BroadcastSetAdvDeviceParam(static_cast<LpServerType>(type), &lpBcParam, &lpScanParam));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam002 end ----");
}

/*
 * @tc.name: BroadcastSetAdvDeviceParam003
 * @tc.desc: BroadcastSetAdvDeviceParam003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetAdvDeviceParam003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam003 begin ----");
    ManagerMock managerMock;

    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());
    int32_t bcId = -1;
    EXPECT_EQ(SOFTBUS_OK, RegisterScanListener(BROADCAST_PROTOCOL_BLE,
        SRV_TYPE_DIS, &bcId, GetScanCallback()));
    EXPECT_TRUE(bcId >= 0);

    g_baseFuzzPos = 0;
    uint8_t type = GetData<uint8_t>();
    LpScanParam lpScanParam = BuildLpScanParam();
    lpScanParam.listenerId = bcId;
    LpBroadcastParam lpBcParam;
    BuildLpBroadcastParam(&lpBcParam);

    EXPECT_FALSE(BroadcastSetAdvDeviceParam(static_cast<LpServerType>(type), &lpBcParam, &lpScanParam));

    EXPECT_EQ(SOFTBUS_OK, UnRegisterScanListener(bcId));
    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetAdvDeviceParam003 end ----");
}

/*
 * @tc.name: BroadcastEnableSyncDataToLpDevice001
 * @tc.desc: BroadcastEnableSyncDataToLpDevice001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastEnableSyncDataToLpDevice001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastEnableSyncDataToLpDevice001 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    EXPECT_EQ(SOFTBUS_OK, BroadcastEnableSyncDataToLpDevice());

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastEnableSyncDataToLpDevice001 end ----");
}

/*
 * @tc.name: BroadcastDisableSyncDataToLpDevice001
 * @tc.desc: BroadcastDisableSyncDataToLpDevice001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastDisableSyncDataToLpDevice001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastDisableSyncDataToLpDevice001 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    EXPECT_EQ(SOFTBUS_OK, BroadcastDisableSyncDataToLpDevice());

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastDisableSyncDataToLpDevice001 end ----");
}

/*
 * @tc.name: BroadcastSetLpAdvParam001
 * @tc.desc: BroadcastSetLpAdvParam001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusBroadcastMgrTest, BroadcastSetLpAdvParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "BroadcastSetLpAdvParam001 begin ----");
    ManagerMock managerMock;
    EXPECT_EQ(SOFTBUS_OK, InitBroadcastMgr());

    int32_t duration = 0;
    int32_t maxExtAdvEvents = 0;
    int32_t window = 0;
    int32_t interval = 0;
    int32_t bcHandle = 0;
    EXPECT_EQ(SOFTBUS_OK, BroadcastSetLpAdvParam(duration, maxExtAdvEvents, window, interval, bcHandle));

    EXPECT_EQ(SOFTBUS_OK, DeInitBroadcastMgr());
    DISC_LOGI(DISC_TEST, "BroadcastSetLpAdvParam001 end ----");
}
} // namespace OHOS
