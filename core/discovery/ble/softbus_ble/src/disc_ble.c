/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "disc_ble.h"

#include <stdlib.h>
#include <stdio.h>

#include "common_list.h"
#include "disc_ble_constant.h"
#include "disc_ble_utils.h"
#include "disc_event.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "discovery_service.h"
#include "lnn_device_info.h"
#include "lnn_ohos_account.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_range.h"
#include "softbus_bitmap.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hisysevt_discreporter.h"
#include "softbus_log_old.h"
#include "softbus_utils.h"

#define BLE_PUBLISH 0x0
#define BLE_SUBSCRIBE 0x2
#define BLE_ACTIVE 0x0
#define BLE_PASSIVE 0x1
#define BLE_INFO_COUNT 4

#define BLE_CHANNLE_MAP 0x0

#define BLE_ADV_TX_POWER_DEFAULT (-6)
#define BLE_ADV_TX_POWER_MAX (-2)

#define CON_ADV_ID 0x0
#define NON_ADV_ID 0x1
#define NUM_ADVERTISER 2
#define ADV_INTERNAL 48

#define BLE_MSG_TIME_OUT 6000

// Defination of boardcast
#define BLE_VERSION 4
#define DISTRIBUTE_BUSINESS 0x5
#define BYTE_MASK 0xFF
#define DEVICE_NAME_MAX_LEN 15

#define BIT_WAKE_UP 0x01
#define BIT_CUST_DATA_TYPE 0x10
#define BIT_HEART_BIT 0x20
#define BIT_CONNECT_BIT 0x40
#define BIT_CON 0x80
#define BIT_CON_POS 7

#define BLE_INFO_MANAGER "bleInfoManager"
#define BlE_ADVERTISER "bleAdvertiser"
#define RECV_MESSAGE_INFO "recvMessageInfo"

static int32_t g_bleScannerId = -1;
typedef enum {
    PUBLISH_ACTIVE_SERVICE,
    PUBLISH_PASSIVE_SERVICE,
    UNPUBLISH_SERVICE,
    START_ACTIVE_DISCOVERY,
    START_PASSIVE_DISCOVERY,
    STOP_DISCOVERY,
    REPLY_PASSIVE_NON_BROADCAST,
    PROCESS_TIME_OUT,
    RECOVERY,
    TURN_OFF,
} DISC_BLE_MESSAGE;

typedef struct {
    int32_t channel;
    bool isAdvertising;
    DeviceInfo deviceInfo;
    int32_t (*GetDeviceInfo)(DeviceInfo *info);
} DiscBleAdvertiser;

typedef struct {
    bool needUpdate;
    uint32_t capBitMap[CAPABILITY_NUM];
    int16_t capCount[CAPABILITY_MAX_BITNUM];
    uint8_t *capabilityData[CAPABILITY_MAX_BITNUM];
    uint32_t capDataLen[CAPABILITY_MAX_BITNUM];
    bool isSameAccount[CAPABILITY_MAX_BITNUM];
    bool isWakeRemote[CAPABILITY_MAX_BITNUM];
    int32_t freq[CAPABILITY_MAX_BITNUM];
    int32_t rangingRefCnt;
} DiscBleInfo;

typedef struct {
    PublishOption *publishOption;
    SubscribeOption *subscribeOption;
} DiscBleOption;

typedef struct {
    int32_t scanWindow;
    int32_t scanInterval;
} ScanSetting;

typedef struct {
    ListNode node;
    uint32_t capBitMap[CAPABILITY_NUM];
    char key[SHA_HASH_LEN];
    bool needBrMac;
} RecvMessage;

typedef struct {
    uint32_t numNeedBrMac;
    uint32_t numNeedResp;
    ListNode node;
    SoftBusMutex lock;
} RecvMessageInfo;

typedef struct {
    int32_t stateListenerId;
    int32_t scanListenerId;
} DiscBleListener;

typedef struct {
    uint32_t optionCapBitMap[CAPABILITY_NUM];
    uint8_t *custData;
    uint32_t custDataLen;
    uint32_t freq;
    bool isSameAccount;
    bool isWakeRemote;
    bool ranging;
} BleOption;

static ScanSetting g_scanTable[FREQ_BUTT] = {
    {SOFTBUS_BLE_SCAN_WINDOW_P2, SOFTBUS_BLE_SCAN_INTERVAL_P2},
    {SOFTBUS_BLE_SCAN_WINDOW_P10, SOFTBUS_BLE_SCAN_INTERVAL_P10},
    {SOFTBUS_BLE_SCAN_WINDOW_P25, SOFTBUS_BLE_SCAN_INTERVAL_P25},
    {SOFTBUS_BLE_SCAN_WINDOW_P100, SOFTBUS_BLE_SCAN_INTERVAL_P100}
};

static DiscInnerCallback *g_discBleInnerCb = NULL;
static DiscBleInfo g_bleInfoManager[BLE_INFO_COUNT];
static SoftBusMutex g_bleInfoLock = {0};
static DiscBleAdvertiser g_bleAdvertiser[NUM_ADVERTISER];
static bool g_isScanning = false;
static SoftBusHandler g_discBleHandler = {0};
static RecvMessageInfo g_recvMessageInfo = {0};
static DiscBleListener g_bleListener = {
    .stateListenerId = -1,
    .scanListenerId = -1
};

//g_conncernCapabilityMask support capability of this ble discovery
static uint32_t g_concernCapabilityMask =
    1 << CASTPLUS_CAPABILITY_BITMAP |
    1 << DVKIT_CAPABILITY_BITMAP |
    1 << OSD_CAPABILITY_BITMAP;

static const int g_bleTransCapabilityMap[CAPABILITY_MAX_BITNUM] = {
    -1,
    CASTPLUS_CAPABILITY_BITMAP,
    DVKIT_CAPABILITY_BITMAP,
    -1,
    OSD_CAPABILITY_BITMAP,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
};

static SoftBusMessage *CreateBleHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj);
static int32_t AddRecvMessage(const char *key, const uint32_t *capBitMap, bool needBrMac);
static int32_t MatchRecvMessage(const uint32_t *publishInfoMap, uint32_t *capBitMap, uint32_t len);
static RecvMessage *GetRecvMessage(const char *key);
static int32_t StartAdvertiser(int32_t adv);
static int32_t StopAdvertiser(int32_t adv);
static int32_t UpdateAdvertiser(int32_t adv);
static int32_t ReplyPassiveNonBroadcast(void);
static void ClearRecvMessage(void);
static int32_t StopScaner(void);
static void AssembleNonOptionalTlv(DeviceInfo *info, BroadcastData *broadcastData);
static int32_t BleInfoDump(int fd);
static int32_t BleAdvertiserDump(int fd);
static int32_t RecvMessageInfoDump(int fd);

// This function is used to compatibled with mobile phone, will remove later
static int ConvertCapBitMap(int oldCap)
{
    switch (oldCap) {
        case 1 << OSD_CAPABILITY_BITMAP: // osdCapability
            return 0x10;
        case 1 << CASTPLUS_CAPABILITY_BITMAP:  // castPlus
            return 0x02;
        case 1 << DVKIT_CAPABILITY_BITMAP: // dvkit
            return 0x04;
        default:
            return oldCap;
    }
}

static void DeConvertBitMap(unsigned int *dstCap, unsigned int *srcCap, int nums)
{
    (void)nums;
    for (int32_t i = 0; i < CAPABILITY_MAX_BITNUM; i++) {
        if (!SoftbusIsBitmapSet(srcCap, i)) {
            continue;
        }
        int bleCapability = g_bleTransCapabilityMap[i];
        if (bleCapability >= 0) {
            SoftbusBitmapSet(dstCap, bleCapability);
        }
    }
    DISC_LOGI(DISC_BLE, "old= %u, new= %u", *srcCap, *dstCap);
}

static void UpdateInfoManager(int adv, bool needUpdate)
{
    DISC_LOGI(DISC_CONTROL, "enter");
    if (SoftBusMutexLock(&g_bleInfoLock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return;
    }
    if (adv == NON_ADV_ID) {
        g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].needUpdate = needUpdate;
        g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdate = needUpdate;
    } else {
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdate = needUpdate;
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdate = needUpdate;
    }
    SoftBusMutexUnlock(&g_bleInfoLock);
}

static int32_t GetNeedUpdateAdvertiser(int32_t adv)
{
    if (adv == NON_ADV_ID) {
        return g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].needUpdate ||
            g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdate;
    } else {
        return g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdate ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdate;
    }
}

static void BleAdvEnableCallback(int channel, int status)
{
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        for (int32_t i = 0; i < NUM_ADVERTISER; i++) {
            if (g_bleAdvertiser[i].channel == channel) {
                g_bleAdvertiser[i].isAdvertising = true;
                DISC_LOGI(DISC_BLE, "enable ble advertiser adv=%d", i);
            }
        }
    }
}

static void BleAdvDisableCallback(int channel, int status)
{
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        for (int32_t i = 0; i < NUM_ADVERTISER; i++) {
            if (g_bleAdvertiser[i].channel == channel) {
                g_bleAdvertiser[i].isAdvertising = false;
                DISC_LOGI(DISC_BLE, "disable ble advertiser adv=%d", i);
            }
        }
    }
}

static void BleAdvDataCallback(int channel, int status)
{
    DISC_LOGI(DISC_BLE, "channel=%d status=%d", channel, status);
}

static void BleAdvUpdateCallback(int channel, int status)
{
    DISC_LOGI(DISC_BLE, "channel=%d status=%d", channel, status);
}

static bool CheckScanner(void)
{
    (void)SoftBusMutexLock(&g_bleInfoLock);
    uint32_t scanCapBit = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0];
    (void)SoftBusMutexUnlock(&g_bleInfoLock);
    return scanCapBit != 0;
}

static int32_t ScanFilter(const SoftBusBleScanResult *scanResultData)
{
    uint32_t advLen = scanResultData->advLen;
    uint8_t *advData = scanResultData->advData;
    DISC_CHECK_AND_RETURN_RET_LOGW(scanResultData->dataStatus == SOFTBUS_BLE_DATA_COMPLETE, SOFTBUS_ERR, DISC_BLE,
        "dataStatus[%u] is invalid", scanResultData->dataStatus);
    DISC_CHECK_AND_RETURN_RET_LOGW(advLen >= (POS_TLV + ADV_HEAD_LEN), SOFTBUS_ERR, DISC_BLE,
        "advLen[%u] is too short, less than adv header length", advLen);

    uint32_t broadcastAdvLen = advData[POS_PACKET_LENGTH];
    DISC_CHECK_AND_RETURN_RET_LOGE(broadcastAdvLen >= (ADV_HEAD_LEN + RSP_HEAD_LEN - 1), SOFTBUS_ERR, DISC_BLE,
        "broadcastAdvLen[%u] is too short, less than adv header length", broadcastAdvLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(advLen > (POS_PACKET_LENGTH + broadcastAdvLen + 1), SOFTBUS_ERR, DISC_BLE,
        "advLen[%u] is too short, less than adv packet length", advLen);
    uint32_t broadcastRspLen = advData[POS_PACKET_LENGTH + broadcastAdvLen + 1];
    DISC_CHECK_AND_RETURN_RET_LOGE(advLen >= (POS_PACKET_LENGTH + broadcastAdvLen + 1 + broadcastRspLen + 1),
        SOFTBUS_ERR, DISC_BLE, "advLen[%u] is too short, less than adv+rsp packet length", advLen);

    DISC_CHECK_AND_RETURN_RET_LOGE(advData[POS_UUID] == (uint8_t)(BLE_UUID & BYTE_MASK), SOFTBUS_ERR, DISC_BLE,
        "uuid low byte[%hhu] is invalid", advData[POS_UUID]);
    DISC_CHECK_AND_RETURN_RET_LOGE(advData[POS_UUID + 1] == (uint8_t)((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK),
        SOFTBUS_ERR, DISC_BLE, "uuid high byte[%hhu] is invalid", advData[POS_UUID + 1]);
    DISC_CHECK_AND_RETURN_RET_LOGE(advData[POS_VERSION + ADV_HEAD_LEN] == BLE_VERSION, SOFTBUS_ERR, DISC_BLE,
        "adv version[%hhu] is invalid", advData[POS_VERSION + ADV_HEAD_LEN]);

    if (!CheckScanner()) {
        DISC_LOGI(DISC_BLE, "no need to scan");
        (void)StopScaner();
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void ProcessDisConPacket(const uint8_t *advData, uint32_t advLen, DeviceInfo *foundInfo)
{
    DeviceWrapper device = {
        .info = foundInfo,
        .power = SOFTBUS_ILLEGAL_BLE_POWER
    };
    if (GetDeviceInfoFromDisAdvData(&device, advData, advLen) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "GetDeviceInfoFromDisAdvData failed");
        return;
    }
    (void)SoftBusMutexLock(&g_bleInfoLock);
    if ((foundInfo->capabilityBitmap[0] & g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0]) == 0x0) {
        DISC_LOGI(DISC_BLE, "don't match passive publish capBitMap");
        (void)SoftBusMutexUnlock(&g_bleInfoLock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_bleInfoLock);
    char key[SHA_HASH_LEN];
    if (SoftBusGenerateStrHash(advData, advLen, (uint8_t *)key) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "GenerateStrHash failed");
        return;
    }
    if (AddRecvMessage(key, foundInfo->capabilityBitmap, true) == SOFTBUS_OK) {
        ReplyPassiveNonBroadcast();
    }
}

static bool ProcessHashAccount(DeviceInfo *foundInfo)
{
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (!CheckCapBitMapExist(CAPABILITY_NUM, foundInfo->capabilityBitmap, pos)) {
            continue;
        }
        if (!(g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].isSameAccount[pos])) {
            return true;
        }
        uint8_t accountIdHash[SHORT_USER_ID_HASH_LEN] = {0};
        if (DiscBleGetShortUserIdHash(accountIdHash, SHORT_USER_ID_HASH_LEN) != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "DiscBleGetShortUserIdHash error");
            return false;
        }
        if (LnnIsDefaultOhosAccount()) {
            DISC_LOGE(DISC_BLE, "LnnIsDefaultOhosAccount, not the same account.");
            return false;
        }
        if (memcmp(accountIdHash, foundInfo->accountHash, SHORT_USER_ID_HASH_LEN) == 0) {
            return true;
        }
        DISC_LOGE(DISC_BLE, "err: not the same account.");
        return false;
    }
    return false;
}

static int32_t ConvertBleAddr(DeviceInfo *foundInfo)
{
    // convert ble bin mac to string mac before report
    char bleMac[BT_MAC_LEN] = {0};
    if (ConvertBtMacToStr(bleMac, BT_MAC_LEN,
        (uint8_t *)foundInfo->addr[0].info.ble.bleMac, BT_ADDR_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "convert ble mac to string failed");
        return SOFTBUS_ERR;
    }

    if (memset_s(foundInfo->addr[0].info.ble.bleMac, BT_MAC_LEN, 0, BT_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memset ble mac failed");
        return SOFTBUS_MEM_ERR;
    }

    if (memcpy_s(foundInfo->addr[0].info.ble.bleMac, BT_MAC_LEN, bleMac, BT_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcopy ble mac failed");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t RangeDevice(DeviceInfo *device, char rssi, int8_t power)
{
    int32_t range = -1;
    if (power != SOFTBUS_ILLEGAL_BLE_POWER) {
        SoftBusRangeParam param = {
            .rssi = *(signed char *)(&rssi),
            .power = power,
            .identity = {0}
        };

        if (memcpy_s(param.identity, SOFTBUS_DEV_IDENTITY_LEN, device->addr[0].info.ble.bleMac, BT_MAC_LEN) != EOK) {
            DISC_LOGE(DISC_BLE, "memcpy failed");
            return SOFTBUS_MEM_ERR;
        }

        int ret = SoftBusBleRange(&param, &range);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "range device failed, ret=%d", ret);
            range = -1;
            // range failed should report device continually
        }
    }
    device->range = range;
    return SOFTBUS_OK;
}

static void ProcessDisNonPacket(const uint8_t *advData, uint32_t advLen, char rssi,
    DeviceInfo *foundInfo)
{
    DeviceWrapper device = {
        .info = foundInfo,
        .power = SOFTBUS_ILLEGAL_BLE_POWER
    };
    if (GetDeviceInfoFromDisAdvData(&device, advData, advLen) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "GetDeviceInfoFromDisAdvData failed");
        return;
    }
    (void)SoftBusMutexLock(&g_bleInfoLock);
    uint32_t subscribeCap = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0];
    if (subscribeCap & (uint32_t)(foundInfo->capabilityBitmap[0] == 0x0)) {
        DISC_LOGE(DISC_BLE, "capbitmap mismatch");
        (void)SoftBusMutexUnlock(&g_bleInfoLock);
        return;
    }
    foundInfo->capabilityBitmap[0] = subscribeCap & foundInfo->capabilityBitmap[0];
    (void)SoftBusMutexUnlock(&g_bleInfoLock);

    if (ConvertBleAddr(foundInfo) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "convert ble address failed");
        return;
    }

    if (RangeDevice(foundInfo, rssi, device.power) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "range device failed");
        return;
    }

    InnerDeviceInfoAddtions add;
    add.medium = BLE;

    if (ProcessHashAccount(foundInfo)) {
        DISC_LOGI(DISC_BLE, "start report found device");
        uint32_t tempCap = 0;
        DeConvertBitMap(&tempCap, foundInfo->capabilityBitmap, foundInfo->capabilityBitmapNum);
        if (tempCap == 0) {
            DISC_LOGE(DISC_BLE, "unsupported ble capability %d", foundInfo->capabilityBitmap[0]);
            return;
        }
        foundInfo->capabilityBitmap[0] = tempCap;
        foundInfo->capabilityBitmapNum = 1;
        g_discBleInnerCb->OnDeviceFound(foundInfo, &add);
        SoftbusRecordDiscBleRssi(*(signed char *)(&rssi));
    }
}

static void ProcessDistributePacket(const SoftBusBleScanResult *scanResultData)
{
    uint32_t advLen = scanResultData->advLen;
    uint8_t *advData = scanResultData->advData;
    DeviceInfo foundInfo;
    (void)memset_s(&foundInfo, sizeof(foundInfo), 0, sizeof(foundInfo));
    foundInfo.addrNum = 1;
    foundInfo.addr[0].type = CONNECTION_ADDR_BLE;
    if (memcpy_s(foundInfo.addr[0].info.ble.bleMac, BT_ADDR_LEN, scanResultData->addr.addr, BT_ADDR_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy_s failed");
        return;
    }
    if ((advData[POS_BUSINESS_EXTENSION + ADV_HEAD_LEN] & BIT_HEART_BIT) != 0) {
        return;
    }
    if ((advData[POS_BUSINESS_EXTENSION + ADV_HEAD_LEN] & BIT_CON) != 0) {
        ProcessDisConPacket(advData, advLen, &foundInfo);
    } else {
        ProcessDisNonPacket(advData, advLen, scanResultData->rssi, &foundInfo);
    }
}

static inline bool IsDistributedBusiness(const uint8_t *data)
{
    return data[POS_BUSINESS + ADV_HEAD_LEN] == DISTRIBUTE_BUSINESS;
}

static void BleScanResultCallback(int listenerId, const SoftBusBleScanResult *scanResultData)
{
    (void)listenerId;
    DISC_CHECK_AND_RETURN_LOGW(scanResultData != NULL, DISC_BLE, "scan result is null");
    DISC_CHECK_AND_RETURN_LOGW(scanResultData->advData != NULL, DISC_BLE, "scan result advData is null");
    DISC_CHECK_AND_RETURN_LOGE(ScanFilter(scanResultData) == SOFTBUS_OK, DISC_BLE, "scan filter failed");

    uint8_t *advData = scanResultData->advData;
    if (IsDistributedBusiness(advData)) {
        SignalingMsgPrint("ble rcv", advData, scanResultData->advLen, SOFTBUS_LOG_DISC);
        ProcessDistributePacket(scanResultData);
    } else {
        DISC_LOGI(DISC_BLE, "ignore other business");
    }
}

static void BleOnScanStart(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGI(DISC_BLE, "BleOnScanStart");
    g_isScanning = true;
}

static void BleOnScanStop(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGI(DISC_BLE, "BleOnScanStop");
    g_isScanning = false;
}

static void BleOnStateChanged(int32_t listenerId, int32_t state)
{
    (void)listenerId;
    SoftBusMessage *msg = NULL;
    switch (state) {
        case SOFTBUS_BT_STATE_TURN_ON:
            DISC_LOGI(DISC_CONTROL, "bt turn on");
            msg = CreateBleHandlerMsg(RECOVERY, 0, 0, NULL);
            DISC_CHECK_AND_RETURN_LOGW(msg != NULL, DISC_CONTROL, "create msg failed");
            g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
            break;
        case SOFTBUS_BT_STATE_TURN_OFF:
            DISC_LOGI(DISC_CONTROL, "bt turn off");
            msg = CreateBleHandlerMsg(TURN_OFF, 0, 0, NULL);
            DISC_CHECK_AND_RETURN_LOGW(msg != NULL, DISC_CONTROL, "create msg failed");
            g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
            break;
        default:
            break;
    }
}

static SoftBusAdvCallback g_advCallback = {
    .AdvEnableCallback = BleAdvEnableCallback,
    .AdvDisableCallback = BleAdvDisableCallback,
    .AdvDataCallback = BleAdvDataCallback,
    .AdvUpdateCallback = BleAdvUpdateCallback,
    .LpDeviceInfoCallback = NULL
};

static SoftBusScanListener g_scanListener = {
    .OnScanStart = BleOnScanStart,
    .OnScanStop = BleOnScanStop,
    .OnScanResult = BleScanResultCallback,
    .OnScanStateChanged = NULL
};

static SoftBusBtStateListener g_stateChangedListener = {
    .OnBtStateChanged = BleOnStateChanged,
    .OnBtAclStateChanged = NULL,
};

static int32_t GetMaxExchangeFreq(void)
{
    int32_t maxFreq = 0;
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        for (uint32_t index = 0; index < BLE_INFO_COUNT; index++) {
            maxFreq = (maxFreq > g_bleInfoManager[index].freq[pos]) ? maxFreq : g_bleInfoManager[index].freq[pos];
        }
    }
    return maxFreq;
}

static bool GetWakeRemote(void)
{
    for (uint32_t index = 0; index < CAPABILITY_MAX_BITNUM; index++) {
        if (g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[index]) {
            return true;
        }
    }
    return false;
}

static int32_t GetConDeviceInfo(DeviceInfo *info)
{
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    uint32_t infoIndex = BLE_SUBSCRIBE | BLE_ACTIVE;
    if (CheckBitMapEmpty(CAPABILITY_NUM, g_bleInfoManager[infoIndex].capBitMap)) {
        DISC_LOGE(DISC_BLE, "all capbit is zero");
        return SOFTBUS_ERR;
    }
    if (DiscBleGetDeviceIdHash((uint8_t *)info->devId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceId failed");
    }
    if (DiscBleGetDeviceName(info->devName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceName failed");
    }
    info->devType = (DeviceType)DiscBleGetDeviceType();
    bool isSameAccount = false;
    bool isWakeRemote = false;
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        isSameAccount = isSameAccount ? isSameAccount : g_bleInfoManager[infoIndex].isSameAccount[pos];
        isWakeRemote = isWakeRemote ? isWakeRemote : g_bleInfoManager[infoIndex].isWakeRemote[pos];
    }
    (void)memset_s(info->accountHash, MAX_ACCOUNT_HASH_LEN, 0x0, MAX_ACCOUNT_HASH_LEN);
    DiscBleGetShortUserIdHash((uint8_t *)info->accountHash, SHORT_USER_ID_HASH_LEN);
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] = g_bleInfoManager[infoIndex].capBitMap[pos];
    }
    return SOFTBUS_OK;
}

static int32_t GetNonDeviceInfo(DeviceInfo *info)
{
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    if (DiscBleGetDeviceIdHash((uint8_t *)info->devId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceId failed");
    }
    if (DiscBleGetDeviceName(info->devName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceName failed");
    }
    info->devType = (DeviceType)DiscBleGetDeviceType();
    uint32_t passiveCapBitMap[CAPABILITY_NUM] = {0};
    if (MatchRecvMessage(g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap,
        passiveCapBitMap, CAPABILITY_NUM) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "MatchRecvMessage failed");
        return SOFTBUS_ERR;
    }
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] =
        g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[pos] | passiveCapBitMap[pos];
    }

    int32_t activeCnt = g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].rangingRefCnt;
    int32_t passiveCnt = g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].rangingRefCnt;
    info->range = activeCnt + passiveCnt;

    if (CheckBitMapEmpty(CAPABILITY_NUM, info->capabilityBitmap)) {
        DISC_LOGE(DISC_BLE, "all capbit is zero");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BuildBleConfigAdvData(SoftBusBleAdvData *advData, const BroadcastData *broadcastData)
{
    if (advData == NULL || broadcastData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    advData->advData = (uint8_t *)SoftBusCalloc(ADV_DATA_MAX_LEN + ADV_HEAD_LEN);
    if (advData->advData == NULL) {
        DISC_LOGE(DISC_BLE, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    advData->scanRspData = (uint8_t *)SoftBusCalloc(RESP_DATA_MAX_LEN + RSP_HEAD_LEN);
    if (advData->scanRspData == NULL) {
        DISC_LOGE(DISC_BLE, "malloc failed");
        SoftBusFree(advData->advData);
        advData->advData = NULL;
        return SOFTBUS_MALLOC_ERR;
    }
    unsigned short advLength = (broadcastData->dataLen > ADV_DATA_MAX_LEN) ? ADV_DATA_MAX_LEN : broadcastData->dataLen;
    advData->advLength = advLength + ADV_HEAD_LEN;
    advData->advData[POS_FLAG_BYTE_LEN] = FLAG_BYTE_LEN;
    advData->advData[POS_FLAG_AD_TYPE] = FLAG_AD_TYPE;
    advData->advData[POS_FLAG_AD_DATA] = FLAG_AD_DATA;
    advData->advData[POS_AD_TYPE] = AD_TYPE;
    advData->advData[POS_UUID] = (char)(BLE_UUID & BYTE_MASK);
    advData->advData[POS_UUID + 1] = (char)((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK);
    advData->advData[POS_PACKET_LENGTH] = advData->advLength - POS_PACKET_LENGTH - 1;
    DISC_LOGI(DISC_BLE, "advData->advLength=%d advLength=%d", advData->advLength, advLength);
    if (memcpy_s(&advData->advData[ADV_HEAD_LEN], advLength, broadcastData->data.advData, advLength) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy err");
        return SOFTBUS_MEM_ERR;
    }
    advData->scanRspLength = broadcastData->dataLen - advLength + RSP_HEAD_LEN;
    advData->scanRspData[POS_RSP_TYPE] = RSP_TYPE;
    advData->scanRspData[POS_COMPANY_ID] = COMPANY_ID & BYTE_MASK;
    advData->scanRspData[POS_COMPANY_ID + 1] = (COMPANY_ID >> BYTE_SHIFT_BIT) & BYTE_MASK;
    if (advData->scanRspLength > RSP_HEAD_LEN) {
        if (memcpy_s(&advData->scanRspData[RSP_HEAD_LEN], advData->scanRspLength,
            broadcastData->data.rspData, advData->scanRspLength) != EOK) {
            DISC_LOGE(DISC_BLE, "memcpy err");
            return SOFTBUS_MEM_ERR;
        }
    }
    advData->scanRspData[POS_RSP_LENGTH] = advData->scanRspLength - POS_RSP_LENGTH - 1;
    DISC_LOGI(DISC_BLE, "advData->scanRspLength=%d POS_RSP_LENGTH=%d",
        advData->scanRspLength, advData->scanRspData[POS_RSP_LENGTH]);
    return SOFTBUS_OK;
}

static void DestroyBleConfigAdvData(SoftBusBleAdvData *advData)
{
    if (advData == NULL) {
        return;
    }
    SoftBusFree(advData->advData);
    SoftBusFree(advData->scanRspData);
}

static void AssembleNonOptionalTlv(DeviceInfo *info, BroadcastData *broadcastData)
{
    (void)SoftBusMutexLock(&g_recvMessageInfo.lock);
    if (g_recvMessageInfo.numNeedBrMac > 0) {
        SoftBusBtAddr addr;
        if (SoftBusGetBtMacAddr(&addr) == SOFTBUS_OK) {
            (void)AssembleTLV(broadcastData, TLV_TYPE_BR_MAC, (const void *)&addr.addr, BT_ADDR_LEN);
        }
    }
    (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    if (info->range > 0) {
        int8_t power = 0;
        if (SoftBusGetBlePower(&power) == SOFTBUS_OK) {
            (void)AssembleTLV(broadcastData, TLV_TYPE_RANGE_POWER, (const void *)&power, RANGE_POWER_TYPE_LEN);
        }
    }
}

static int32_t GetBroadcastData(DeviceInfo *info, int32_t advId, BroadcastData *broadcastData)
{
    bool isWakeRemote = GetWakeRemote();
    if (memset_s(broadcastData->data.data, BROADCAST_MAX_LEN, 0x0, BROADCAST_MAX_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memset failed");
        return SOFTBUS_MEM_ERR;
    }
    broadcastData->data.data[POS_VERSION] = BLE_VERSION & BYTE_MASK;
    broadcastData->data.data[POS_BUSINESS] = DISTRIBUTE_BUSINESS & BYTE_MASK;
    broadcastData->data.data[POS_BUSINESS_EXTENSION] = BIT_CUST_DATA_TYPE;
    if (advId == CON_ADV_ID) {
        broadcastData->data.data[POS_BUSINESS_EXTENSION] |= BIT_CON;
        if (isWakeRemote) {
            broadcastData->data.data[POS_BUSINESS_EXTENSION] |= BIT_WAKE_UP;
        }
        if (memcpy_s(&broadcastData->data.data[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN,
            info->accountHash, SHORT_USER_ID_HASH_LEN) != EOK) {
            DISC_LOGE(DISC_BLE, "memcpy failed");
            return SOFTBUS_ERR;
        }
    } else {
        DiscBleGetShortUserIdHash(&broadcastData->data.data[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN);
    }
    broadcastData->data.data[POS_CAPABLITY] = info->capabilityBitmap[0] & BYTE_MASK;
    broadcastData->data.data[POS_CAPABLITY_EXTENSION] = 0x0;
    broadcastData->dataLen = POS_TLV;
    char deviceIdHash[SHORT_DEVICE_ID_HASH_LENGTH + 1] = {0};
    if (DiscBleGetDeviceIdHash((uint8_t *)deviceIdHash) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceId Hash failed");
    }
    (void)AssembleTLV(broadcastData, TLV_TYPE_DEVICE_ID_HASH, (const void *)deviceIdHash,
        SHORT_DEVICE_ID_HASH_LENGTH);
    uint16_t devType = info->devType;
    uint8_t sendDevType[DEVICE_TYPE_LEN] = {0};
    uint32_t devTypeLen = 1;
    sendDevType[0] = devType & DEVICE_TYPE_MASK;
    if (devType >= (1 << ONE_BYTE_LENGTH)) {
        sendDevType[1] = (devType >> ONE_BYTE_LENGTH) & DEVICE_TYPE_MASK;
        devTypeLen++;
    }
    (void)AssembleTLV(broadcastData, TLV_TYPE_DEVICE_TYPE, (const void *)sendDevType, devTypeLen);
    if (advId == NON_ADV_ID) {
        AssembleNonOptionalTlv(info, broadcastData);
    }
    (void)AssembleTLV(broadcastData, TLV_TYPE_DEVICE_NAME, (const void *)info->devName, strlen(info->devName) + 1);
    DISC_LOGE(DISC_BLE, "broadcastData->dataLen=%d", broadcastData->dataLen);
    return SOFTBUS_OK;
}

static void BuildAdvParam(SoftBusBleAdvParams *advParam)
{
    advParam->minInterval = ADV_INTERNAL;
    advParam->maxInterval = ADV_INTERNAL;
    advParam->advType = SOFTBUS_BLE_ADV_IND;
    advParam->ownAddrType = SOFTBUS_BLE_PUBLIC_DEVICE_ADDRESS;
    advParam->peerAddrType = SOFTBUS_BLE_PUBLIC_DEVICE_ADDRESS;
    advParam->channelMap = BLE_CHANNLE_MAP;
    advParam->txPower = BLE_ADV_TX_POWER_DEFAULT;
}

static int32_t StartAdvertiser(int32_t adv)
{
    DISC_LOGI(DISC_BLE, "enter");
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser->isAdvertising) {
        if (GetNeedUpdateAdvertiser(adv)) {
            DISC_LOGI(DISC_BLE, "advertising need update");
            return UpdateAdvertiser(adv);
        } else {
            DISC_LOGI(DISC_BLE, "advertising no need update");
            return SOFTBUS_OK;
        }
    }
    int32_t ret = advertiser->GetDeviceInfo(&advertiser->deviceInfo);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "advertiser adv:%d GetConDeviceInfo failed", adv);
        return StopAdvertiser(adv);
    }
    BroadcastData broadcastData;
    (void)memset_s(&broadcastData, sizeof(BroadcastData), 0, sizeof(BroadcastData));
    if (GetBroadcastData(&advertiser->deviceInfo, adv, &broadcastData) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get broadcast data failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvData advData = {0};
    if (BuildBleConfigAdvData(&advData, &broadcastData) != SOFTBUS_OK) {
        DestroyBleConfigAdvData(&advData);
        DISC_LOGE(DISC_BLE, "BuildBleConfigAdvData failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvParams advParam = {0};
    BuildAdvParam(&advParam);
    if (SoftBusSetAdvData(adv, &advData) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "set ble adv adv=%d data failed", adv);
        DestroyBleConfigAdvData(&advData);
        return SOFTBUS_ERR;
    }
    SignalingMsgPrint("ble send", (uint8_t *)advData.advData, (uint8_t)advData.advLength, SOFTBUS_LOG_DISC);
    DiscEventExtra discEventExtra = { .broadcastType = BLE };
    DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
    if (SoftBusStartAdv(advertiser->channel, &advParam) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_START_BROADCAST_FAIL;
        DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
        DestroyBleConfigAdvData(&advData);
        DISC_LOGE(DISC_BLE, "start adv adv=%d failed", adv);
        return SOFTBUS_ERR;
    }
    UpdateInfoManager(adv, false);
    DestroyBleConfigAdvData(&advData);
    return SOFTBUS_OK;
}

static int32_t StopAdvertiser(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (!advertiser->isAdvertising) {
        DISC_LOGI(DISC_BLE, "advertiser adv adv=%d is already stopped.", adv);
        return SOFTBUS_OK;
    }
    DiscEventExtra discEventExtra = { .broadcastType = BLE, .result = EVENT_STAGE_RESULT_OK };
    DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
    if (SoftBusStopAdv(advertiser->channel) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_END_BROADCAST_FAIL;
        DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
        DISC_LOGE(DISC_BLE, "stop advertiser advId=%d failed.", adv);
    }
    if (adv == NON_ADV_ID) {
        (void)SoftBusMutexLock(&g_recvMessageInfo.lock);
        ClearRecvMessage();
        (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAdvertiser(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    int32_t ret = advertiser->GetDeviceInfo(&advertiser->deviceInfo);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "advertiser adv=%d GetConDeviceInfo failed", adv);
        return StopAdvertiser(adv);
    }
    BroadcastData broadcastData;
    if (GetBroadcastData(&advertiser->deviceInfo, adv, &broadcastData) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvData advData = {0};
    if (BuildBleConfigAdvData(&advData, &broadcastData) != SOFTBUS_OK) {
        DestroyBleConfigAdvData(&advData);
        DISC_LOGE(DISC_BLE, "BuildBleConfigAdvData failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvParams advParam = {0};
    BuildAdvParam(&advParam);
    DiscEventExtra discEventExtra = { .broadcastType = BLE };
    DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
    if (SoftBusUpdateAdv(advertiser->channel, &advData, &advParam) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_START_BROADCAST_FAIL;
        DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, discEventExtra);
        DestroyBleConfigAdvData(&advData);
        DISC_LOGE(DISC_BLE, "UpdateAdv failed");
        return SOFTBUS_ERR;
    }
    UpdateInfoManager(adv, false);
    DestroyBleConfigAdvData(&advData);
    return SOFTBUS_OK;
}

static void InitScanner(void)
{
    g_isScanning = false;
}

static int32_t GetScannerParam(int32_t freq, SoftBusBleScanParams *scanParam)
{
    scanParam->scanInterval = (uint16_t)g_scanTable[freq].scanInterval;
    scanParam->scanWindow = (uint16_t)g_scanTable[freq].scanWindow;
    scanParam->scanType = SOFTBUS_BLE_SCAN_TYPE_ACTIVE;
    scanParam->scanPhy = SOFTBUS_BLE_SCAN_PHY_1M;
    scanParam->scanFilterPolicy = SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL;
    return SOFTBUS_OK;
}

static void StartScaner(void)
{
    if (!CheckScanner()) {
        DISC_LOGI(DISC_BLE, "no need to start scanner");
        (void)StopScaner();
        return;
    }
    if (g_isScanning) {
        DISC_LOGI(DISC_BLE, "scanner already start, no need start again");
        return;
    }
    SoftBusBleScanParams scanParam;
    int32_t maxFreq = GetMaxExchangeFreq();
    DiscEventExtra discEventExtra = { .scanType = BLE };
    DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, discEventExtra);
    if (GetScannerParam(maxFreq, &scanParam) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_START_SCAN_FAIL;
        DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, discEventExtra);
        DISC_LOGE(DISC_BLE, "GetScannerParam failed");
        return;
    }
    if (SoftBusStartScan(g_bleListener.scanListenerId, g_bleScannerId, &scanParam) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_START_SCAN_FAIL;
        DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, discEventExtra);
        DISC_LOGE(DISC_BLE, "start scan failed");
        return;
    }
    DISC_LOGI(DISC_BLE, "StartScanner success");
}

static int32_t StopScaner(void)
{
    if (!g_isScanning) {
        DISC_LOGI(DISC_BLE, "already stop scanning");
        return SOFTBUS_OK;
    }
    DiscEventExtra discEventExtra = { .scanType = BLE, .result = EVENT_STAGE_RESULT_OK };
    DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, discEventExtra);
    if (SoftBusStopScan(g_bleListener.scanListenerId, g_bleScannerId) != SOFTBUS_OK) {
        discEventExtra.errcode = SOFTBUS_DISCOVER_END_SCAN_FAIL;
        DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, discEventExtra);
        DISC_LOGI(DISC_BLE, "StopScaner failed");
        return SOFTBUS_ERR;
    }
    DISC_LOGI(DISC_BLE, "success");
    return SOFTBUS_OK;
}

static void GetBleOption(BleOption *bleOption, const DiscBleOption *option)
{
    if (option->publishOption != NULL) {
        bleOption->optionCapBitMap[0] = (uint32_t)ConvertCapBitMap(option->publishOption->capabilityBitmap[0]);
        bleOption->custDataLen = option->publishOption->dataLen;
        bleOption->custData = option->publishOption->capabilityData;
        bleOption->isSameAccount = false;
        bleOption->isWakeRemote = false;
        bleOption->freq = (uint32_t)(option->publishOption->freq);
        bleOption->ranging = option->publishOption->ranging;
    } else {
        bleOption->optionCapBitMap[0] = (uint32_t)ConvertCapBitMap(option->subscribeOption->capabilityBitmap[0]);
        bleOption->custDataLen = option->subscribeOption->dataLen;
        bleOption->custData = option->subscribeOption->capabilityData;
        bleOption->isSameAccount = option->subscribeOption->isSameAccount;
        bleOption->isWakeRemote = option->subscribeOption->isWakeRemote;
        bleOption->freq = (uint32_t)(option->subscribeOption->freq);
        bleOption->ranging = false;
    }
}

static int32_t RegisterCapability(DiscBleInfo *info, const DiscBleOption *option)
{
    BleOption bleOption;
    (void)memset_s(&bleOption, sizeof(BleOption), 0, sizeof(BleOption));
    GetBleOption(&bleOption, option);
    uint32_t *optionCapBitMap = bleOption.optionCapBitMap;
    uint32_t custDataLen = bleOption.custDataLen;
    uint32_t freq = bleOption.freq;
    uint8_t *custData = bleOption.custData;
    bool isSameAccount = bleOption.isSameAccount;
    bool isWakeRemote = bleOption.isWakeRemote;
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (!CheckCapBitMapExist(CAPABILITY_NUM, optionCapBitMap, pos)) {
            continue;
        }
        if (!CheckCapBitMapExist(CAPABILITY_NUM, info->capBitMap, pos)) {
            (void)SetCapBitMapPos(CAPABILITY_NUM, info->capBitMap, pos);
            info->needUpdate = true;
        }
        info->capCount[pos] += 1;
        info->isSameAccount[pos] = isSameAccount;
        info->isWakeRemote[pos] = isWakeRemote;
        info->freq[pos] = (int32_t)freq;
        info->capDataLen[pos] = 0;
        if (custData == NULL) {
            continue;
        }
        if (info->capabilityData[pos] == NULL) {
            info->capabilityData[pos] = (uint8_t *)SoftBusCalloc(CUST_DATA_MAX_LEN);
            if (info->capabilityData[pos] == NULL) {
                return SOFTBUS_MALLOC_ERR;
            }
        }
        if (memcpy_s(info->capabilityData[pos], CUST_DATA_MAX_LEN, custData, custDataLen) != EOK) {
            SoftBusFree(info->capabilityData[pos]);
            return SOFTBUS_MEM_ERR;
        }
        info->capDataLen[pos] = custDataLen;
    }

    if (bleOption.ranging) {
        info->rangingRefCnt += 1;
        info->needUpdate = true;
    }

    return SOFTBUS_OK;
}

static void UnregisterCapability(DiscBleInfo *info, DiscBleOption *option)
{
    uint32_t *optionCapBitMap = NULL;
    bool isSameAccount = false;
    bool isWakeRemote = false;
    bool ranging = false;
    if (option->publishOption != NULL) {
        optionCapBitMap = option->publishOption->capabilityBitmap;
        optionCapBitMap[0] = (uint32_t)ConvertCapBitMap(optionCapBitMap[0]);
        ranging = option->publishOption->ranging;
    } else {
        optionCapBitMap = option->subscribeOption->capabilityBitmap;
        optionCapBitMap[0] = (uint32_t)ConvertCapBitMap(optionCapBitMap[0]);
        isSameAccount = option->subscribeOption->isSameAccount;
        isWakeRemote = option->subscribeOption->isWakeRemote;
        ranging = false;
    }
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (!CheckCapBitMapExist(CAPABILITY_NUM, optionCapBitMap, pos) ||
            !CheckCapBitMapExist(CAPABILITY_NUM, info->capBitMap, pos)) {
            continue;
        }
        info->capCount[pos] -= 1;
        if (info->capCount[pos] == 0) {
            (void)UnsetCapBitMapPos(CAPABILITY_NUM, info->capBitMap, pos);
            SoftBusFree(info->capabilityData[pos]);
            info->capabilityData[pos] = NULL;
            info->capDataLen[pos] = 0;
            info->needUpdate = true;
        }
        info->isSameAccount[pos] = isSameAccount;
        info->isWakeRemote[pos] = isWakeRemote;
        info->freq[pos] = -1;
    }
    if (ranging && info->rangingRefCnt > 0) {
        info->rangingRefCnt -= 1;
        info->needUpdate = true;
    }
}

static int32_t ProcessBleInfoManager(bool isStart, uint8_t publishFlags, uint8_t activeFlags, const void *option)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_ERR, DISC_BLE, "option is null");
    DiscBleOption regOption;
    if (publishFlags == BLE_PUBLISH) {
        regOption.publishOption = (PublishOption *)option;
        regOption.subscribeOption = NULL;
    } else {
        regOption.publishOption = NULL;
        regOption.subscribeOption = (SubscribeOption *)option;
    }
    uint8_t index = publishFlags | activeFlags;
    if (SoftBusMutexLock(&g_bleInfoLock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t oldCap = g_bleInfoManager[index].capBitMap[0];
    int32_t oldRangingRefCount = g_bleInfoManager[index].rangingRefCnt;
    if (isStart) {
        int32_t status = RegisterCapability(&g_bleInfoManager[index], &regOption);
        if (status != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "RegisterCapability failed, err=%d", status);
            SoftBusMutexUnlock(&g_bleInfoLock);
            return SOFTBUS_ERR;
        }
    } else {
        UnregisterCapability(&g_bleInfoManager[index], &regOption);
    }

    uint32_t newCap = g_bleInfoManager[index].capBitMap[0];
    int32_t newRangingRefCount = g_bleInfoManager[index].rangingRefCnt;
    DISC_LOGI(DISC_BLE, "ble discovery request summary, action: (%d, %d, %d) cap: %d->%d, ref ranging count: %d->%d",
          isStart, publishFlags, activeFlags, oldCap, newCap, oldRangingRefCount, newRangingRefCount);

    SoftBusMutexUnlock(&g_bleInfoLock);
    return SOFTBUS_OK;
}

static SoftBusMessage *CreateBleHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        DISC_LOGE(DISC_BLE, "ble create handler msg failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_discBleHandler;
    msg->FreeMessage = NULL;
    msg->obj = obj;
    return msg;
}

static int32_t ProcessBleDiscFunc(bool isStart, uint8_t publishFlags, uint8_t activeFlags,
    int32_t funcCode, const void *option)
{
    if (SoftBusGetBtState() != BLE_ENABLE) {
        DISC_LOGE(DISC_BLE, "get bt state failed.");
        return SOFTBUS_ERR;
    }
    int32_t ret = ProcessBleInfoManager(isStart, publishFlags, activeFlags, option);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "process ble info manager failed");
        return ret;
    }
    SoftBusMessage *msg = CreateBleHandlerMsg(funcCode, 0, 0, NULL);
    if (msg == NULL) {
        DISC_LOGE(DISC_BLE, "CreateBleHandlerMsg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t BleStartActivePublish(const PublishOption *option)
{
    return ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_ACTIVE, PUBLISH_ACTIVE_SERVICE, (void *)option);
}

static int32_t BleStartPassivePublish(const PublishOption *option)
{
    return ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_PASSIVE, PUBLISH_PASSIVE_SERVICE, (void *)option);
}

static int32_t BleStopActivePublish(const PublishOption *option)
{
    return ProcessBleDiscFunc(false, BLE_PUBLISH, BLE_ACTIVE, UNPUBLISH_SERVICE, (void *)option);
}

static int32_t BleStopPassivePublish(const PublishOption *option)
{
    return ProcessBleDiscFunc(false, BLE_PUBLISH, BLE_PASSIVE, UNPUBLISH_SERVICE, (void *)option);
}

static int32_t BleStartActiveDiscovery(const SubscribeOption *option)
{
    return ProcessBleDiscFunc(true, BLE_SUBSCRIBE, BLE_ACTIVE, START_ACTIVE_DISCOVERY, (void *)option);
}

static int32_t BleStartPassiveDiscovery(const SubscribeOption *option)
{
    return ProcessBleDiscFunc(true, BLE_SUBSCRIBE, BLE_PASSIVE, START_PASSIVE_DISCOVERY, (void *)option);
}

static int32_t BleStopActiveDiscovery(const SubscribeOption *option)
{
    return ProcessBleDiscFunc(false, BLE_SUBSCRIBE, BLE_ACTIVE, STOP_DISCOVERY, (void *)option);
}

static int32_t BleStopPassiveDiscovery(const SubscribeOption *option)
{
    return ProcessBleDiscFunc(false, BLE_SUBSCRIBE, BLE_PASSIVE, STOP_DISCOVERY, (void *)option);
}

static bool BleIsConcern(uint32_t capability)
{
    return (capability & g_concernCapabilityMask) != 0;
}
static int32_t UpdateAdvertiserDeviceInfo(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser->isAdvertising && GetNeedUpdateAdvertiser(adv)) {
        if (UpdateAdvertiser(adv) == SOFTBUS_OK) {
            DISC_LOGI(DISC_BLE, "update device info success");
            return SOFTBUS_OK;
        }
        return SOFTBUS_ERR;
    }

    DISC_LOGI(DISC_BLE, "not advertising or no need to update");
    return SOFTBUS_OK;
}

static void BleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
    if (UpdateAdvertiserDeviceInfo(NON_ADV_ID) != SOFTBUS_OK || UpdateAdvertiserDeviceInfo(CON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "update failed");
        return;
    }
    DISC_LOGI(DISC_BLE, "update success");
}

static DiscoveryFuncInterface g_discBleFuncInterface = {
    .Publish = BleStartActivePublish,
    .StartScan = BleStartPassivePublish,
    .Unpublish = BleStopActivePublish,
    .StopScan = BleStopPassivePublish,
    .StartAdvertise = BleStartActiveDiscovery,
    .Subscribe = BleStartPassiveDiscovery,
    .Unsubscribe = BleStopPassiveDiscovery,
    .StopAdvertise = BleStopActiveDiscovery,
    .UpdateLocalDeviceInfo = BleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_discBleDispatcherInterface = {
    .IsConcern = BleIsConcern,
    .mediumInterface = &g_discBleFuncInterface

};

static int32_t InitAdvertiser(void)
{
    int32_t conChannel = SoftBusGetAdvChannel(&g_advCallback, &g_bleScannerId, false);
    int32_t nonChannel = SoftBusGetAdvChannel(&g_advCallback, &g_bleScannerId, false);
    if (conChannel < 0 || nonChannel < 0) {
        DISC_LOGE(DISC_INIT, "get adv channel failed");
        (void)SoftBusReleaseAdvChannel(conChannel);
        (void)SoftBusReleaseAdvChannel(nonChannel);
        return SOFTBUS_ERR;
    }
    DISC_LOGI(DISC_INIT, "conChannel=%d nonChannel=%d", conChannel, nonChannel);

    for (uint32_t i = 0; i < NUM_ADVERTISER; i++) {
        g_bleAdvertiser[i].isAdvertising = false;
    }
    g_bleAdvertiser[CON_ADV_ID].GetDeviceInfo = GetConDeviceInfo;
    g_bleAdvertiser[CON_ADV_ID].channel = conChannel;
    g_bleAdvertiser[NON_ADV_ID].GetDeviceInfo = GetNonDeviceInfo;
    g_bleAdvertiser[NON_ADV_ID].channel = nonChannel;

    return SOFTBUS_OK;
}

static void InitDiscBleInfo(DiscBleInfo *info)
{
    (void)memset_s(info, sizeof(DiscBleInfo), 0, sizeof(DiscBleInfo));
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        info->freq[pos] = -1;
    }
}

static void DiscBleInitPublish(void)
{
    InitDiscBleInfo(&g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE]);
    InitDiscBleInfo(&g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE]);
}

static void DiscBleInitSubscribe(void)
{
    InitDiscBleInfo(&g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE]);
    InitDiscBleInfo(&g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE]);
}

static void StartActivePublish(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    (void)StartAdvertiser(NON_ADV_ID);
    DISC_LOGI(DISC_BLE, "end");
}

static void StartPassivePublish(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
        DISC_LOGI(DISC_BLE, "UpdateAdvertiser %d", NON_ADV_ID);
        UpdateAdvertiser(NON_ADV_ID);
    }
    StartScaner();
    DISC_LOGI(DISC_BLE, "end");
}

static void StartActiveDiscovery(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (StartAdvertiser(CON_ADV_ID) == SOFTBUS_OK) {
        StartScaner();
    }
    DISC_LOGI(DISC_BLE, "end");
}

static void StartPassiveDiscovery(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    StartScaner();
    DISC_LOGI(DISC_BLE, "end");
}

static void Recovery(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    (void)StartAdvertiser(CON_ADV_ID);
    (void)StartAdvertiser(NON_ADV_ID);
    StartScaner();
    DISC_LOGI(DISC_BLE, "end");
}

static void BleDiscTurnOff(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    (void)StopAdvertiser(NON_ADV_ID);
    (void)StopAdvertiser(CON_ADV_ID);
    (void)StopScaner();
    DISC_LOGI(DISC_BLE, "end");
}

static int32_t ReplyPassiveNonBroadcast(void)
{
    DISC_LOGI(DISC_BLE, "enter");
    SoftBusMessage *msg = CreateBleHandlerMsg(REPLY_PASSIVE_NON_BROADCAST, 0, 0, NULL);
    if (msg == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t MessageRemovePredicate(const SoftBusMessage *msg, void *args)
{
    DISC_LOGI(DISC_BLE, "enter");
    uintptr_t key = (uintptr_t)args;
    if (msg->what == PROCESS_TIME_OUT && msg->arg1 == key) {
        DISC_LOGI(DISC_BLE, "find key");
        return 0;
    }
    DISC_LOGI(DISC_BLE, "not find key");
    return 1;
}

static RecvMessage *GetRecvMessage(const char *key)
{
    RecvMessage *msg = NULL;
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        if (memcmp((void *)key, (void *)msg->key, SHA_HASH_LEN) == 0) {
            return msg;
        }
    }
    return NULL;
}

static int32_t MatchRecvMessage(const uint32_t *publishInfoMap, uint32_t *capBitMap, uint32_t len)
{
    (void)SoftBusMutexLock(&g_recvMessageInfo.lock);
    RecvMessage *msg = NULL;
    DISC_LOGI(DISC_BLE, "recv message cnt=%d", g_recvMessageInfo.numNeedResp);
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        for (uint32_t index = 0; index < len; index++) {
            capBitMap[index] = msg->capBitMap[index] & publishInfoMap[index];
        }
    }
    (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    return SOFTBUS_OK;
}

static void StartTimeout(const char *key)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return;
    }
    if (GetRecvMessage(key) == NULL) {
        DISC_LOGE(DISC_BLE, "key is not exists");
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        return;
    }
    SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    SoftBusMessage *msg = CreateBleHandlerMsg(PROCESS_TIME_OUT, (uintptr_t)key, 0, NULL);
    if (msg == NULL) {
        DISC_LOGE(DISC_BLE, "malloc msg failed");
        return;
    }
    g_discBleHandler.looper->PostMessageDelay(g_discBleHandler.looper, msg, BLE_MSG_TIME_OUT);
}

static void RemoveTimeout(const char *key)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return;
    }
    if (GetRecvMessage(key) == NULL) {
        DISC_LOGI(DISC_BLE, "key is not in recv message");
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        return;
    }
    SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler, MessageRemovePredicate,
                                                 (void *)key);
}

static uint32_t RecvMsgAggregateCap(void)
{
    RecvMessage *msg = NULL;
    uint32_t revMessageCap = 0;
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        for (uint32_t index = 0; index < CAPABILITY_NUM; index++) {
            revMessageCap = msg->capBitMap[index] | revMessageCap;
        }
    }
    return revMessageCap;
}

static int32_t AddRecvMessage(const char *key, const uint32_t *capBitMap, bool needBrMac)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t oldAggregateCap = RecvMsgAggregateCap();
    RecvMessage *recvMsg = GetRecvMessage(key);
    if (recvMsg == NULL) {
        DISC_LOGI(DISC_BLE, "key is not exit");
        recvMsg = (RecvMessage *)SoftBusCalloc(sizeof(RecvMessage));
        if (recvMsg == NULL) {
            DISC_LOGE(DISC_BLE, "malloc recv msg failed");
            SoftBusMutexUnlock(&g_recvMessageInfo.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(&recvMsg->key, SHA_HASH_LEN, key, SHA_HASH_LEN) != EOK) {
            DISC_LOGE(DISC_BLE, "copy key to create recv msg failed");
            SoftBusFree(recvMsg);
            SoftBusMutexUnlock(&g_recvMessageInfo.lock);
            return SOFTBUS_MEM_ERR;
        }
        for (uint32_t index = 0; index < CAPABILITY_NUM; index++) {
            recvMsg->capBitMap[index] = capBitMap[index];
        }
        recvMsg->needBrMac = needBrMac;
        g_recvMessageInfo.numNeedBrMac++;
        g_recvMessageInfo.numNeedResp++;
        ListTailInsert(&g_recvMessageInfo.node, &recvMsg->node);
        uint32_t newAggregateCap = RecvMsgAggregateCap();
        if (oldAggregateCap != newAggregateCap) {
            UpdateInfoManager(NON_ADV_ID, true);
        }
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    } else {
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        RemoveTimeout(recvMsg->key);
    }
    StartTimeout(recvMsg->key);
    return SOFTBUS_OK;
}

static void RemoveRecvMessage(uint64_t key)
{
    DISC_LOGI(DISC_BLE, "enter");
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != 0) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return;
    }

    RecvMessage *msg = GetRecvMessage((char *)(uintptr_t)key);
    if (msg == NULL) {
        DISC_LOGE(DISC_BLE, "not find message");
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        return;
    }

    g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler, MessageRemovePredicate,
                                                 (void *)key);
    if (msg->needBrMac) {
        g_recvMessageInfo.numNeedBrMac--;
    }
    g_recvMessageInfo.numNeedResp--;
    ListDelete(&msg->node);
    SoftBusFree(msg);
    SoftBusMutexUnlock(&g_recvMessageInfo.lock);
}

static void ClearRecvMessage(void)
{
    ListNode *head = &(g_recvMessageInfo.node);
    while (!IsListEmpty(head)) {
        RecvMessage *msg = LIST_ENTRY(head->next, RecvMessage, node);
        ListDelete(&msg->node);
        SoftBusFree(msg);
    }
}

static void ProcessTimeout(SoftBusMessage *msg)
{
    DISC_LOGI(DISC_BLE, "enter");
    RemoveRecvMessage(msg->arg1);
    UpdateAdvertiser(NON_ADV_ID);
}

static void DiscBleMsgHandler(SoftBusMessage *msg)
{
    switch (msg->what) {
        case PUBLISH_ACTIVE_SERVICE:
            StartActivePublish(msg);
            break;
        case PUBLISH_PASSIVE_SERVICE:
            StartPassivePublish(msg);
            break;
        case UNPUBLISH_SERVICE:
            if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
                UpdateAdvertiser(NON_ADV_ID);
            }
            StartScaner();
            break;
        case START_ACTIVE_DISCOVERY:
            StartActiveDiscovery(msg);
            break;
        case START_PASSIVE_DISCOVERY:
            StartPassiveDiscovery(msg);
            break;
        case STOP_DISCOVERY:
            if (g_bleAdvertiser[CON_ADV_ID].isAdvertising) {
                UpdateAdvertiser(CON_ADV_ID);
            } else {
                StartAdvertiser(CON_ADV_ID);
            }
            (void)StartScaner();
            break;
        case REPLY_PASSIVE_NON_BROADCAST:
            StartAdvertiser(NON_ADV_ID);
            break;
        case PROCESS_TIME_OUT:
            ProcessTimeout(msg);
            break;
        case RECOVERY:
            Recovery(msg);
            break;
        case TURN_OFF:
            BleDiscTurnOff(msg);
            break;
        default:
            DISC_LOGW(DISC_BLE, "wrong msg what=%d", msg->what);
            break;
    }
}

static int32_t DiscBleLooperInit(void)
{
    g_discBleHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_discBleHandler.looper == NULL) {
        DISC_LOGE(DISC_INIT, "get looper fail");
        return SOFTBUS_ERR;
    }

    g_discBleHandler.name = (char *)"ble_disc_handler";
    g_discBleHandler.HandleMessage = DiscBleMsgHandler;
    return SOFTBUS_OK;
}

static void DiscFreeBleScanFilter(SoftBusBleScanFilter *filter)
{
    if (filter) {
        SoftBusFree(filter->serviceData);
        SoftBusFree(filter->serviceDataMask);
        SoftBusFree(filter);
    }
}

static void DiscBleSetScanFilter(int32_t listenerId)
{
    SoftBusBleScanFilter *filter = (SoftBusBleScanFilter *)SoftBusCalloc(sizeof(SoftBusBleScanFilter));
    DISC_CHECK_AND_RETURN_LOGW(filter != NULL, DISC_BLE, "malloc filter failed");

    filter->serviceData = (uint8_t *)SoftBusCalloc(BLE_SCAN_FILTER_LEN);
    filter->serviceDataMask = (uint8_t *)SoftBusCalloc(BLE_SCAN_FILTER_LEN);
    if (filter->serviceData == NULL || filter->serviceDataMask == NULL) {
        DISC_LOGE(DISC_BLE, "malloc filter data failed");
        DiscFreeBleScanFilter(filter);
        return;
    }

    filter->serviceDataLength = BLE_SCAN_FILTER_LEN;
    filter->serviceData[0] = BLE_UUID & BYTE_MASK;
    filter->serviceData[1] = (BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK;
    filter->serviceData[UUID_LEN + POS_VERSION] = BLE_VERSION;
    filter->serviceData[UUID_LEN + POS_BUSINESS] = DISTRIBUTE_BUSINESS;
    filter->serviceDataMask[0] = BYTE_MASK;
    filter->serviceDataMask[1] = BYTE_MASK;
    filter->serviceDataMask[UUID_LEN + POS_VERSION] = BYTE_MASK;
    filter->serviceDataMask[UUID_LEN + POS_BUSINESS] = BYTE_MASK;

    if (SoftBusSetScanFilter(listenerId, filter, 1) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "set scan filter failed");
        DiscFreeBleScanFilter(filter);
    }
}

static int32_t InitBleListener(void)
{
    g_bleListener.scanListenerId = SoftBusAddScanListener(&g_scanListener, &g_bleScannerId, false);
    g_bleListener.stateListenerId = SoftBusAddBtStateListener(&g_stateChangedListener);
    if (g_bleListener.stateListenerId < 0 || g_bleListener.scanListenerId < 0) {
        return SOFTBUS_ERR;
    }
    DiscBleSetScanFilter(g_bleListener.scanListenerId);
    return SOFTBUS_OK;
}

DiscoveryBleDispatcherInterface *DiscSoftBusBleInit(DiscInnerCallback *callback)
{
    DISC_LOGI(DISC_INIT, "enter");
    if (callback == NULL || callback->OnDeviceFound == NULL) {
        DISC_LOGE(DISC_INIT, "callback invalid.");
        return NULL;
    }

    ListInit(&g_recvMessageInfo.node);
    g_discBleInnerCb = callback;

    if (SoftBusMutexInit(&g_recvMessageInfo.lock, NULL) != SOFTBUS_OK ||
        SoftBusMutexInit(&g_bleInfoLock, NULL) != SOFTBUS_OK || BleGattLockInit() != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "init ble lock failed");
        return NULL;
    }

    DiscBleInitPublish();
    DiscBleInitSubscribe();
    InitScanner();

    if (DiscBleLooperInit() != SOFTBUS_OK || InitBleListener() != SOFTBUS_OK || InitAdvertiser() != SOFTBUS_OK)  {
        DiscSoftBusBleDeinit();
        return NULL;
    }

    SoftBusRegDiscVarDump((char *)BLE_INFO_MANAGER, &BleInfoDump);
    SoftBusRegDiscVarDump((char *)BlE_ADVERTISER, &BleAdvertiserDump);
    SoftBusRegDiscVarDump((char *)RECV_MESSAGE_INFO, &RecvMessageInfoDump);

    DISC_LOGI(DISC_INIT, "success");
    return &g_discBleDispatcherInterface;
}

static bool CheckLockInit(SoftBusMutex *lock)
{
    if (SoftBusMutexLock(lock) != 0) {
        return false;
    }
    SoftBusMutexUnlock(lock);
    return true;
}

static void RecvMessageDeinit(void)
{
    ClearRecvMessage();
    if (CheckLockInit(&g_recvMessageInfo.lock)) {
        (void)SoftBusMutexDestroy(&g_recvMessageInfo.lock);
    }
    g_recvMessageInfo.numNeedBrMac = 0;
    g_recvMessageInfo.numNeedResp = 0;
}

static void AdvertiserDeinit(void)
{
    (void)SoftBusReleaseAdvChannel(g_bleAdvertiser[CON_ADV_ID].channel);
    (void)SoftBusReleaseAdvChannel(g_bleAdvertiser[NON_ADV_ID].channel);
    for (uint32_t index = 0; index < NUM_ADVERTISER; index++) {
        (void)memset_s(&g_bleAdvertiser[index], sizeof(DiscBleAdvertiser), 0x0, sizeof(DiscBleAdvertiser));
    }
}

static void BleListenerDeinit(void)
{
    (void)SoftBusRemoveBtStateListener(g_bleListener.stateListenerId);
    (void)SoftBusRemoveScanListener(g_bleListener.scanListenerId);
    (void)SoftBusDeregisterScanCallbacks(g_bleScannerId);
}

static void DiscBleInfoDeinit(void)
{
    for (uint32_t index = 0; index < BLE_INFO_COUNT; index++) {
        (void)memset_s(&g_bleInfoManager[index], sizeof(DiscBleInfo), 0x0, sizeof(DiscBleInfo));
    }
}

void DiscSoftBusBleDeinit(void)
{
    if (g_isScanning) {
        (void)StopScaner();
    }
    g_discBleInnerCb = NULL;
    BleListenerDeinit();
    RecvMessageDeinit();
    DiscBleInfoDeinit();
    AdvertiserDeinit();
}

static int32_t BleInfoDump(int fd)
{
    if (SoftBusMutexLock(&g_bleInfoLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    SOFTBUS_DPRINTF(fd, "-----------------BleInfoManager Info-------------------\n");
    for (int i = 0; i < BLE_INFO_COUNT; i++) {
        SOFTBUS_DPRINTF(fd, "BleInfo needUpdate                      : %d\n", g_bleInfoManager[i].needUpdate);
        SOFTBUS_DPRINTF(fd, "BleInfo capBitMap                       : %u\n", *(g_bleInfoManager[i].capBitMap));
        SOFTBUS_DPRINTF(fd, "BleInfo capCount                        : %d\n", *(g_bleInfoManager[i].capCount));
        SOFTBUS_DPRINTF(fd, "BleInfo capabilityData                  : %s\n", *(g_bleInfoManager[i].capabilityData));
        SOFTBUS_DPRINTF(fd, "BleInfo capDataLen                      : %u\n", *(g_bleInfoManager[i].capDataLen));
        SOFTBUS_DPRINTF(fd, "BleInfo isSameAccount                   : %d\n", *(g_bleInfoManager[i].isSameAccount));
        SOFTBUS_DPRINTF(fd, "BleInfo isWakeRemote                    : %d\n", *(g_bleInfoManager[i].isWakeRemote));
        SOFTBUS_DPRINTF(fd, "BleInfo freq                            : %d\n", *(g_bleInfoManager[i].freq));
        SOFTBUS_DPRINTF(fd, "BleInfo rangingRefCnt                   : %d\n", g_bleInfoManager[i].rangingRefCnt);
    }
    (void)SoftBusMutexUnlock(&g_bleInfoLock);
    return SOFTBUS_OK;
}

static int32_t BleAdvertiserDump(int fd)
{
    char bleMac[BT_MAC_LEN] = {0};
    char hash[UDID_HASH_LEN] = {0};
    char peerUid[MAX_ACCOUNT_HASH_LEN] = {0};
    SOFTBUS_DPRINTF(fd, "\n-----------------BleAdvertiser Info-------------------\n");
    for (int i = 0; i < NUM_ADVERTISER; i++) {
        SOFTBUS_DPRINTF(fd, "BleAdvertiser channel                   : %d\n", g_bleAdvertiser[i].channel);
        SOFTBUS_DPRINTF(fd, "BleAdvertiser isAdvertising             : %d\n", g_bleAdvertiser[i].isAdvertising);
        SOFTBUS_DPRINTF(fd, "DeviceInfo                              : \n");
        SOFTBUS_DPRINTF(fd, "devId                                   : %s\n", g_bleAdvertiser[i].deviceInfo.devId);
        SOFTBUS_DPRINTF(fd, "accountHash                             : %s\n",
            g_bleAdvertiser[i].deviceInfo.accountHash);
        SOFTBUS_DPRINTF(fd, "devType                                 : %u\n", g_bleAdvertiser[i].deviceInfo.devType);
        SOFTBUS_DPRINTF(fd, "devName                                 : %s\n", g_bleAdvertiser[i].deviceInfo.devName);
        SOFTBUS_DPRINTF(fd, "addrNum                                 : %u\n", g_bleAdvertiser[i].deviceInfo.addrNum);
        SOFTBUS_DPRINTF(fd, "addr type                               : %u\n",
                g_bleAdvertiser[i].deviceInfo.addr[CONNECTION_ADDR_BLE].type);
        DataMasking(g_bleAdvertiser[i].deviceInfo.addr[CONNECTION_ADDR_BLE].info.ble.bleMac,
                    BT_MAC_LEN, MAC_DELIMITER, bleMac);
        SOFTBUS_DPRINTF(fd, "Connection bleMac                       : %s\n", bleMac);
        DataMasking((char *)(g_bleAdvertiser[i].deviceInfo.addr[CONNECTION_ADDR_BLE].info.ble.udidHash),
                    UDID_HASH_LEN, ID_DELIMITER, hash);
        SOFTBUS_DPRINTF(fd, "Connection bleHash                      : %s\n", hash);
        DataMasking(g_bleAdvertiser[i].deviceInfo.addr[CONNECTION_ADDR_BLE].peerUid,
                    MAX_ACCOUNT_HASH_LEN, ID_DELIMITER, peerUid);
        SOFTBUS_DPRINTF(fd, "Connection peerUid                      : %s\n", peerUid);
        SOFTBUS_DPRINTF(fd, "capabilityBitmapNum                     : %u\n",
                g_bleAdvertiser[i].deviceInfo.capabilityBitmapNum);
        SOFTBUS_DPRINTF(fd, "capabilityBitmap                        : %u\n",
                *(g_bleAdvertiser[i].deviceInfo.capabilityBitmap));
        SOFTBUS_DPRINTF(fd, "custData                                : %s\n", g_bleAdvertiser[i].deviceInfo.custData);
        SOFTBUS_DPRINTF(fd, "range                                   : %d\n", g_bleAdvertiser[i].deviceInfo.range);
    }
    return SOFTBUS_OK;
}

static int32_t RecvMessageInfoDump(int fd)
{
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ListNode *item = NULL;
    SOFTBUS_DPRINTF(fd, "\n-----------------RecvMessage Info-------------------\n");
    SOFTBUS_DPRINTF(fd, "RecvMessageInfo numNeedBrMac           : %u\n", g_recvMessageInfo.numNeedBrMac);
    SOFTBUS_DPRINTF(fd, "RecvMessageInfo numNeedResp            : %u\n", g_recvMessageInfo.numNeedResp);
    LIST_FOR_EACH(item, &g_recvMessageInfo.node)
    {
        RecvMessage *recvNode = LIST_ENTRY(item, RecvMessage, node);
        SOFTBUS_DPRINTF(fd, "RecvMessage capBitMap                  : %u\n", recvNode->capBitMap[0]);
        SOFTBUS_DPRINTF(fd, "RecvMessage key                        : %s\n", recvNode->key);
        SOFTBUS_DPRINTF(fd, "needBrMac                              : %d\n", recvNode->needBrMac);
    }
    (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    return SOFTBUS_OK;
}
