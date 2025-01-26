/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "broadcast_scheduler.h"
#include "broadcast_dfx_event.h"
#include "common_list.h"
#include "disc_ble_constant.h"
#include "disc_ble_utils.h"
#include "disc_event.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "lnn_device_info.h"
#include "lnn_ohos_account.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_range.h"
#include "softbus_bitmap.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_disc.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "softbus_json_utils.h"
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

typedef enum {
    CON_FILTER_TYPE = 1,
    NON_FILTER_TYPE = 2,
    MAX_FILTER_TYPE,
} DicsBleFilterType;

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
    DFX_DELAY_RECORD,
    BR_STATE_CHANGED,
} DiscBleMessage;

typedef enum {
    CAST_EVENT,
    OSD_EVENT,
    DVKIT_EVENT,
} EventType;
 
typedef enum {
    CAST_EVENT_CON,
    CAST_EVENT_NON,
    OSD_EVENT_CON,
    OSD_EVENT_NON,
    DVKIT_EVENT_CON,
    DVKIT_EVENT_NON,
    MAX_DISC_EVENT,
} DiscBleEventType;
 
typedef enum {
    SCAN_CAST_EVENT,
    SCAN_DVKIT_EVENT,
    SCAN_OSD_EVENT,
    MAX_SCAN_EVENT,
} ScanBleEventType;

typedef struct {
    bool isAdvertising;
    int32_t channel;
    DeviceInfo deviceInfo;
    int32_t (*GetDeviceInfo)(DeviceInfo *info);
} DiscBleAdvertiser;

typedef struct {
    bool needUpdate;
    bool needUpdateCap;
    int16_t capCount[CAPABILITY_MAX_BITNUM];
    uint32_t capBitMap[CAPABILITY_NUM];
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
    {SOFTBUS_BC_SCAN_WINDOW_P2, SOFTBUS_BC_SCAN_INTERVAL_P2},
    {SOFTBUS_BC_SCAN_WINDOW_P10, SOFTBUS_BC_SCAN_INTERVAL_P10},
    {SOFTBUS_BC_SCAN_WINDOW_P25, SOFTBUS_BC_SCAN_INTERVAL_P25},
    {SOFTBUS_BC_SCAN_WINDOW_P75, SOFTBUS_BC_SCAN_INTERVAL_P75},
    {SOFTBUS_BC_SCAN_WINDOW_P100, SOFTBUS_BC_SCAN_INTERVAL_P100}
};

static DiscInnerCallback *g_discBleInnerCb = NULL;
static DiscBleInfo g_bleInfoManager[BLE_INFO_COUNT];
static SoftBusMutex g_bleInfoLock = {0};
static DiscBleAdvertiser g_bleAdvertiser[NUM_ADVERTISER];
static bool g_isScanning = false;
static SoftBusHandler g_discBleHandler = {};
static RecvMessageInfo g_recvMessageInfo = {};
static DiscBleListener g_bleListener = {
    .stateListenerId = -1,
    .scanListenerId = -1
};

static DiscEventExtra g_bleDiscExtra[MAX_DISC_EVENT] = {};
static DiscEventExtra g_bleScanExtra[MAX_SCAN_EVENT] = {};
static uint32_t g_bleOldCap = 0;

// g_conncernCapabilityMask support capability of this ble discovery
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
static void DiscBleSetScanFilter(int32_t listenerId, int32_t type);
static void BleEventExtraInit(void);
static void CalcDurationTime(int32_t adv, uint32_t capabilityBitmap);
static void CalcCount(int32_t adv, uint32_t capabilityBitmap, bool result);

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

static void DeConvertBitMap(uint32_t *dstCap, uint32_t *srcCap, int nums)
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
    DISC_LOGD(DISC_BLE, "old=%{public}u, new=%{public}u", *srcCap, *dstCap);
}

static void UpdateInfoManager(int adv, bool needUpdate)
{
    DISC_LOGI(DISC_CONTROL, "enter");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK, DISC_BLE, "lock failed");
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

static void UpdateScannerInfoManager(int32_t type, bool needUpdate)
{
    DISC_LOGD(DISC_BLE, "enter");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK, DISC_BLE, "lock failed");
    if (type == CON_FILTER_TYPE) {
        g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdateCap = needUpdate;
    } else if (type == NON_FILTER_TYPE) {
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdateCap = needUpdate;
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdateCap = needUpdate;
    } else if (type == (CON_FILTER_TYPE | NON_FILTER_TYPE)) {
        g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdateCap = needUpdate;
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdateCap = needUpdate;
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdateCap = needUpdate;
    }
    SoftBusMutexUnlock(&g_bleInfoLock);
}

static bool GetNeedUpdateScanner(int32_t type)
{
    if (type == CON_FILTER_TYPE) {
        return g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdateCap;
    } else if (type == NON_FILTER_TYPE) {
        return g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdateCap ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdateCap;
    } else if (type == (CON_FILTER_TYPE | NON_FILTER_TYPE)) {
        return g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdateCap ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdateCap ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdateCap;
    }
    return false;
}

static void BleAdvEnableCallback(int channel, int status)
{
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        for (int32_t i = 0; i < NUM_ADVERTISER; i++) {
            if (g_bleAdvertiser[i].channel == channel) {
                g_bleAdvertiser[i].isAdvertising = true;
                DISC_LOGI(DISC_BLE, "enable ble advertiser adv=%{public}d", i);
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
                DISC_LOGI(DISC_BLE, "disable ble advertiser adv=%{public}d", i);
            }
        }
    }
}

static void BleAdvDataCallback(int channel, int status)
{
    DISC_LOGI(DISC_BLE, "channel=%{public}d, status=%{public}d", channel, status);
}

static void BleAdvUpdateCallback(int channel, int status)
{
    DISC_LOGI(DISC_BLE, "channel=%{public}d, status=%{public}d", channel, status);
}

static int32_t GetScannerFilterType(void)
{
    int32_t type = 0;
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BLE, "lock failed");
    uint32_t conScanCapBit = g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0];
    uint32_t nonScanCapBit = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0];
    (void)SoftBusMutexUnlock(&g_bleInfoLock);

    if (conScanCapBit != 0 && nonScanCapBit != 0) {
        type = (CON_FILTER_TYPE | NON_FILTER_TYPE);
    } else if (conScanCapBit != 0 && nonScanCapBit == 0) {
        type = CON_FILTER_TYPE;
    } else if (conScanCapBit == 0 && nonScanCapBit != 0) {
        type = NON_FILTER_TYPE;
    }
    return type;
}

static bool CheckScanner(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK,
        false, DISC_BLE, "lock failed");
    uint32_t scanCapBit = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0];
    (void)SoftBusMutexUnlock(&g_bleInfoLock);
    return scanCapBit != 0;
}

static int32_t ScanFilter(const BroadcastReportInfo *reportInfo)
{
    uint32_t advLen = reportInfo->packet.bcData.payloadLen;
    uint8_t *advData = reportInfo->packet.bcData.payload;

    DISC_CHECK_AND_RETURN_RET_LOGE(reportInfo->dataStatus == SOFTBUS_BC_DATA_COMPLETE,
        SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
        "dataStatus is invalid. dataStatus=%{public}u", reportInfo->dataStatus);
    DISC_CHECK_AND_RETURN_RET_LOGE(advData != NULL, SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
        "advData is null");
    DISC_CHECK_AND_RETURN_RET_LOGE(advLen >= POS_TLV, SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
        "advLen is too short, less than adv header length. advLen=%{public}u", advLen);

    DISC_CHECK_AND_RETURN_RET_LOGE(reportInfo->packet.bcData.type == BC_DATA_TYPE_SERVICE,
        SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
        "type is invalid. type=%{public}u", reportInfo->packet.bcData.type);
    DISC_CHECK_AND_RETURN_RET_LOGE(reportInfo->packet.bcData.id == SERVICE_UUID,
        SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
        "uuid is invalid. id=%{public}u", reportInfo->packet.bcData.id);
    DISC_CHECK_AND_RETURN_RET_LOGE(advData[POS_VERSION] == BLE_VERSION, SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL,
        DISC_BLE, "adv version is invalid. advVersion=%{public}hhu", advData[POS_VERSION]);
    if (reportInfo->packet.rspData.payload != NULL && reportInfo->packet.rspData.payloadLen != 0) {
        DISC_CHECK_AND_RETURN_RET_LOGE(reportInfo->packet.rspData.type == BC_DATA_TYPE_MANUFACTURER,
            SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
            "type is invalid. type=%{public}u", reportInfo->packet.rspData.type);
        DISC_CHECK_AND_RETURN_RET_LOGE(reportInfo->packet.rspData.id == MANU_COMPANY_ID,
            SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL, DISC_BLE,
            "companyId is invalid. companyId=%{public}u", reportInfo->packet.rspData.id);
    }

    if (!CheckScanner()) {
        DISC_LOGI(DISC_BLE, "no need to scan");
        (void)StopScaner();
        return SOFTBUS_DISCOVER_BLE_REPORT_FILTER_FAIL;
    }
    return SOFTBUS_OK;
}

static void ProcessDisConPacket(const BroadcastReportInfo *reportInfo, DeviceInfo *foundInfo)
{
    static uint32_t callCount = 0;
    DeviceWrapper device = {
        .info = foundInfo,
        .power = SOFTBUS_ILLEGAL_BLE_POWER
    };
    int32_t ret = GetDeviceInfoFromDisAdvData(&device, (uint8_t *)reportInfo, sizeof(BroadcastReportInfo));
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "GetDeviceInfoFromDisAdvData failed, ret=%{public}d", ret);
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK, DISC_BLE, "lock failed");
    if ((foundInfo->capabilityBitmap[0] & g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0]) == 0x0) {
        DISC_LOGD(DISC_BLE, "don't match passive publish capBitMap, callCount=%{public}u", callCount++);
        (void)SoftBusMutexUnlock(&g_bleInfoLock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_bleInfoLock);
    char key[SHA_HASH_LEN];
    ret = SoftBusGenerateStrHash(reportInfo->packet.bcData.payload,
        reportInfo->packet.bcData.payloadLen, (uint8_t *)key);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "GenerateStrHash failed, ret=%{public}d", ret);
    if (AddRecvMessage(key, foundInfo->capabilityBitmap, true) == SOFTBUS_OK) {
        ReplyPassiveNonBroadcast();
    }
}

static bool ProcessHashAccount(DeviceInfo *foundInfo)
{
    int32_t ret;
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (!CheckCapBitMapExist(CAPABILITY_NUM, foundInfo->capabilityBitmap, pos)) {
            continue;
        }
        if (!(g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] ||
            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].isSameAccount[pos])) {
            return true;
        }
        uint8_t accountIdHash[SHORT_USER_ID_HASH_LEN] = {0};
        ret = DiscBleGetShortUserIdHash(accountIdHash, SHORT_USER_ID_HASH_LEN);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false,
            DISC_BLE, "DiscBleGetShortUserIdHash error, ret=%{public}d", ret);
        DISC_CHECK_AND_RETURN_RET_LOGE(!LnnIsDefaultOhosAccount(), false,
            DISC_BLE, "LnnIsDefaultOhosAccount, not the same account.");
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
    int32_t ret = ConvertBtMacToStr(bleMac, BT_MAC_LEN, (uint8_t *)foundInfo->addr[0].info.ble.bleMac, BT_ADDR_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "convert ble mac to string failed");
    errno_t retMem = memset_s(foundInfo->addr[0].info.ble.bleMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(retMem == EOK, SOFTBUS_MEM_ERR, DISC_BLE, "memset ble mac failed");
    retMem = memcpy_s(foundInfo->addr[0].info.ble.bleMac, BT_MAC_LEN, bleMac, BT_MAC_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(retMem == EOK, SOFTBUS_MEM_ERR, DISC_BLE, "memcopy ble mac failed");
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
        errno_t retMem = memcpy_s(param.identity, SOFTBUS_DEV_IDENTITY_LEN,
            device->addr[0].info.ble.bleMac, BT_MAC_LEN);
        DISC_CHECK_AND_RETURN_RET_LOGE(retMem == EOK, SOFTBUS_MEM_ERR, DISC_BLE, "memcpy failed");

        int ret = SoftBusBleRange(&param, &range);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "range device failed, ret=%{public}d", ret);
            range = -1;
            // range failed should report device continually
        }
    }
    device->range = range;
    return SOFTBUS_OK;
}

static void ProcessDisNonPacket(const BroadcastReportInfo *reportInfo, char rssi, DeviceInfo *foundInfo)
{
    static uint32_t callCount = 0;
    DeviceWrapper device = {
        .info = foundInfo,
        .power = SOFTBUS_ILLEGAL_BLE_POWER
    };
    int32_t ret = GetDeviceInfoFromDisAdvData(&device, (uint8_t *)reportInfo, sizeof(BroadcastReportInfo));
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "GetDeviceInfoFromDisAdvData failed, ret=%{public}d", ret);
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
    ret = ConvertBleAddr(foundInfo);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "convert ble address failed, ret=%{public}d", ret);
    ret = RangeDevice(foundInfo, rssi, device.power);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "range device failed, ret=%{public}d", ret);

    InnerDeviceInfoAddtions add;
    add.medium = BLE;

    if (ProcessHashAccount(foundInfo)) {
        char *anonyLocalBleMac = NULL;
        Anonymize(foundInfo->addr[0].info.ble.bleMac, &anonyLocalBleMac);
        DISC_LOGI(DISC_BLE, "start report found device, addrNum=%{public}u, addr[0].type=%{public}u,"
            "capabilityBitmap=%{public}u, bleMac=%{public}s, callCount=%{public}u", foundInfo->addrNum,
            foundInfo->addr[0].type, foundInfo->capabilityBitmap[0], AnonymizeWrapper(anonyLocalBleMac), callCount++);
        AnonymizeFree(anonyLocalBleMac);
        uint32_t tempCap = 0;
        DeConvertBitMap(&tempCap, foundInfo->capabilityBitmap, foundInfo->capabilityBitmapNum);
        DISC_CHECK_AND_RETURN_LOGE(tempCap != 0, DISC_BLE, "unsupported ble capability. capabilityBitmap=%{public}d",
            foundInfo->capabilityBitmap[0]);
        foundInfo->capabilityBitmap[0] = tempCap;
        foundInfo->capabilityBitmapNum = 1;
        g_discBleInnerCb->OnDeviceFound(foundInfo, &add);
        SoftbusRecordDiscBleRssi(*(signed char *)(&rssi));
    }
}

static void ProcessDistributePacket(const BroadcastReportInfo *reportInfo)
{
    uint32_t advLen = reportInfo->packet.bcData.payloadLen;
    uint8_t *advData = reportInfo->packet.bcData.payload;
    DeviceInfo foundInfo;

    DISC_CHECK_AND_RETURN_LOGE(advData != NULL && advLen > POS_BUSINESS_EXTENSION,
        DISC_BLE, "scan report data null, len=%{public}d", advLen);
    (void)memset_s(&foundInfo, sizeof(foundInfo), 0, sizeof(foundInfo));
    foundInfo.addrNum = 1;
    foundInfo.addr[0].type = CONNECTION_ADDR_BLE;
    errno_t retMem = memcpy_s(foundInfo.addr[0].info.ble.bleMac, BT_ADDR_LEN, reportInfo->addr.addr, BC_ADDR_MAC_LEN);
    DISC_CHECK_AND_RETURN_LOGE(retMem == EOK, DISC_BLE, "memcpy_s failed");
    if ((advData[POS_BUSINESS_EXTENSION] & BIT_HEART_BIT) != 0) {
        return;
    }
    if ((advData[POS_BUSINESS_EXTENSION] & BIT_CON) != 0) {
        ProcessDisConPacket(reportInfo, &foundInfo);
    } else {
        ProcessDisNonPacket(reportInfo, reportInfo->rssi, &foundInfo);
    }
}

static void AccumulateBleScanNum(uint32_t capabilityBitmap)
{
    uint32_t tempCap = 0;
    DeConvertBitMap(&tempCap, &capabilityBitmap, 1);
    if (tempCap & 1 << CASTPLUS_CAPABILITY_BITMAP) {
        g_bleScanExtra[SCAN_CAST_EVENT].scanCount++;
    }
    if (tempCap & 1 << DVKIT_CAPABILITY_BITMAP) {
        g_bleScanExtra[SCAN_DVKIT_EVENT].scanCount++;
    }
    if (tempCap & 1 << OSD_CAPABILITY_BITMAP) {
        g_bleScanExtra[SCAN_OSD_EVENT].scanCount++;
    }
}

static void BleScanResultCallback(int listenerId, const BroadcastReportInfo *reportInfo)
{
    (void)listenerId;
    DISC_CHECK_AND_RETURN_LOGE(listenerId == g_bleListener.scanListenerId, DISC_BLE, "listenerId not match");
    DISC_CHECK_AND_RETURN_LOGE(reportInfo != NULL, DISC_BLE, "scan result is null");
    DISC_CHECK_AND_RETURN_LOGD(ScanFilter(reportInfo) == SOFTBUS_OK, DISC_BLE, "scan filter failed");

    uint8_t *advData = reportInfo->packet.bcData.payload;
    if ((reportInfo->packet.bcData.id == SERVICE_UUID) && (advData[POS_BUSINESS] == DISTRIBUTE_BUSINESS)) {
        SignalingMsgPrint("ble adv rcv", advData, reportInfo->packet.bcData.payloadLen, DISC_BLE);
        ProcessDistributePacket(reportInfo);
        AccumulateBleScanNum((uint32_t)advData[POS_CAPABLITY]);
    } else {
        DISC_LOGI(DISC_BLE, "ignore other business");
    }
}

static void BleOnScanStart(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGD(DISC_BLE, "BleOnScanStart");
    g_isScanning = true;
}

static void BleOnScanStop(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    DISC_LOGD(DISC_BLE, "BleOnScanStop");
    g_isScanning = false;
}

static void BtOnStateChanged(int32_t listenerId, int32_t state)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.bleTurnState = state;
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_STATE_TURN, extra);
    (void)listenerId;
    SoftBusMessage *msg = NULL;
    switch (state) {
        case SOFTBUS_BLE_STATE_TURN_ON:
            DISC_LOGI(DISC_CONTROL, "ble turn on");
            msg = CreateBleHandlerMsg(RECOVERY, 0, 0, NULL);
            break;
        case SOFTBUS_BLE_STATE_TURN_OFF:
            DISC_LOGI(DISC_CONTROL, "ble turn off");
            msg = CreateBleHandlerMsg(TURN_OFF, 0, 0, NULL);
            break;
        case SOFTBUS_BR_STATE_TURN_ON:
            DISC_LOGI(DISC_CONTROL, "br turn on");
            msg = CreateBleHandlerMsg(BR_STATE_CHANGED, SOFTBUS_BR_STATE_TURN_ON, 0, NULL);
            break;
        case SOFTBUS_BR_STATE_TURN_OFF:
            DISC_LOGI(DISC_CONTROL, "br turn off");
            msg = CreateBleHandlerMsg(BR_STATE_CHANGED, SOFTBUS_BR_STATE_TURN_OFF, 0, NULL);
            break;
        default:
            return;
    }
    DISC_CHECK_AND_RETURN_LOGE(msg != NULL, DISC_CONTROL, "create msg failed");
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
}

static BroadcastCallback g_advCallback = {
    .OnStartBroadcastingCallback = BleAdvEnableCallback,
    .OnStopBroadcastingCallback = BleAdvDisableCallback,
    .OnSetBroadcastingCallback = BleAdvDataCallback,
    .OnUpdateBroadcastingCallback = BleAdvUpdateCallback,
};

static ScanCallback g_scanListener = {
    .OnStartScanCallback = BleOnScanStart,
    .OnStopScanCallback = BleOnScanStop,
    .OnReportScanDataCallback = BleScanResultCallback,
};

static SoftBusBtStateListener g_stateChangedListener = {
    .OnBtStateChanged = BtOnStateChanged,
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

static int32_t DiscBleGetCustData(DeviceInfo *info)
{
    uint32_t infoIndex = BLE_PUBLISH | BLE_PASSIVE;
    uint32_t pos = 0;
    for (pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (CheckCapBitMapExist(CAPABILITY_NUM, g_bleInfoManager[infoIndex].capBitMap, pos)) {
            break;
        }
    }
    DISC_CHECK_AND_RETURN_RET_LOGD(
        pos < CAPABILITY_MAX_BITNUM, SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL, DISC_BLE, "not find capBitMap");
    cJSON *json = cJSON_ParseWithLength((const char *)g_bleInfoManager[infoIndex].capabilityData[pos],
        g_bleInfoManager[infoIndex].capDataLen[pos]);
    DISC_CHECK_AND_RETURN_RET_LOGE(json != NULL, SOFTBUS_PARSE_JSON_ERR, DISC_BLE, "parse cJSON failed");

    char custData[DISC_MAX_CUST_DATA_LEN] = {0};
    if (!GetJsonObjectStringItem(json, g_capabilityMap[CASTPLUS_CAPABILITY_BITMAP].capability, custData,
        DISC_MAX_CUST_DATA_LEN)) {
        DISC_LOGE(DISC_BLE, "GetJsonObjectStringItem custData failed, custData=%{public}s", custData);
        cJSON_Delete(json);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (strcpy_s(info->custData, DISC_MAX_CUST_DATA_LEN, custData) != EOK) {
        DISC_LOGE(DISC_BLE, "strcpy_s custData failed");
        cJSON_Delete(json);
        return SOFTBUS_STRCPY_ERR;
    }
    cJSON_Delete(json);
    return SOFTBUS_OK;
}

static int32_t GetConDeviceInfo(DeviceInfo *info)
{
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    uint32_t infoIndex = BLE_SUBSCRIBE | BLE_ACTIVE;
    DISC_CHECK_AND_RETURN_RET_LOGE(!CheckBitMapEmpty(CAPABILITY_NUM, g_bleInfoManager[infoIndex].capBitMap),
        SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL, DISC_BLE, "all capbit is zero");
    if (DiscBleGetDeviceIdHash((uint8_t *)info->devId, DISC_MAX_DEVICE_ID_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceId failed");
    }
    if (DiscBleGetDeviceName(info->devName, sizeof(info->devName)) != SOFTBUS_OK) {
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
    if (isSameAccount) {
        if (!LnnIsDefaultOhosAccount()) {
            DiscBleGetShortUserIdHash((uint8_t *)info->accountHash, SHORT_USER_ID_HASH_LEN);
        } else {
            DISC_LOGW(DISC_BLE, "Account not logged in during same account check");
        }
    }
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] = g_bleInfoManager[infoIndex].capBitMap[pos];
    }
    return SOFTBUS_OK;
}

static int32_t GetNonDeviceInfo(DeviceInfo *info)
{
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    if (DiscBleGetDeviceIdHash((uint8_t *)info->devId, DISC_MAX_DEVICE_ID_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceId failed");
    }

    if (DiscBleGetDeviceName(info->devName, sizeof(info->devName)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceName failed");
    }
    info->devType = (DeviceType)DiscBleGetDeviceType();
    uint32_t passiveCapBitMap[CAPABILITY_NUM] = {0};
    int32_t ret = MatchRecvMessage(g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap,
        passiveCapBitMap, CAPABILITY_NUM);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL,
        DISC_BLE, "MatchRecvMessage failed");
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] =
        g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[pos] | passiveCapBitMap[pos];
    }
    if (DiscBleGetCustData(info) != SOFTBUS_OK) {
        DISC_LOGW(DISC_BLE, "get custData failed");
    }

    int32_t activeCnt = g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].rangingRefCnt;
    int32_t passiveCnt = g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].rangingRefCnt;
    info->range = activeCnt + passiveCnt;

    DISC_CHECK_AND_RETURN_RET_LOGE(!CheckBitMapEmpty(CAPABILITY_NUM, info->capabilityBitmap),
        SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL, DISC_BLE, "all capbit is zero");
    return SOFTBUS_OK;
}

static void DestroyBleConfigAdvData(BroadcastPacket *packet)
{
    SoftBusFree(packet->bcData.payload);
    SoftBusFree(packet->rspData.payload);
    packet->bcData.payload = NULL;
    packet->rspData.payload = NULL;
}

static int32_t BuildBleConfigAdvData(BroadcastPacket *packet, const BroadcastData *broadcastData)
{
    if (packet->bcData.payload != NULL || packet->rspData.payload != NULL) {
        DestroyBleConfigAdvData(packet);
    }
    packet->bcData.payload = (uint8_t *)SoftBusCalloc(ADV_DATA_MAX_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(packet->bcData.payload != NULL, SOFTBUS_MALLOC_ERR,
        DISC_BLE, "malloc serviceData failed");

    packet->isSupportFlag = true;
    packet->flag = FLAG_AD_DATA;
    packet->bcData.type = BC_DATA_TYPE_SERVICE;
    packet->bcData.id = SERVICE_UUID;
    packet->bcData.payloadLen = (broadcastData->dataLen > ADV_DATA_MAX_LEN) ? ADV_DATA_MAX_LEN :
        broadcastData->dataLen;
    if (memcpy_s(&packet->bcData.payload[0], ADV_DATA_MAX_LEN, broadcastData->data.advData,
        packet->bcData.payloadLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy err");
        SoftBusFree(packet->bcData.payload);
        packet->bcData.payload = NULL;
        return SOFTBUS_MEM_ERR;
    }

    packet->rspData.payloadLen = broadcastData->dataLen - packet->bcData.payloadLen;
    if (packet->rspData.payloadLen == 0) {
        packet->rspData.payload = NULL;
        return SOFTBUS_OK;
    }

    packet->rspData.payload = (uint8_t *)SoftBusCalloc(RESP_DATA_MAX_LEN);
    if (packet->rspData.payload == NULL) {
        DISC_LOGE(DISC_BLE, "malloc failed");
        SoftBusFree(packet->bcData.payload);
        packet->bcData.payload = NULL;
        return SOFTBUS_MALLOC_ERR;
    }
    packet->rspData.type = BC_DATA_TYPE_MANUFACTURER;
    packet->rspData.id = MANU_COMPANY_ID;
    if (memcpy_s(&packet->rspData.payload[0], RESP_DATA_MAX_LEN, broadcastData->data.rspData,
        packet->rspData.payloadLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy err");
        DestroyBleConfigAdvData(packet);
        return SOFTBUS_MEM_ERR;
    }

    DISC_LOGI(DISC_BLE, "packet->rspData.payloadLen=%{public}d", packet->rspData.payloadLen);
    return SOFTBUS_OK;
}

static void AssembleCustData(DeviceInfo *info, BroadcastData *broadcastData)
{
    if ((info->capabilityBitmap[0] & 0x02) == 0) { // CastPlus
        return;
    }
    uint8_t custData[CUST_CAPABILITY_TYPE_LEN + CUST_CAPABILITY_LEN] = {0};
    custData[0] = CAST_PLUS;
    int32_t ret = ConvertHexStringToBytes(&custData[1], CUST_CAPABILITY_LEN, (const char *)info->custData,
        strlen(info->custData));
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE,
        "ConvertHexStringToBytes custData failed, ret=%{public}d", ret);
    (void)AssembleTLV(broadcastData, TLV_TYPE_CUST, (const void *)custData,
        CUST_CAPABILITY_LEN + CUST_CAPABILITY_TYPE_LEN);
}

static void AssembleNonOptionalTlv(DeviceInfo *info, BroadcastData *broadcastData)
{
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK, DISC_BLE, "lock failed");
    if (g_recvMessageInfo.numNeedBrMac > 0) {
        SoftBusBtAddr addr;
        if (SoftBusGetBrState() == BR_ENABLE && SoftBusGetBtMacAddr(&addr) == SOFTBUS_OK) {
            (void)AssembleTLV(broadcastData, TLV_TYPE_BR_MAC, (const void *)&addr.addr, BT_ADDR_LEN);
        }
    }
    (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
#ifdef DISC_COMMUNITY
    if (info->range > 0) {
        int8_t power = 0;
        if (SoftBusGetBlePower(&power) == SOFTBUS_OK) {
            (void)AssembleTLV(broadcastData, TLV_TYPE_RANGE_POWER, (const void *)&power, RANGE_POWER_TYPE_LEN);
        }
    }
#endif /* DISC_COMMUNITY */
    if (info->custData[0] != 0) {
        AssembleCustData(info, broadcastData);
    }
}

static int32_t AssembleBroadcastData(DeviceInfo *info, int32_t advId, BroadcastData *broadcastData)
{
    bool isWakeRemote = GetWakeRemote();
    errno_t retMem = memset_s(broadcastData->data.data, BROADCAST_MAX_LEN, 0x0, BROADCAST_MAX_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(retMem == EOK, SOFTBUS_MEM_ERR, DISC_BLE, "memset failed");
    broadcastData->data.data[POS_VERSION] = BLE_VERSION & BYTE_MASK;
    broadcastData->data.data[POS_BUSINESS] = DISTRIBUTE_BUSINESS & BYTE_MASK;
    broadcastData->data.data[POS_BUSINESS_EXTENSION] = BIT_CUST_DATA_TYPE;
    if (advId == CON_ADV_ID) {
        broadcastData->data.data[POS_BUSINESS_EXTENSION] |= BIT_CON;
        if (isWakeRemote) {
            broadcastData->data.data[POS_BUSINESS_EXTENSION] |= BIT_WAKE_UP;
        }
        retMem = memcpy_s(&broadcastData->data.data[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN,
            info->accountHash, SHORT_USER_ID_HASH_LEN);
        DISC_CHECK_AND_RETURN_RET_LOGE(retMem == EOK, SOFTBUS_MEM_ERR, DISC_BLE, "memcpy failed");
    } else {
        DiscBleGetShortUserIdHash(&broadcastData->data.data[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN);
    }
    broadcastData->data.data[POS_CAPABLITY] = info->capabilityBitmap[0] & BYTE_MASK;
    broadcastData->data.data[POS_CAPABLITY_EXTENSION] = 0x0;
    broadcastData->dataLen = POS_TLV;
    return SOFTBUS_OK;
}

static int32_t GetBroadcastData(DeviceInfo *info, int32_t advId, BroadcastData *broadcastData)
{
    int32_t ret = AssembleBroadcastData(info, advId, broadcastData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
        ret, DISC_BLE, "assemble broadcast failed, ret=%{public}d", ret);
    char deviceIdHash[SHORT_DEVICE_ID_HASH_LENGTH + 1] = {0};
    if (DiscBleGetDeviceIdHash((uint8_t *)deviceIdHash, SHORT_DEVICE_ID_HASH_LENGTH + 1) != SOFTBUS_OK) {
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
    uint32_t remainLen = BROADCAST_MAX_LEN - broadcastData->dataLen - 1;
    uint32_t validLen = (strlen(info->devName) + 1 > remainLen) ? remainLen : strlen(info->devName) + 1;
    char deviceName[DISC_MAX_DEVICE_NAME_LEN] = {0};
    if (DiscBleGetDeviceName(deviceName, validLen) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "get deviceName failed");
    }
    (void)AssembleTLV(broadcastData, TLV_TYPE_DEVICE_NAME, (const void *)deviceName, strlen(deviceName) + 1);

    DISC_LOGD(DISC_BLE, "broadcastData->dataLen=%{public}d", broadcastData->dataLen);
    return SOFTBUS_OK;
}

static void BuildAdvParam(BroadcastParam *advParam)
{
    advParam->minInterval = ADV_INTERNAL;
    advParam->maxInterval = ADV_INTERNAL;
    advParam->advType = SOFTBUS_BC_ADV_IND;
    advParam->ownAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    advParam->peerAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    advParam->channelMap = BLE_CHANNLE_MAP;
    advParam->txPower = BLE_ADV_TX_POWER_DEFAULT;
    (void)memset_s(advParam->localAddr.addr, BC_ADDR_MAC_LEN, 0, BC_ADDR_MAC_LEN);
}

static void DfxRecordAdevertiserEnd(int32_t adv, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.discType = BLE + 1;
    extra.broadcastType = adv + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BROADCAST, extra);
}

static void BleEventExtraInit(void)
{
    for (int32_t i = 0; i < MAX_DISC_EVENT; i++) {
        g_bleDiscExtra[i].discType = BLE + 1;
        g_bleDiscExtra[i].minInterval = ADV_INTERNAL;
        g_bleDiscExtra[i].maxInterval = ADV_INTERNAL;
    }
    for (int32_t i = 0; i < MAX_SCAN_EVENT; i++) {
        g_bleScanExtra[i].scanType = BLE + 1;
    }
 
    g_bleDiscExtra[CAST_EVENT_CON].broadcastType = CON_ADV_ID + 1;
    g_bleDiscExtra[CAST_EVENT_CON].capabilityBit = CASTPLUS_CAPABILITY_BITMAP;
    g_bleDiscExtra[CAST_EVENT_NON].broadcastType = NON_ADV_ID + 1;
    g_bleDiscExtra[CAST_EVENT_NON].capabilityBit = CASTPLUS_CAPABILITY_BITMAP;
    g_bleDiscExtra[OSD_EVENT_CON].broadcastType = CON_ADV_ID + 1;
    g_bleDiscExtra[OSD_EVENT_CON].capabilityBit = OSD_CAPABILITY_BITMAP;
    g_bleDiscExtra[OSD_EVENT_NON].broadcastType = NON_ADV_ID + 1;
    g_bleDiscExtra[OSD_EVENT_NON].capabilityBit = OSD_CAPABILITY_BITMAP;
    g_bleDiscExtra[DVKIT_EVENT_CON].broadcastType = CON_ADV_ID + 1;
    g_bleDiscExtra[DVKIT_EVENT_CON].capabilityBit = DVKIT_CAPABILITY_BITMAP;
    g_bleDiscExtra[DVKIT_EVENT_NON].broadcastType = NON_ADV_ID + 1;
    g_bleDiscExtra[DVKIT_EVENT_NON].capabilityBit = DVKIT_CAPABILITY_BITMAP;
    g_bleScanExtra[SCAN_CAST_EVENT].capabilityBit = CASTPLUS_CAPABILITY_BITMAP;
    g_bleScanExtra[SCAN_DVKIT_EVENT].capabilityBit = DVKIT_CAPABILITY_BITMAP;
    g_bleScanExtra[SCAN_OSD_EVENT].capabilityBit = OSD_CAPABILITY_BITMAP;
}
 
static void ClearDiscEventExtra(int32_t index)
{
    for (int32_t i = 0; i < index; i++) {
        g_bleDiscExtra[i].successCnt = 0;
        g_bleDiscExtra[i].failCnt = 0;
        g_bleDiscExtra[i].costTime = 0;
    }
}
 
static void ClearScanEventExtra(int32_t index)
{
    for (int32_t i = 0; i < index; i++) {
        g_bleScanExtra[i].scanCount = 0;
    }
}
 
static void DfxDelayRecord(const SoftBusMessage *msg)
{
    BroadcastDiscEvent(EVENT_SCENE_BLE, EVENT_STAGE_BLE_PROCESS, g_bleDiscExtra, MAX_DISC_EVENT);
    BroadcastScanEvent(EVENT_SCENE_BLE, EVENT_STAGE_BLE_PROCESS, g_bleScanExtra, MAX_SCAN_EVENT);
    ClearDiscEventExtra(MAX_DISC_EVENT);
    ClearScanEventExtra(MAX_SCAN_EVENT);
 
    SoftBusMessage *dfxmsg = CreateBleHandlerMsg(DFX_DELAY_RECORD, 0, 0, NULL);
    if (dfxmsg == NULL) {
        DISC_LOGE(DISC_BLE, "create msg fail");
    }
    g_discBleHandler.looper->PostMessageDelay(g_discBleHandler.looper, dfxmsg, DELAY_TIME_DEFAULT);
}
 
static void CalcCount(int32_t adv, uint32_t capabilityBitmap, bool result)
{
    uint32_t tempCap = 0;
    DeConvertBitMap(&tempCap, &capabilityBitmap, 1);
    if (adv == CON_ADV_ID) {
        if (tempCap & 1 << CASTPLUS_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[CAST_EVENT_CON].successCnt++ : g_bleDiscExtra[CAST_EVENT_CON].failCnt++;
        }
        if (tempCap & 1 << OSD_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[OSD_EVENT_CON].successCnt++ : g_bleDiscExtra[OSD_EVENT_CON].failCnt++;
        }
        if (tempCap & 1 << DVKIT_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[DVKIT_EVENT_CON].successCnt++ : g_bleDiscExtra[DVKIT_EVENT_CON].failCnt++;
        }
    }
    if (adv == NON_ADV_ID) {
        if (tempCap & 1 << CASTPLUS_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[CAST_EVENT_NON].successCnt++ : g_bleDiscExtra[CAST_EVENT_NON].failCnt++;
        }
        if (tempCap & 1 << OSD_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[OSD_EVENT_NON].successCnt++ : g_bleDiscExtra[OSD_EVENT_NON].failCnt++;
        }
        if (tempCap & 1 << DVKIT_CAPABILITY_BITMAP) {
            result ? g_bleDiscExtra[DVKIT_EVENT_NON].successCnt++ : g_bleDiscExtra[DVKIT_EVENT_NON].failCnt++;
        }
    }
}
 
static void CalcDurationTime(int32_t adv, uint32_t capabilityBitmap)
{
    uint32_t tempCap = 0;
    DeConvertBitMap(&tempCap, &capabilityBitmap, 1);
    int32_t stamptime = (int32_t)SoftBusGetSysTimeMs();
 
    const uint32_t event[] = {
        adv == CON_ADV_ID ? CAST_EVENT_CON : CAST_EVENT_NON,
        adv == CON_ADV_ID ? OSD_EVENT_CON : OSD_EVENT_NON,
        adv == CON_ADV_ID ? DVKIT_EVENT_CON : DVKIT_EVENT_NON
    };
 
    if ((tempCap & (1 << CASTPLUS_CAPABILITY_BITMAP)) && g_bleDiscExtra[event[CAST_EVENT]].isOn == 0) {
        g_bleDiscExtra[event[CAST_EVENT]].startTime = stamptime;
        g_bleDiscExtra[event[CAST_EVENT]].isOn = 1;
    } else if (((tempCap & 1 << CASTPLUS_CAPABILITY_BITMAP) == 0) && g_bleDiscExtra[event[CAST_EVENT]].isOn == 1) {
        g_bleDiscExtra[event[CAST_EVENT]].stopTime = stamptime;
        g_bleDiscExtra[event[CAST_EVENT]].isOn = 0;
        g_bleDiscExtra[event[CAST_EVENT]].costTime +=
            (g_bleDiscExtra[event[CAST_EVENT]].stopTime - g_bleDiscExtra[event[CAST_EVENT]].startTime);
    }
 
    if ((tempCap & (1 << OSD_CAPABILITY_BITMAP)) && g_bleDiscExtra[event[OSD_EVENT]].isOn == 0) {
        g_bleDiscExtra[event[OSD_EVENT]].startTime = stamptime;
        g_bleDiscExtra[event[OSD_EVENT]].isOn = 1;
    } else if (((tempCap & 1 << OSD_CAPABILITY_BITMAP) == 0) && g_bleDiscExtra[event[OSD_EVENT]].isOn == 1) {
        g_bleDiscExtra[event[OSD_EVENT]].stopTime = stamptime;
        g_bleDiscExtra[event[OSD_EVENT]].isOn = 0;
        g_bleDiscExtra[event[OSD_EVENT]].costTime +=
            (g_bleDiscExtra[event[OSD_EVENT]].stopTime - g_bleDiscExtra[event[OSD_EVENT]].startTime);
    }
 
    if ((tempCap & (1 << DVKIT_CAPABILITY_BITMAP)) && g_bleDiscExtra[event[DVKIT_EVENT]].isOn == 0) {
        g_bleDiscExtra[event[DVKIT_EVENT]].startTime = stamptime;
        g_bleDiscExtra[event[DVKIT_EVENT]].isOn = 1;
    } else if (((tempCap & 1 << DVKIT_CAPABILITY_BITMAP) == 0) && g_bleDiscExtra[event[DVKIT_EVENT]].isOn == 1) {
        g_bleDiscExtra[event[DVKIT_EVENT]].stopTime = stamptime;
        g_bleDiscExtra[event[DVKIT_EVENT]].isOn = 0;
        g_bleDiscExtra[event[DVKIT_EVENT]].costTime +=
            (g_bleDiscExtra[event[DVKIT_EVENT]].stopTime - g_bleDiscExtra[event[DVKIT_EVENT]].startTime);
    }
}

static int32_t StartAdvertiser(int32_t adv)
{
    DISC_LOGD(DISC_BLE, "enter");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, StopAdvertiser(adv),
        DISC_BLE, "advertiser GetConDeviceInfo failed. adv=%{public}d", adv);
    BroadcastData broadcastData;
    (void)memset_s(&broadcastData, sizeof(BroadcastData), 0, sizeof(BroadcastData));
    ret = GetBroadcastData(&advertiser->deviceInfo, adv, &broadcastData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_DISCOVER_BLE_GET_BROADCAST_DATA_FAIL,
        DISC_BLE, "get broadcast data failed");
    BroadcastPacket packet = {};
    ret = BuildBleConfigAdvData(&packet, &broadcastData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_DISCOVER_BLE_BUILD_CONFIG_ADV_DATA_FAIL,
        DISC_BLE, "BuildBleConfigAdvData failed, ret=%{public}d", ret);
    BroadcastParam advParam = {};
    BuildAdvParam(&advParam);

    SignalingMsgPrint("ble adv send", (uint8_t *)packet.bcData.payload, (uint8_t)packet.bcData.payloadLen,
        DISC_BLE);
    BroadcastContentType contentType = (adv == CON_ADV_ID) ? BC_TYPE_DISTRIB_CON : BC_TYPE_DISTRIB_NON;
    ret = SchedulerStartBroadcast(advertiser->channel, contentType, &advParam, &packet);
    if (ret != SOFTBUS_OK) {
        DfxRecordAdevertiserEnd(adv, ret);
        CalcCount(adv, advertiser->deviceInfo.capabilityBitmap[0], false);
        DestroyBleConfigAdvData(&packet);
        DISC_LOGE(DISC_BLE, "start adv failed, adv=%{public}d", adv);
        return SOFTBUS_DISCOVER_BLE_START_BROADCAST_FAIL;
    }
    CalcCount(adv, advertiser->deviceInfo.capabilityBitmap[0], true);
    CalcDurationTime(adv, advertiser->deviceInfo.capabilityBitmap[0]);
    DfxRecordAdevertiserEnd(adv, SOFTBUS_OK);
    UpdateInfoManager(adv, false);
    DestroyBleConfigAdvData(&packet);
    return SOFTBUS_OK;
}

static int32_t StopAdvertiser(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (!advertiser->isAdvertising) {
        DISC_LOGI(DISC_BLE, "advertiser adv is already stopped. adv=%{public}d", adv);
        return SOFTBUS_OK;
    }
    int32_t ret = SchedulerStopBroadcast(advertiser->channel);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "stop advertiser failed. advId=%{public}d, ret=%{public}d", adv, ret);
    }
    if (adv == NON_ADV_ID) {
        DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK,
            SOFTBUS_LOCK_ERR, DISC_BLE, "Lock failed");
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
        CalcDurationTime(adv, advertiser->deviceInfo.capabilityBitmap[0]);
        DISC_LOGE(DISC_BLE, "advertiser adv GetConDeviceInfo failed. adv=%{public}d", adv);
        StopAdvertiser(adv);
    }
    BroadcastData broadcastData = {};
    ret = GetBroadcastData(&advertiser->deviceInfo, adv, &broadcastData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,  SOFTBUS_DISCOVER_BLE_GET_BROADCAST_DATA_FAIL,
        DISC_BLE, "GetBroadcastData failed, ret=%{public}d", ret);
    BroadcastPacket packet = {};
    ret = BuildBleConfigAdvData(&packet, &broadcastData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_DISCOVER_BLE_BUILD_CONFIG_ADV_DATA_FAIL,
        DISC_BLE, "BuildBleConfigAdvData failed, ret=%{public}d", ret);
    BroadcastParam advParam = {0};
    BuildAdvParam(&advParam);
    ret = SchedulerUpdateBroadcast(advertiser->channel, &advParam, &packet);
    if (ret != SOFTBUS_OK) {
        CalcCount(adv, advertiser->deviceInfo.capabilityBitmap[0], false);
        DestroyBleConfigAdvData(&packet);
        DISC_LOGE(DISC_BLE, "UpdateAdv failed, ret=%{public}d", ret);
        return SOFTBUS_DISCOVER_BLE_START_BROADCAST_FAIL;
    }
    CalcCount(adv, advertiser->deviceInfo.capabilityBitmap[0] - g_bleOldCap, true);
    CalcDurationTime(adv, advertiser->deviceInfo.capabilityBitmap[0]);
    UpdateInfoManager(adv, false);
    DestroyBleConfigAdvData(&packet);
    return SOFTBUS_OK;
}

static void InitScanner(void)
{
    g_isScanning = false;
}

static int32_t GetScannerParam(int32_t freq, BcScanParams *scanParam)
{
    scanParam->scanInterval = (uint16_t)g_scanTable[freq].scanInterval;
    scanParam->scanWindow = (uint16_t)g_scanTable[freq].scanWindow;
    scanParam->scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE;
    scanParam->scanPhy = SOFTBUS_BC_SCAN_PHY_1M;
    scanParam->scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL;
    return SOFTBUS_OK;
}

static void DfxRecordScanEnd(int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.scanType = BLE + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_SCAN, extra);
}

static void UpdateScannerFilter(bool isStopScan)
{
    if (isStopScan) {
        int32_t ret = SchedulerStopScan(g_bleListener.scanListenerId);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "StopScaner failed, ret=%{public}d", ret);
    }
    int32_t type = GetScannerFilterType();
    DISC_LOGI(DISC_BLE, "Set filter type=%{public}d", type);
    DiscBleSetScanFilter(g_bleListener.scanListenerId, type);
}

static void StartScaner(int32_t type)
{
    DISC_CHECK_AND_RETURN_LOGE(type > 0 && type <= (CON_FILTER_TYPE | NON_FILTER_TYPE),
        DISC_BLE, "start scanner type invaild");
    if (!CheckScanner()) {
        DISC_LOGI(DISC_BLE, "no need to start scanner");
        (void)StopScaner();
        return;
    }

    if (g_isScanning) {
        if (GetNeedUpdateScanner(type)) {
            UpdateScannerFilter(true);
        } else {
            DISC_LOGI(DISC_BLE, "scanner already start, no need start again");
            return;
        }
    } else {
        if (GetNeedUpdateScanner(type)) {
            UpdateScannerFilter(false);
        } else {
            DISC_LOGI(DISC_BLE, "no need update filter, start scan"); // when bt turn on or off
        }
    }

    BcScanParams scanParam;
    int32_t maxFreq = GetMaxExchangeFreq();
    int32_t ret = GetScannerParam(maxFreq, &scanParam);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "GetScannerParam failed");
    ret = SchedulerStartScan(g_bleListener.scanListenerId, &scanParam);
    if (ret != SOFTBUS_OK) {
        DfxRecordScanEnd(ret);
        DISC_LOGE(DISC_BLE, "start scan failed");
        return;
    }
    UpdateScannerInfoManager(type, true);
    DfxRecordScanEnd(SOFTBUS_OK);
    DISC_LOGD(DISC_BLE, "StartScanner success");
}

static int32_t StopScaner(void)
{
    if (!g_isScanning) {
        DISC_LOGI(DISC_BLE, "already stop scanning");
        return SOFTBUS_OK;
    }
    int32_t ret = SchedulerStopScan(g_bleListener.scanListenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
        SOFTBUS_DISCOVER_BLE_END_SCAN_FAIL, DISC_BLE, "StopScaner failed, ret=%{public}d", ret);
    DISC_LOGD(DISC_BLE, "success");
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
            SetCapBitMapPos(CAPABILITY_NUM, info->capBitMap, pos);
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
            info->capabilityData[pos] = (uint8_t *)SoftBusCalloc(MAX_CAPABILITYDATA_LEN);
            if (info->capabilityData[pos] == NULL) {
                return SOFTBUS_MALLOC_ERR;
            }
        }
        if (memcpy_s(info->capabilityData[pos], MAX_CAPABILITYDATA_LEN, custData, custDataLen) != EOK) {
            SoftBusFree(info->capabilityData[pos]);
            info->capabilityData[pos] = NULL;
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
            UnsetCapBitMapPos(CAPABILITY_NUM, info->capBitMap, pos);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "option is null");
    DiscBleOption regOption;
    if (publishFlags == BLE_PUBLISH) {
        regOption.publishOption = (PublishOption *)option;
        regOption.subscribeOption = NULL;
    } else {
        regOption.publishOption = NULL;
        regOption.subscribeOption = (SubscribeOption *)option;
    }
    uint8_t index = publishFlags | activeFlags;
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BLE, "lock failed.");
    uint32_t oldCap = g_bleInfoManager[index].capBitMap[0];
    g_bleOldCap = oldCap;
    int32_t oldRangingRefCount = g_bleInfoManager[index].rangingRefCnt;
    if (isStart) {
        int32_t status = RegisterCapability(&g_bleInfoManager[index], &regOption);
        if (status != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "RegisterCapability failed, err=%{public}d", status);
            SoftBusMutexUnlock(&g_bleInfoLock);
            return SOFTBUS_DISCOVER_BLE_REGISTER_CAP_FAIL;
        }
    } else {
        UnregisterCapability(&g_bleInfoManager[index], &regOption);
    }

    uint32_t newCap = g_bleInfoManager[index].capBitMap[0];
    if ((index != (BLE_PUBLISH | BLE_ACTIVE)) && newCap != oldCap) {
        g_bleInfoManager[index].needUpdateCap = true;
    }
    int32_t newRangingRefCount = g_bleInfoManager[index].rangingRefCnt;
    BleEventExtraInit();
    DISC_LOGI(DISC_BLE, "ble discovery request summary, action: isStart=%{public}d, publishFlags=%{public}d, "
        "activeFlags=%{public}d, oldCap=%{public}d, newCap=%{public}d, "
        "oldRangingRefCount=%{public}d, newRangingRefCount=%{public}d, needUpdateCap=%{public}d",
        isStart, publishFlags, activeFlags, oldCap, newCap, oldRangingRefCount, newRangingRefCount,
        g_bleInfoManager[index].needUpdateCap);

    SoftBusMutexUnlock(&g_bleInfoLock);
    return SOFTBUS_OK;
}

static SoftBusMessage *CreateBleHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    DISC_CHECK_AND_RETURN_RET_LOGE(msg != NULL, NULL, DISC_BLE, "ble create handler msg failed");
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_discBleHandler;
    msg->FreeMessage = NULL;
    msg->obj = obj;
    return msg;
}

static void DfxRecordBleProcessEnd(uint8_t publishFlag, uint8_t activeFlag, int32_t funcCode,
    const void *option, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.errcode = reason;
    extra.discType = BLE + 1;
    extra.interFuncType = funcCode + 1;
    extra.discMode = (activeFlag == BLE_ACTIVE) ? DISCOVER_MODE_ACTIVE : DISCOVER_MODE_PASSIVE;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    const char *capabilityData = NULL;
    uint32_t dataLen = MAX_CAPABILITYDATA_LEN - 1;
    if (publishFlag == BLE_PUBLISH && option != NULL) {
        PublishOption *publishOption = (PublishOption *)option;
        extra.capabilityBit = (int32_t)publishOption->capabilityBitmap[0];
        capabilityData = (const char *)publishOption->capabilityData;
        dataLen = publishOption->dataLen < dataLen ? publishOption->dataLen : dataLen;
    } else if (publishFlag == BLE_SUBSCRIBE && option != NULL) {
        SubscribeOption *subscribeOption = (SubscribeOption *)option;
        extra.capabilityBit = (int32_t)subscribeOption->capabilityBitmap[0];
        capabilityData = (const char *)subscribeOption->capabilityData;
        dataLen = subscribeOption->dataLen < dataLen ? subscribeOption->dataLen : dataLen;
    }

    char data[MAX_CAPABILITYDATA_LEN] = { 0 };
    if (capabilityData != NULL && strncpy_s(data, MAX_CAPABILITYDATA_LEN, capabilityData, dataLen) == EOK) {
        extra.capabilityData = data;
    }
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BLE_PROCESS, extra);
}

static int32_t ProcessBleDiscFunc(bool isStart, uint8_t publishFlags, uint8_t activeFlags,
    int32_t funcCode, const void *option)
{
    if (isStart && SoftBusGetBtState() != BLE_ENABLE) {
        DfxRecordBleProcessEnd(publishFlags, activeFlags, funcCode, option, SOFTBUS_BLUETOOTH_OFF);
        DISC_LOGE(DISC_BLE, "get bt state failed.");
        return SOFTBUS_BLUETOOTH_OFF;
    }
    int32_t ret = ProcessBleInfoManager(isStart, publishFlags, activeFlags, option);
    if (ret != SOFTBUS_OK) {
        DfxRecordBleProcessEnd(publishFlags, activeFlags, funcCode, option, ret);
        DISC_LOGE(DISC_BLE, "process ble info manager failed");
        return ret;
    }
    SoftBusMessage *msg = CreateBleHandlerMsg(funcCode, 0, 0, NULL);
    if (msg == NULL) {
        DfxRecordBleProcessEnd(publishFlags, activeFlags, funcCode, option, SOFTBUS_MALLOC_ERR);
        DISC_LOGE(DISC_BLE, "CreateBleHandlerMsg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
    DfxRecordBleProcessEnd(publishFlags, activeFlags, funcCode, option, SOFTBUS_OK);
    return SOFTBUS_OK;
}

static int32_t BleStartActivePublish(const PublishOption *option)
{
    DISC_LOGI(DISC_BLE, "start active publish");
    return ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_ACTIVE, PUBLISH_ACTIVE_SERVICE, (void *)option);
}

static int32_t BleStartPassivePublish(const PublishOption *option)
{
    DISC_LOGD(DISC_BLE, "start passive publish");
    return ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_PASSIVE, PUBLISH_PASSIVE_SERVICE, (void *)option);
}

static int32_t BleStopActivePublish(const PublishOption *option)
{
    DISC_LOGI(DISC_BLE, "stop active publish");
    return ProcessBleDiscFunc(false, BLE_PUBLISH, BLE_ACTIVE, UNPUBLISH_SERVICE, (void *)option);
}

static int32_t BleStopPassivePublish(const PublishOption *option)
{
    DISC_LOGD(DISC_BLE, "stop passive publish");
    return ProcessBleDiscFunc(false, BLE_PUBLISH, BLE_PASSIVE, UNPUBLISH_SERVICE, (void *)option);
}

static int32_t BleStartActiveDiscovery(const SubscribeOption *option)
{
    DISC_LOGI(DISC_BLE, "start active discovery");
    return ProcessBleDiscFunc(true, BLE_SUBSCRIBE, BLE_ACTIVE, START_ACTIVE_DISCOVERY, (void *)option);
}

static int32_t BleStartPassiveDiscovery(const SubscribeOption *option)
{
    DISC_LOGI(DISC_BLE, "start passive discovery");
    return ProcessBleDiscFunc(true, BLE_SUBSCRIBE, BLE_PASSIVE, START_PASSIVE_DISCOVERY, (void *)option);
}

static int32_t BleStopActiveDiscovery(const SubscribeOption *option)
{
    DISC_LOGI(DISC_BLE, "stop active discovery");
    return ProcessBleDiscFunc(false, BLE_SUBSCRIBE, BLE_ACTIVE, STOP_DISCOVERY, (void *)option);
}

static int32_t BleStopPassiveDiscovery(const SubscribeOption *option)
{
    DISC_LOGI(DISC_BLE, "stop passive discovery");
    return ProcessBleDiscFunc(false, BLE_SUBSCRIBE, BLE_PASSIVE, STOP_DISCOVERY, (void *)option);
}

static bool BleIsConcern(uint32_t capability)
{
    return (capability & g_concernCapabilityMask) != 0;
}

static int32_t UpdateAdvertiserDeviceInfo(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser->isAdvertising) {
        int32_t ret = UpdateAdvertiser(adv);
        if (ret == SOFTBUS_OK) {
            DISC_LOGI(DISC_BLE, "update device info success");
            return SOFTBUS_OK;
        }
        return ret;
    }

    DISC_LOGI(DISC_BLE, "not advertising or no need to update");
    return SOFTBUS_OK;
}

static void BleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
    DISC_CHECK_AND_RETURN_LOGE(
        UpdateAdvertiserDeviceInfo(NON_ADV_ID) == SOFTBUS_OK && UpdateAdvertiserDeviceInfo(CON_ADV_ID) == SOFTBUS_OK,
        DISC_BLE, "update failed");
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
    int32_t conChannel = -1;
    int32_t nonChannel = -1;
    int32_t ret = SchedulerRegisterBroadcaster(SRV_TYPE_DIS, &conChannel, &g_advCallback);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "register broadcaster con fail");

    ret = SchedulerRegisterBroadcaster(SRV_TYPE_DIS, &nonChannel, &g_advCallback);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "register broadcaster non fail");
        (void)SchedulerUnregisterBroadcaster(conChannel);
        return ret;
    }
    if (conChannel < 0 || nonChannel < 0) {
        DISC_LOGE(DISC_INIT, "register broadcaster fail. conChannel=%{public}d, nonChannel=%{public}d",
            conChannel, nonChannel);
        (void)SchedulerUnregisterBroadcaster(conChannel);
        (void)SchedulerUnregisterBroadcaster(nonChannel);
        return SOFTBUS_DISCOVER_BLE_ADV_INIT_FAIL;
    }
    DISC_LOGI(DISC_INIT, "conChannel=%{public}d, nonChannel=%{public}d", conChannel, nonChannel);

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
    DISC_LOGD(DISC_BLE, "enter");
    if (StartAdvertiser(NON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Start msg failed");
    }
    DISC_LOGD(DISC_BLE, "end");
}

static void StartPassivePublish(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
        DISC_LOGI(DISC_BLE, "UpdateAdvertiser NON_ADV_ID=%{public}d", NON_ADV_ID);
        UpdateAdvertiser(NON_ADV_ID);
    }
    StartScaner(CON_FILTER_TYPE);
    DISC_LOGD(DISC_BLE, "end");
}

static void StartActiveDiscovery(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    if (StartAdvertiser(CON_ADV_ID) == SOFTBUS_OK) {
        StartScaner(NON_FILTER_TYPE);
    }
    DISC_LOGD(DISC_BLE, "end");
}

static void StartPassiveDiscovery(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    StartScaner(NON_FILTER_TYPE);
    DISC_LOGD(DISC_BLE, "end");
}

static void Recovery(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    if (StartAdvertiser(CON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Start CON_ADV_ID failed");
    }
    if (StartAdvertiser(NON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Start NON_ADV_ID failed");
    }
    StartScaner(CON_FILTER_TYPE | NON_FILTER_TYPE);
    DISC_LOGD(DISC_BLE, "end");
}

static void BleDiscTurnOff(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    if (StopAdvertiser(NON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Stop NON_ADV_ID failed");
    }
    if (StopAdvertiser(CON_ADV_ID) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Stop CON_ADV_ID failed");
    }
    if (StopScaner() != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Stop failed");
    }
    DISC_LOGD(DISC_BLE, "end");
}

static int32_t ReplyPassiveNonBroadcast(void)
{
    DISC_LOGD(DISC_BLE, "enter");
    SoftBusMessage *msg = CreateBleHandlerMsg(REPLY_PASSIVE_NON_BROADCAST, 0, 0, NULL);
    if (msg == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t MessageRemovePredicate(const SoftBusMessage *msg, void *args)
{
    DISC_LOGD(DISC_BLE, "enter");
    uintptr_t key = (uintptr_t)args;
    if (msg->what == PROCESS_TIME_OUT && msg->arg1 == key) {
        DISC_LOGD(DISC_BLE, "find key");
        return 0;
    }
    DISC_LOGW(DISC_BLE, "not find key");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BLE, "lock failed");
    RecvMessage *msg = NULL;
    DISC_LOGI(DISC_BLE, "recv message cnt=%{public}d", g_recvMessageInfo.numNeedResp);
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        for (uint32_t index = 0; index < len; index++) {
            capBitMap[index] |= msg->capBitMap[index] & publishInfoMap[index];
        }
    }
    (void)SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    return SOFTBUS_OK;
}

static void StartTimeout(const char *key)
{
    DISC_LOGD(DISC_BLE, "enter");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK, DISC_BLE, "lock failed");
    if (GetRecvMessage(key) == NULL) {
        DISC_LOGE(DISC_BLE, "key is not exists");
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        return;
    }
    SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    SoftBusMessage *msg = CreateBleHandlerMsg(PROCESS_TIME_OUT, (uintptr_t)key, 0, NULL);
    DISC_CHECK_AND_RETURN_LOGE(msg != NULL, DISC_BLE, "malloc msg failed");
    g_discBleHandler.looper->PostMessageDelay(g_discBleHandler.looper, msg, BLE_MSG_TIME_OUT);
}

static void RemoveTimeout(const char *key)
{
    DISC_LOGD(DISC_BLE, "enter");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK, DISC_BLE, "lock failed");
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

static void DfxRecordAddRecvMsgEnd(const uint32_t *capBitMap, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.discType = BLE + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    if (capBitMap != NULL) {
        extra.capabilityBit = (int32_t)capBitMap[0];
    }
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_SCAN_RECV, extra);
}

static int32_t AddRecvMessage(const char *key, const uint32_t *capBitMap, bool needBrMac)
{
    DISC_LOGD(DISC_BLE, "enter");
    if (SoftBusMutexLock(&g_recvMessageInfo.lock) != SOFTBUS_OK) {
        DfxRecordAddRecvMsgEnd(capBitMap, SOFTBUS_LOCK_ERR);
        DISC_LOGE(DISC_BLE, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t oldAggregateCap = RecvMsgAggregateCap();
    RecvMessage *recvMsg = GetRecvMessage(key);
    if (recvMsg == NULL) {
        DISC_LOGI(DISC_BLE, "key is not exit");
        recvMsg = (RecvMessage *)SoftBusCalloc(sizeof(RecvMessage));
        if (recvMsg == NULL) {
            DfxRecordAddRecvMsgEnd(capBitMap, SOFTBUS_MALLOC_ERR);
            DISC_LOGE(DISC_BLE, "malloc recv msg failed");
            SoftBusMutexUnlock(&g_recvMessageInfo.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(&recvMsg->key, SHA_HASH_LEN, key, SHA_HASH_LEN) != EOK) {
            DfxRecordAddRecvMsgEnd(capBitMap, SOFTBUS_MEM_ERR);
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
    } else {
        RemoveTimeout(recvMsg->key);
    }
    StartTimeout(recvMsg->key);
    SoftBusMutexUnlock(&g_recvMessageInfo.lock);
    DfxRecordAddRecvMsgEnd(capBitMap, SOFTBUS_OK);
    return SOFTBUS_OK;
}

static void RemoveRecvMessage(uint64_t key)
{
    DISC_LOGD(DISC_BLE, "enter");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK, DISC_BLE, "lock failed");

    RecvMessage *msg = GetRecvMessage((char *)(uintptr_t)key);
    if (msg == NULL) {
        DISC_LOGE(DISC_BLE, "not find message");
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        return;
    }

    if (g_discBleHandler.looper && g_discBleHandler.looper->RemoveMessageCustom) {
        g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler,
            MessageRemovePredicate, (void *)key);
    }
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
        if (g_discBleHandler.looper && g_discBleHandler.looper->RemoveMessageCustom) {
            g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler,
                MessageRemovePredicate, (void *)msg->key);
        }
        SoftBusFree(msg);
    }
}

static void ProcessTimeout(SoftBusMessage *msg)
{
    DISC_LOGD(DISC_BLE, "enter");
    RemoveRecvMessage(msg->arg1);
    if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
        UpdateAdvertiser(NON_ADV_ID);
    }
}

static void OnBrStateChanged(SoftBusMessage *msg)
{
    (void)msg;
    DISC_LOGD(DISC_BLE, "enter");
    if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK, DISC_BLE, "lock failed");
        uint32_t numNeedBrMac = g_recvMessageInfo.numNeedBrMac;
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);

        if (numNeedBrMac > 0) {
            UpdateAdvertiser(NON_ADV_ID);
        }
    }
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
            StartScaner(CON_FILTER_TYPE);
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
            StartScaner(NON_FILTER_TYPE);
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
        case BR_STATE_CHANGED:
            OnBrStateChanged(msg);
            break;
        case DFX_DELAY_RECORD:
            DfxDelayRecord(msg);
            break;
        default:
            DISC_LOGW(DISC_BLE, "wrong msg what=%{public}d", msg->what);
            break;
    }
}

static int32_t DiscBleLooperInit(void)
{
    g_discBleHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    DISC_CHECK_AND_RETURN_RET_LOGE(g_discBleHandler.looper != NULL, SOFTBUS_LOOPER_ERR, DISC_INIT, "get looper fail");

    g_discBleHandler.name = (char *)"ble_disc_handler";
    g_discBleHandler.HandleMessage = DiscBleMsgHandler;
    return SOFTBUS_OK;
}

static void DiscFreeBleScanFilter(BcScanFilter *filter)
{
    if (filter != NULL) {
        SoftBusFree(filter->serviceData);
        SoftBusFree(filter->serviceDataMask);
        SoftBusFree(filter);
        filter = NULL;
    }
}

static void DiscBleSetScanFilter(int32_t listenerId, int32_t type)
{
    DISC_CHECK_AND_RETURN_LOGW(type != 0, DISC_BLE, "not disc capblity, not set filter");
    BcScanFilter *filter = (BcScanFilter *)SoftBusCalloc(sizeof(BcScanFilter));
    DISC_CHECK_AND_RETURN_LOGE(filter != NULL, DISC_BLE, "malloc filter failed");

    filter->serviceData = (uint8_t *)SoftBusCalloc(BLE_SCAN_FILTER_LEN);
    filter->serviceDataMask = (uint8_t *)SoftBusCalloc(BLE_SCAN_FILTER_LEN);
    if (filter->serviceData == NULL || filter->serviceDataMask == NULL) {
        DISC_LOGE(DISC_BLE, "malloc filter data failed");
        DiscFreeBleScanFilter(filter);
        return;
    }

    filter->serviceUuid = SERVICE_UUID;
    filter->serviceDataLength = BLE_SCAN_FILTER_LEN;
    filter->serviceData[POS_VERSION] = BLE_VERSION;
    filter->serviceData[POS_BUSINESS] = DISTRIBUTE_BUSINESS;
    filter->serviceDataMask[POS_VERSION] = BYTE_MASK;
    filter->serviceDataMask[POS_BUSINESS] = BYTE_MASK;

    if (type == CON_FILTER_TYPE) {
        filter->serviceData[POS_BUSINESS_EXTENSION] = ((1 << BYTE_SHIFT_7BIT) | (1 << BYTE_SHIFT_4BIT));
        filter->serviceDataMask[POS_BUSINESS_EXTENSION] = ((1 << BYTE_SHIFT_7BIT) | (1 << BYTE_SHIFT_4BIT));
    }
    if (type == NON_FILTER_TYPE) {
        filter->serviceData[POS_BUSINESS_EXTENSION] = (1 << BYTE_SHIFT_4BIT);
        filter->serviceDataMask[POS_BUSINESS_EXTENSION] = ((1 << BYTE_SHIFT_7BIT) | (1 << BYTE_SHIFT_4BIT));
    }
    if (type == (CON_FILTER_TYPE | NON_FILTER_TYPE)) {
        filter->serviceData[POS_BUSINESS_EXTENSION] = ((1 << BYTE_SHIFT_7BIT) | (1 << BYTE_SHIFT_4BIT));
        filter->serviceDataMask[POS_BUSINESS_EXTENSION] = (1 << BYTE_SHIFT_4BIT);
    }

    if (SchedulerSetScanFilter(listenerId, filter, 1) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "set scan filter failed");
        DiscFreeBleScanFilter(filter);
    }
}

static int32_t InitBleListener(void)
{
    int32_t ret = SchedulerRegisterScanListener(SRV_TYPE_DIS, &g_bleListener.scanListenerId, &g_scanListener);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "register scanner listener fail");
    g_bleListener.stateListenerId = SoftBusAddBtStateListener(&g_stateChangedListener);
    if (g_bleListener.stateListenerId < 0 || g_bleListener.scanListenerId < 0) {
        return SOFTBUS_BC_MGR_REG_NO_AVAILABLE_LISN_ID;
    }
    return SOFTBUS_OK;
}

DiscoveryBleDispatcherInterface *DiscSoftBusBleInit(DiscInnerCallback *callback)
{
    DISC_LOGI(DISC_INIT, "enter");
    DISC_CHECK_AND_RETURN_RET_LOGE(callback != NULL && callback->OnDeviceFound != NULL, NULL,
        DISC_INIT, "callback invalid.");

    ListInit(&g_recvMessageInfo.node);
    g_discBleInnerCb = callback;

    SoftBusMutexAttr mutexAttr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    if (SoftBusMutexInit(&g_recvMessageInfo.lock, &mutexAttr) != SOFTBUS_OK ||
        SoftBusMutexInit(&g_bleInfoLock, NULL) != SOFTBUS_OK) {
        DiscSoftBusBleDeinit();
        DISC_LOGE(DISC_INIT, "init ble lock failed");
        return NULL;
    }

    DiscBleInitPublish();
    DiscBleInitSubscribe();
    InitScanner();
    if (SchedulerInitBroadcast() != SOFTBUS_OK) {
        DiscSoftBusBleDeinit();
        DISC_LOGE(DISC_INIT, "init broadcast scheduler failed");
        return NULL;
    }

    if (DiscBleLooperInit() != SOFTBUS_OK || InitAdvertiser() != SOFTBUS_OK || InitBleListener() != SOFTBUS_OK)  {
        DiscSoftBusBleDeinit();
        return NULL;
    }

    SoftBusMessage *msg = CreateBleHandlerMsg(DFX_DELAY_RECORD, 0, 0, NULL);
    g_discBleHandler.looper->PostMessageDelay(g_discBleHandler.looper, msg, DELAY_TIME_DEFAULT);
    SoftBusRegDiscVarDump((char *)BLE_INFO_MANAGER, &BleInfoDump);
    SoftBusRegDiscVarDump((char *)BlE_ADVERTISER, &BleAdvertiserDump);
    SoftBusRegDiscVarDump((char *)RECV_MESSAGE_INFO, &RecvMessageInfoDump);

    DISC_LOGI(DISC_INIT, "success");
    return &g_discBleDispatcherInterface;
}

static bool CheckLockInit(SoftBusMutex *lock)
{
    if (SoftBusMutexLock(lock) != SOFTBUS_OK) {
        return false;
    }
    SoftBusMutexUnlock(lock);
    return true;
}

static void RecvMessageDeinit(void)
{
    int32_t ret = SoftBusMutexLock(&g_recvMessageInfo.lock);
    ClearRecvMessage();
    if (ret == SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_recvMessageInfo.lock);
        (void)SoftBusMutexDestroy(&g_recvMessageInfo.lock);
    }
    g_recvMessageInfo.numNeedBrMac = 0;
    g_recvMessageInfo.numNeedResp = 0;
}

static void AdvertiserDeinit(void)
{
    (void)SchedulerUnregisterBroadcaster(g_bleAdvertiser[CON_ADV_ID].channel);
    (void)SchedulerUnregisterBroadcaster(g_bleAdvertiser[NON_ADV_ID].channel);
    for (uint32_t index = 0; index < NUM_ADVERTISER; index++) {
        (void)memset_s(&g_bleAdvertiser[index], sizeof(DiscBleAdvertiser), 0x0, sizeof(DiscBleAdvertiser));
    }
}

static void BleListenerDeinit(void)
{
    (void)SoftBusRemoveBtStateListener(g_bleListener.stateListenerId);
    (void)SchedulerUnregisterListener(g_bleListener.scanListenerId);
}

static void DiscBleInfoDeinit(void)
{
    for (uint32_t index = 0; index < BLE_INFO_COUNT; index++) {
        (void)memset_s(&g_bleInfoManager[index], sizeof(DiscBleInfo), 0x0, sizeof(DiscBleInfo));
    }
    if (CheckLockInit(&g_bleInfoLock)) {
        (void)SoftBusMutexDestroy(&g_bleInfoLock);
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
    SchedulerDeinitBroadcast();
}

static int32_t BleInfoDump(int fd)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleInfoLock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BLE, "lock failed.");
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
        char *anonymizedInfo = NULL;
        Anonymize(g_bleAdvertiser[i].deviceInfo.devId, &anonymizedInfo);
        SOFTBUS_DPRINTF(fd, "devId                                   : %s\n", AnonymizeWrapper(anonymizedInfo));
        AnonymizeFree(anonymizedInfo);
        Anonymize(g_bleAdvertiser[i].deviceInfo.accountHash, &anonymizedInfo);
        SOFTBUS_DPRINTF(fd, "accountHash                             : %s\n", AnonymizeWrapper(anonymizedInfo));
        AnonymizeFree(anonymizedInfo);
        SOFTBUS_DPRINTF(fd, "devType                                 : %u\n", g_bleAdvertiser[i].deviceInfo.devType);
        Anonymize(g_bleAdvertiser[i].deviceInfo.devName, &anonymizedInfo);
        SOFTBUS_DPRINTF(fd, "devName                                 : %s\n", AnonymizeWrapper(anonymizedInfo));
        AnonymizeFree(anonymizedInfo);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_recvMessageInfo.lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BLE, "lock failed.");
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
