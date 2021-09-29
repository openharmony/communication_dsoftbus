/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "common_list.h"
#include "discovery_service.h"
#include "disc_ble_constant.h"
#include "disc_ble_utils.h"
#include "disc_manager.h"
#include "lnn_device_info.h"
#include "message_handler.h"
#include "pthread.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
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

/* Defination of boardcast */

#define BLE_VERSION 4
#define NEARBY_BUSSINESS 0x1
#define DISTRIBUTE_BUSSINESS 0x5
#define BYTE_MASK 0xFF
#define DEVICE_NAME_MAX_LEN 15

#define BIT_WAKE_UP 0x01
#define BIT_CUST_DATA_TYPE 0x10
#define BIT_HEART_BIT 0x20
#define BIT_CON 0x80
#define BIT_CON_POS 7

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
    int32_t advId;
    bool isAdvertising;
    DeviceInfo deviceInfo;
    int32_t (*GetDeviceInfo)(DeviceInfo *info);
} DiscBleAdvertiser;

typedef struct {
    bool needUpdate;
    uint32_t capBitMap[CAPABILITY_NUM];
    int16_t capCount[CAPABILITY_MAX_BITNUM];
    unsigned char *capabilityData[CAPABILITY_MAX_BITNUM];
    uint32_t capDataLen[CAPABILITY_MAX_BITNUM];
    bool isSameAccount[CAPABILITY_MAX_BITNUM];
    bool isWakeRemote[CAPABILITY_MAX_BITNUM];
    int32_t freq[CAPABILITY_MAX_BITNUM];
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
    pthread_mutex_t lock;
} RecvMessageInfo;

typedef struct {
    int32_t stateListenerId;
    int32_t scanListenerId;
} DiscBleListener;

static ScanSetting g_scanTable[FREQ_BUTT] = {
    {60, 3000},
    {60, 600},
    {60, 240},
    {1000, 1000}
};

static DiscInnerCallback *g_discBleInnerCb = NULL;
static DiscBleInfo g_bleInfoManager[BLE_INFO_COUNT];
static pthread_mutex_t g_bleInfoLock = PTHREAD_MUTEX_INITIALIZER;
static DiscBleAdvertiser g_bleAdvertiser[NUM_ADVERTISER];
static bool g_isScanning = false;
static SoftBusHandler g_discBleHandler = {0};
static RecvMessageInfo g_recvMessageInfo = {0};
static DiscBleListener g_bleListener = {
    .stateListenerId = -1,
    .scanListenerId = -1
};

static SoftBusMessage *CreateBleHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj);
static int32_t AddRecvMessage(const char *key, const uint32_t *capBitMap, bool needBrMac);
static int32_t MatchRecvMessage(const uint32_t *publishInfoMap, uint32_t *capBitMap);
static RecvMessage *GetRecvMessage(const char *key);
static int32_t StartAdvertiser(int32_t adv);
static int32_t StopAdvertiser(int32_t adv);
static int32_t UpdateAdvertiser(int32_t adv);
static int32_t ReplyPassiveNonBroadcast(void);
static void ClearRecvMessage(void);
static int32_t StopScaner(void);

/* This function is used to compatibled with mobile phone, will remove later */
static int ConvertCapBitMap(int oldCap)
{
    switch (oldCap) {
        case 0x80: // osdCapability
            return 0x10;
        case 0x8:  // castPlus
            return 0x2;
        case 0x20: // dvkit
            return 0x4;
        default:
            return oldCap;
    }
    return oldCap;
}

static void ResetInfoUpdate(int adv)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ResetInfoUpdate");
    if (adv == NON_ADV_ID) {
        g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].needUpdate = false;
        g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdate = false;
    } else {
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdate = false;
        g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdate = false;
    }
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

static void BleAdvEnableCallback(int advId, int status)
{
    if (advId >= NUM_ADVERTISER || status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BleAdvEnableCallback failed");
        return;
    }
    g_bleAdvertiser[advId].isAdvertising = true;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "Enable ble advertiser adv:%d", advId);
}

static void BleAdvDisableCallback(int advId, int status)
{
    if (advId >= NUM_ADVERTISER || status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BleAdvDisableCallback failed");
        return;
    }
    g_bleAdvertiser[advId].isAdvertising = false;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "Disable ble advertiser adv:%d", advId);
}

static void BleAdvDataCallback(int advId, int status)
{
    if (advId >= NUM_ADVERTISER || status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BleAdvDataCallback failed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "Set adv data success adv:%d", advId);
}

static void BleAdvUpdateCallback(int advId, int status)
{
    if (advId >= NUM_ADVERTISER || status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BleAdvUpdateCallback failed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "update advertiser success adv:%d", advId);
}

static bool CheckScanner(void)
{
    (void)pthread_mutex_lock(&g_bleInfoLock);
    uint32_t scanCapBit = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0];
    (void)pthread_mutex_unlock(&g_bleInfoLock);
    if (scanCapBit == 0x0) {
        return false;
    }
    return true;
}

static int32_t ScanFilter(const SoftBusBleScanResult *scanResultData)
{
    if (scanResultData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t advLen = scanResultData->advLen;
    unsigned char *advData = scanResultData->advData;
    if (scanResultData->dataStatus != SOFTBUS_BLE_DATA_COMPLETE || advLen < (POS_TLV + ADV_HEAD_LEN)) {
        return SOFTBUS_ERR;
    }
    if (advData[POS_UUID] != (unsigned char)(BLE_UUID & BYTE_MASK) ||
        advData[POS_UUID + 1] != (unsigned char)((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK)) {
        return SOFTBUS_ERR;
    }
    if (advData[POS_VERSION + ADV_HEAD_LEN] != BLE_VERSION) {
        return SOFTBUS_ERR;
    }
    if (!CheckScanner()) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "no need to scan");
        (void)StopScaner();
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_bleInfoLock);
    return SOFTBUS_OK;
}

static void ProcessNearbyPacket(const SoftBusBleScanResult *scanResultData)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ProcessNearbyPacket");
}

static void ProcessDisConPacket(const unsigned char *advData, uint32_t advLen, DeviceInfo *foundInfo)
{
    if (GetDeviceInfoFromDisAdvData(foundInfo, advData, advLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceInfoFromDisAdvData failed");
        return;
    }
    (void)pthread_mutex_lock(&g_bleInfoLock);
    if ((foundInfo->capabilityBitmap[0] & g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0]) == 0x0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "don't match passive publish capBitMap");
        (void)pthread_mutex_unlock(&g_bleInfoLock);
        return;
    }
    (void)pthread_mutex_unlock(&g_bleInfoLock);
    char key[SHA_HASH_LEN];
    if (GenerateStrHash(advData, advLen, key) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GenerateStrHash failed");
        return;
    }
    if (AddRecvMessage(key, foundInfo->capabilityBitmap, true) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ReplyPassiveNonBroadcast");
        ReplyPassiveNonBroadcast();
    };
}

static void ProcessDisNonPacket(const unsigned char *advData, uint32_t advLen, DeviceInfo *foundInfo)
{
    if (GetDeviceInfoFromDisAdvData(foundInfo, advData, advLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceInfoFromDisAdvData failed");
        return;
    }
    (void)pthread_mutex_lock(&g_bleInfoLock);
    uint32_t subscribeCap = g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] |
                            g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0];
    if (subscribeCap & (foundInfo->capabilityBitmap[0] == 0x0)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Capbitmap unmatch");
        (void)pthread_mutex_unlock(&g_bleInfoLock);
        return;
    }
    foundInfo->capabilityBitmap[0] = subscribeCap & foundInfo->capabilityBitmap[0];
    (void)pthread_mutex_unlock(&g_bleInfoLock);
    g_discBleInnerCb->OnDeviceFound(foundInfo);
}

static void ProcessDistributePacket(const SoftBusBleScanResult *scanResultData)
{
    uint32_t advLen = scanResultData->advLen;
    unsigned char *advData = scanResultData->advData;
    DeviceInfo foundInfo = {0};
    foundInfo.addrNum = 1;
    (void)memcpy_s(foundInfo.addr[0].info.ble.bleMac, BT_ADDR_LEN, scanResultData->addr.addr, BT_ADDR_LEN);
    if ((advData[POS_BUSSINESS_EXTENSION + ADV_HEAD_LEN] & BIT_HEART_BIT) != 0) {
        return;
    }
    if ((advData[POS_BUSSINESS_EXTENSION + ADV_HEAD_LEN] & BIT_CON) != 0) {
        ProcessDisConPacket(advData, advLen, &foundInfo);
    } else {
        ProcessDisNonPacket(advData, advLen, &foundInfo);
    }
}

static void BleScanResultCallback(int listenerId, const SoftBusBleScanResult *scanResultData)
{
    (void)listenerId;
    if (scanResultData == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "scanResultData is NULL");
        return;
    }
    if (ScanFilter(scanResultData) != SOFTBUS_OK) {
        return;
    }
    unsigned char *advData = scanResultData->advData;
    if (advData == NULL) {
        return;
    }
    if ((advData[POS_BUSSINESS + ADV_HEAD_LEN] & DISTRIBUTE_BUSSINESS) == DISTRIBUTE_BUSSINESS) {
        ProcessDistributePacket(scanResultData);
    } else if ((advData[POS_BUSSINESS + ADV_HEAD_LEN] & NEARBY_BUSSINESS) == NEARBY_BUSSINESS) {
        ProcessNearbyPacket(scanResultData);
    }
}

static void BleOnScanStart(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "BleOnScanStart");
    g_isScanning = true;
}

static void BleOnScanStop(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "BleOnScanStop");
    g_isScanning = false;
}

static void BleOnStateChanged(int listenerId, int state)
{
    (void)listenerId;
    SoftBusMessage *msg;
    switch (state) {
        case SOFTBUS_BT_STATE_TURN_ON:
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "BleOnStateChanged to SOFTBUS_BT_STATE_TURNING_ON");
            msg = CreateBleHandlerMsg(RECOVERY, 0, 0, NULL);
            if (msg == NULL) {
                return;
            }
            g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
            break;
        case SOFTBUS_BT_STATE_TURN_OFF:
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "BleOnStateChanged to SOFTBUS_BT_STATE_TURNING_OFF");
            msg = CreateBleHandlerMsg(TURN_OFF, 0, 0, NULL);
            if (msg == NULL) {
                return;
            }
            g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
            break;
        default:
            return;
    }
}

static SoftBusAdvCallback g_advCallback = {
    .AdvEnableCallback = BleAdvEnableCallback,
    .AdvDisableCallback = BleAdvDisableCallback,
    .AdvDataCallback = BleAdvDataCallback,
    .AdvUpdateCallback = BleAdvUpdateCallback
};

static SoftBusScanListener g_scanListener = {
    .OnScanStart = BleOnScanStart,
    .OnScanStop = BleOnScanStop,
    .OnScanResult = BleScanResultCallback
};

static SoftBusBtStateListener g_stateChangedListener = {
    .OnBtStateChanged = BleOnStateChanged
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

static bool GetSameAccount(void)
{
    for (uint32_t index = 0; index < CAPABILITY_MAX_BITNUM; index++) {
        if (g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[index]) {
            return true;
        }
    }
    return false;
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
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetConDeviceInfo input is null");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    uint32_t infoIndex = BLE_SUBSCRIBE | BLE_ACTIVE;
    if (CheckBitMapEmpty(CAPABILITY_NUM, g_bleInfoManager[infoIndex].capBitMap)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "All capbit is zero");
        return SOFTBUS_ERR;
    }
    if (DiscBleGetDeviceIdHash(info->devId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get deviceId failed");
    }
    if (DiscBleGetDeviceName(info->devName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get deviceName failed");
    }
    info->devType = DiscBleGetDeviceType();
    bool isSameAccount = false;
    bool isWakeRemote = false;
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        isSameAccount |= g_bleInfoManager[infoIndex].isSameAccount[pos];
        isWakeRemote |= g_bleInfoManager[infoIndex].isWakeRemote[pos];
    }
    (void)memset_s(info->hwAccountHash, MAX_ACCOUNT_HASH_LEN, 0x0, MAX_ACCOUNT_HASH_LEN);
    if (isSameAccount) {
        if (DiscBleGetShortUserIdHash(info->hwAccountHash) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetShortUserIdHash failed");
        }
    }
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] = g_bleInfoManager[infoIndex].capBitMap[pos];
    }
    return SOFTBUS_OK;
}

static int32_t GetNonDeviceInfo(DeviceInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetNonDeviceInfo input is null");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(info, sizeof(DeviceInfo), 0x0, sizeof(DeviceInfo));
    if (DiscBleGetDeviceIdHash(info->devId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get deviceId failed");
    }
    if (DiscBleGetDeviceName(info->devName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get deviceName failed");
    }
    info->devType = DiscBleGetDeviceType();
    uint32_t passiveCapBitMap[CAPABILITY_NUM] = {0};
    if (MatchRecvMessage(g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap, passiveCapBitMap) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "MatchRecvMessage failed");
        return SOFTBUS_ERR;
    }
    for (uint32_t pos = 0; pos < CAPABILITY_NUM; pos++) {
        info->capabilityBitmap[pos] =
        g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[pos] | passiveCapBitMap[pos];
    }
    if (CheckBitMapEmpty(CAPABILITY_NUM, info->capabilityBitmap)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "All capbit is zero");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BuildBleConfigAdvData(SoftBusBleAdvData *advData, const BoardcastData *boardcastData)
{
    if (advData == NULL || boardcastData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    advData->advData = (unsigned char *)SoftBusCalloc(ADV_DATA_MAX_LEN + ADV_HEAD_LEN);
    advData->scanRspData = (unsigned char *)SoftBusCalloc(RESP_DATA_MAX_LEN + RSP_HEAD_LEN);
    if (advData->advData == NULL || advData->scanRspData == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "malloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    unsigned short advLength = (boardcastData->dataLen > ADV_DATA_MAX_LEN) ? ADV_DATA_MAX_LEN : boardcastData->dataLen;
    advData->advLength = advLength + ADV_HEAD_LEN;
    advData->advData[POS_FLAG_BYTE_LEN] = FLAG_BYTE_LEN;
    advData->advData[POS_FLAG_AD_TYPE] = FLAG_AD_TYPE;
    advData->advData[POS_FLAG_AD_DATA] = FLAG_AD_DATA;
    advData->advData[POS_AD_TYPE] = AD_TYPE;
    advData->advData[POS_UUID] = BLE_UUID & BYTE_MASK;
    advData->advData[POS_UUID + 1] = (BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK;
    advData->advData[POS_PACKET_LENGTH] = advData->advLength - POS_PACKET_LENGTH - 1;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "advData->advLength:%d advLength:%d", advData->advLength, advLength);
    if (memcpy_s(&advData->advData[ADV_HEAD_LEN], advLength, boardcastData->data.advData, advLength) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memcpy err");
        return SOFTBUS_MEM_ERR;
    }
    advData->scanRspLength = boardcastData->dataLen - advLength + RSP_HEAD_LEN;
    advData->scanRspData[POS_RSP_TYPE] = RSP_TYPE;
    advData->scanRspData[POS_COMPANY_ID] = COMPANY_ID & BYTE_MASK;
    advData->scanRspData[POS_COMPANY_ID + 1] = (COMPANY_ID >> BYTE_SHIFT_BIT) & BYTE_MASK;
    if (advData->scanRspLength > RSP_HEAD_LEN) {
        if (memcpy_s(&advData->scanRspData[RSP_HEAD_LEN], advData->scanRspLength,
            boardcastData->data.rspData, advData->scanRspLength) != EOK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memcpy err");
            return SOFTBUS_MEM_ERR;
        }
    }
    advData->scanRspData[POS_RSP_LENGTH] = advData->scanRspLength - POS_RSP_LENGTH - 1;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "advData->scanRspLength:%d POS_RSP_LENGTH:%d",
        advData->scanRspLength, advData->scanRspData[POS_RSP_LENGTH]);
    return SOFTBUS_OK;
}

static void DestoryBleConfigAdvData(SoftBusBleAdvData *advData)
{
    if (advData == NULL) {
        return;
    }
    SoftBusFree(advData->advData);
    SoftBusFree(advData->scanRspData);
}

static int32_t GetBroadcastData(DeviceInfo *info, int32_t advId, BoardcastData *boardcastData)
{
    if (info == NULL || advId >= NUM_ADVERTISER || boardcastData == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetBroadcastData input param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    bool isSameAccount = GetSameAccount();
    bool isWakeRemote = GetWakeRemote();
    if (memset_s(boardcastData->data.data, BOARDCAST_MAX_LEN, 0x0, BOARDCAST_MAX_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memset failed");
        return SOFTBUS_MEM_ERR;
    }
    boardcastData->data.data[POS_VERSION] = BLE_VERSION & BYTE_MASK;
    boardcastData->data.data[POS_BUSSINESS] = DISTRIBUTE_BUSSINESS & BYTE_MASK;
    boardcastData->data.data[POS_BUSSINESS_EXTENSION] = BIT_CUST_DATA_TYPE;
    if (advId == CON_ADV_ID) {
        boardcastData->data.data[POS_BUSSINESS_EXTENSION] |= BIT_CON;
        if (isWakeRemote) {
            boardcastData->data.data[POS_BUSSINESS_EXTENSION] |= BIT_WAKE_UP;
        }
        (void)memcpy_s(&boardcastData->data.data[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN,
            info->hwAccountHash, SHORT_USER_ID_HASH_LEN);
    } else {
        if (DiscBleGetShortUserIdHash(&boardcastData->data.data[POS_USER_ID_HASH]) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetShortUserIdHash failed");
        }
    }
    boardcastData->data.data[POS_CAPABLITY] = info->capabilityBitmap[0] & BYTE_MASK;
    boardcastData->data.data[POS_CAPABLITY_EXTENSION] = 0x0;
    boardcastData->dataLen = POS_TLV;
    char deviceIdHash[SHORT_DEVICE_ID_HASH_LENGTH + 1] = {0};
    if (DiscBleGetDeviceIdHash(deviceIdHash) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get deviceId Hash failed");
    }
    uint8_t devType = info->devType;
    (void)AssembleTLV(boardcastData, TLV_TYPE_DEVICE_ID_HASH, deviceIdHash, SHORT_DEVICE_ID_HASH_LENGTH);
    (void)AssembleTLV(boardcastData, TLV_TYPE_DEVICE_TYPE, &devType, DEVICE_TYPE_LEN);
    if (advId == NON_ADV_ID && g_recvMessageInfo.numNeedBrMac > 0) {
        SoftBusBtAddr addr;
        if (SoftBusGetBtMacAddr(&addr) == SOFTBUS_OK) {
            (void)AssembleTLV(boardcastData, TLV_TYPE_BR_MAC, &addr.addr, BT_ADDR_LEN);
        }
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "boardcastData->dataLen:%d", boardcastData->dataLen);
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
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser == NULL || advertiser->GetDeviceInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get Advertiser adv:%d failed", adv);
        return SOFTBUS_ERR;
    }
    if (advertiser->isAdvertising) {
        if (GetNeedUpdateAdvertiser(adv)) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "advertising need update");
            return UpdateAdvertiser(adv);
        } else {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "advertising no need update");
            return SOFTBUS_OK;
        }
    }
    int32_t ret = advertiser->GetDeviceInfo(&advertiser->deviceInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "advertiser adv:%d GetConDeviceInfo failed", adv);
        return StopAdvertiser(adv);
    }
    BoardcastData boardcastData;
    if (GetBroadcastData(&advertiser->deviceInfo, adv, &boardcastData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetBoardcastData failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvData advData = {0};
    if (BuildBleConfigAdvData(&advData, &boardcastData) != SOFTBUS_OK) {
        DestoryBleConfigAdvData(&advData);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BuildBleConfigAdvData failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvParams advParam = {0};
    BuildAdvParam(&advParam);
    if (SoftBusSetAdvData(adv, &advData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Set ble adv adv:%d data failed", adv);
        DestoryBleConfigAdvData(&advData);
        return SOFTBUS_ERR;
    }
    if (SoftBusStartAdv(advertiser->advId, &advParam) != SOFTBUS_OK) {
        DestoryBleConfigAdvData(&advData);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "start adv adv:%d failed", adv);
        return SOFTBUS_ERR;
    }
    ResetInfoUpdate(adv);
    DestoryBleConfigAdvData(&advData);
    return SOFTBUS_OK;
}

static int32_t StopAdvertiser(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get Advertiser adv:%d failed", adv);
        return SOFTBUS_MEM_ERR;
    }
    if (!advertiser->isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "advertiser adv adv:%d is already stopped.", adv);
        return SOFTBUS_OK;
    }
    if (SoftBusStopAdv(advertiser->advId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "stop advertiser advId:%d failed.", adv);
    }
    if (adv == NON_ADV_ID) {
        (void)pthread_mutex_lock(&g_recvMessageInfo.lock);
        ClearRecvMessage();
        (void)pthread_mutex_unlock(&g_recvMessageInfo.lock);
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAdvertiser(int32_t adv)
{
    DiscBleAdvertiser *advertiser = &g_bleAdvertiser[adv];
    if (advertiser == NULL || advertiser->GetDeviceInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get Advertiser adv:%d failed", adv);
        return SOFTBUS_ERR;
    }
    int32_t ret = advertiser->GetDeviceInfo(&advertiser->deviceInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "advertiser adv:%d GetConDeviceInfo failed", adv);
        return StopAdvertiser(adv);
    }
    BoardcastData boardcastData;
    if (GetBroadcastData(&advertiser->deviceInfo, adv, &boardcastData) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvData advData = {0};
    if (BuildBleConfigAdvData(&advData, &boardcastData) != SOFTBUS_OK) {
        DestoryBleConfigAdvData(&advData);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "BuildBleConfigAdvData failed");
        return SOFTBUS_ERR;
    }
    SoftBusBleAdvParams advParam = {0};
    BuildAdvParam(&advParam);
    if (SoftBusUpdateAdv(advertiser->advId, &advData, &advParam) != SOFTBUS_OK) {
        DestoryBleConfigAdvData(&advData);
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "UpdateAdv failed");
        return SOFTBUS_ERR;
    }
    ResetInfoUpdate(adv);
    DestoryBleConfigAdvData(&advData);
    return SOFTBUS_OK;
}

static int32_t InitScanner(void)
{
    g_isScanning = false;
    return SOFTBUS_OK;
}

static int32_t GetScannerParam(int32_t freq, SoftBusBleScanParams *scanParam)
{
    if (freq >= FREQ_BUTT) {
        return SOFTBUS_INVALID_PARAM;
    }
    scanParam->scanInterval = (uint16_t)g_scanTable[freq].scanInterval;
    scanParam->scanWindow = (uint16_t)g_scanTable[freq].scanWindow;
    scanParam->scanType = SOFTBUS_BLE_SCAN_TYPE_ACTIVE;
    scanParam->scanPhy = SOFTBUS_BLE_SCAN_PHY_1M;
    scanParam->scanFilterPolicy = SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL;
    return SOFTBUS_OK;
}

static int32_t StartScaner(void)
{
    if (!CheckScanner()) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "no need to start scanner");
        (void)StopScaner();
        return SOFTBUS_ERR;
    }
    if (g_isScanning) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "scanner already start");
        if (StopScaner() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "stop scanner failed");
            return SOFTBUS_ERR;
        }
    }
    SoftBusBleScanParams scanParam;
    int32_t maxFreq = GetMaxExchangeFreq();
    if (GetScannerParam(maxFreq, &scanParam) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetScannerParam failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusStartScan(g_bleListener.scanListenerId, &scanParam) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "start scan failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartScanner success");
    return SOFTBUS_OK;
}

static int32_t StopScaner(void)
{
    if (!g_isScanning) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "already stop scanning");
        return SOFTBUS_OK;
    }
    if (SoftBusStopScan(g_bleListener.scanListenerId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StopScaner failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "stop scaner");
    return SOFTBUS_OK;
}

static int32_t RegisterCapability(DiscBleInfo *info, const DiscBleOption *option)
{
    if (info == NULL || option == NULL || (option->publishOption == NULL && option->subscribeOption == NULL) ||
        (option->publishOption != NULL && option->subscribeOption != NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t *optionCapBitMap;
    uint32_t custDataLen;
    unsigned char *custData;
    bool isSameAccount = false;
    bool isWakeRemote = false;
    int32_t freq;
    if (option->publishOption != NULL) {
        optionCapBitMap = option->publishOption->capabilityBitmap;
        optionCapBitMap[0] = ConvertCapBitMap(optionCapBitMap[0]);
        custDataLen = option->publishOption->dataLen;
        custData = option->publishOption->capabilityData;
        freq = option->publishOption->freq;
    } else {
        optionCapBitMap = option->subscribeOption->capabilityBitmap;
        optionCapBitMap[0] = ConvertCapBitMap(optionCapBitMap[0]);
        custDataLen = option->subscribeOption->dataLen;
        custData = option->subscribeOption->capabilityData;
        isSameAccount = option->subscribeOption->isSameAccount;
        isWakeRemote = option->subscribeOption->isWakeRemote;
        freq = option->subscribeOption->freq;
    }
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        if (!CheckCapBitMapExist(CAPABILITY_NUM, optionCapBitMap, pos)) {
            continue;
        }
        if (!CheckCapBitMapExist(CAPABILITY_NUM, info->capBitMap, pos)) {
            (void)SetCapBitMapPos(CAPABILITY_NUM, info->capBitMap, pos);
            info->needUpdate = true;
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "RegisterCapability set update");
        }
        info->capCount[pos] += 1;
        info->isSameAccount[pos] = isSameAccount;
        info->isWakeRemote[pos] = isWakeRemote;
        info->freq[pos] = freq;
        if (custData == NULL) {
            info->capDataLen[pos] = 0;
            continue;
        }
        if (info->capabilityData[pos] == NULL) {
            info->capabilityData[pos] = SoftBusCalloc(CUST_DATA_MAX_LEN);
            if (info->capabilityData[pos] == NULL) {
                info->capDataLen[pos] = 0;
                return SOFTBUS_MALLOC_ERR;
            }
        }
        if (memcpy_s(info->capabilityData[pos], CUST_DATA_MAX_LEN, custData, custDataLen) != EOK) {
            info->capDataLen[pos] = 0;
            return SOFTBUS_MEM_ERR;
        }
        info->capDataLen[pos] = custDataLen;
    }
    return SOFTBUS_OK;
}

static int32_t UnregisterCapability(DiscBleInfo *info, DiscBleOption *option)
{
    if (info == NULL || option == NULL ||
        (option->publishOption == NULL && option->subscribeOption == NULL) ||
        (option->publishOption != NULL && option->subscribeOption != NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t *optionCapBitMap;
    bool isSameAccount = false;
    bool isWakeRemote = false;
    if (option->publishOption != NULL) {
        optionCapBitMap = option->publishOption->capabilityBitmap;
        optionCapBitMap[0] = ConvertCapBitMap(optionCapBitMap[0]);
    } else {
        optionCapBitMap = option->subscribeOption->capabilityBitmap;
        optionCapBitMap[0] = ConvertCapBitMap(optionCapBitMap[0]);
        isSameAccount = option->subscribeOption->isSameAccount;
        isWakeRemote = option->subscribeOption->isWakeRemote;
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
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "UnregisterCapability set update");
        }
        info->isSameAccount[pos] = isSameAccount;
        info->isWakeRemote[pos] = isWakeRemote;
        info->freq[pos] = -1;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessBleInfoManager(bool isStart, uint8_t publishFlags, uint8_t activeFlags, const void *option)
{
    if (option == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    DiscBleOption regOption;
    if (publishFlags == BLE_PUBLISH) {
        regOption.publishOption = (PublishOption *)option;
        regOption.subscribeOption = NULL;
    } else {
        regOption.publishOption = NULL;
        regOption.subscribeOption = (SubscribeOption *)option;
    }
    unsigned char index = publishFlags | activeFlags;
    if (pthread_mutex_lock(&g_bleInfoLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (isStart) {
        if (RegisterCapability(&g_bleInfoManager[index], &regOption) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "RegisterCapability failed.");
            pthread_mutex_unlock(&g_bleInfoLock);
            return SOFTBUS_ERR;
        }
    } else {
        if (UnregisterCapability(&g_bleInfoManager[index], &regOption) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "UnregisterCapability failed.");
            pthread_mutex_unlock(&g_bleInfoLock);
            return SOFTBUS_ERR;
        }
    }
    pthread_mutex_unlock(&g_bleInfoLock);
    return SOFTBUS_OK;
}

static SoftBusMessage *CreateBleHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ble create handler msg failed");
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

static int32_t ProcessBleDiscFunc(bool isStart, uint8_t publishFlags,
    uint8_t activeFlags, int32_t funcCode, void *option)
{
    if (option == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusGetBtState() != BLE_ENABLE) {
        return SOFTBUS_ERR;
    }
    int32_t ret = ProcessBleInfoManager(isStart, publishFlags, activeFlags, (void *)option);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    SoftBusMessage *msg = CreateBleHandlerMsg(funcCode, 0, 0, NULL);
    if (msg == NULL) {
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

static DiscoveryFuncInterface g_discBleFuncInterface = {
    .Publish = BleStartActivePublish,
    .StartScan = BleStartPassivePublish,
    .Unpublish = BleStopActivePublish,
    .StopScan = BleStopPassivePublish,
    .StartAdvertise = BleStartActiveDiscovery,
    .Subscribe = BleStartPassiveDiscovery,
    .StopAdvertise = BleStopActiveDiscovery,
    .Unsubscribe = BleStopPassiveDiscovery
};

static int32_t InitAdvertiser(void)
{
    int conAdvId = SoftBusGetAdvChannel(&g_advCallback);
    int nonAdvId = SoftBusGetAdvChannel(&g_advCallback);
    if (conAdvId < 0 || nonAdvId < 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "SoftBusGetAdvChannel failed");
        (void)SoftBusReleaseAdvChannel(conAdvId);
        (void)SoftBusReleaseAdvChannel(nonAdvId);
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < NUM_ADVERTISER; i++) {
        g_bleAdvertiser[i].isAdvertising = false;
    }
    g_bleAdvertiser[CON_ADV_ID].GetDeviceInfo = GetConDeviceInfo;
    g_bleAdvertiser[CON_ADV_ID].advId = conAdvId;
    g_bleAdvertiser[NON_ADV_ID].GetDeviceInfo = GetNonDeviceInfo;
    g_bleAdvertiser[NON_ADV_ID].advId = nonAdvId;
    return SOFTBUS_OK;
}

static int32_t InitDiscBleInfo(DiscBleInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(info, sizeof(DiscBleInfo), 0x0, sizeof(DiscBleInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        info->freq[pos] = -1;
    }
    return SOFTBUS_OK;
}

static int32_t DiscBleInitPublish(void)
{
    int32_t ret = InitDiscBleInfo(&g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE]);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Init active publish failed");
        return ret;
    }
    ret = InitDiscBleInfo(&g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE]);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Init passive publish failed");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DiscBleInitSubscribe(void)
{
    int32_t ret = InitDiscBleInfo(&g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE]);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Init active subscribe failed");
        return ret;
    }
    ret = InitDiscBleInfo(&g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE]);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Init passive subscribe failed");
        return ret;
    }
    return SOFTBUS_OK;
}

static void StartActivePublish(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartActivePublish");
    if (msg == NULL || msg->what != PUBLISH_ACTIVE_SERVICE) {
        return;
    }
    (void)StartAdvertiser(NON_ADV_ID);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartActivePublish finish");
}

static void StartPassivePublish(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartPassivePublish");
    if (msg == NULL || msg->what != PUBLISH_PASSIVE_SERVICE) {
        return;
    }
    if (g_bleAdvertiser[NON_ADV_ID].isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "UpdateAdvertiser %d", NON_ADV_ID);
        UpdateAdvertiser(NON_ADV_ID);
    }
    (void)StartScaner();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartPassivePublish finish");
}

static void StartActiveDiscovery(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartActiveDiscovery");
    if (msg == NULL || msg->what != START_ACTIVE_DISCOVERY) {
        return;
    }
    if (StartAdvertiser(CON_ADV_ID) == SOFTBUS_OK) {
        (void)StartScaner();
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartActiveDiscovery finish");
}

static void StartPassiveDiscovery(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartPassiveDiscovery");
    if (msg == NULL || msg->what != START_PASSIVE_DISCOVERY) {
        return;
    }
    (void)StartScaner();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartPassiveDiscovery finish");
}

static void Recovery(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "recovery");
    if (msg == NULL || msg->what != RECOVERY) {
        return;
    }
    (void)StartAdvertiser(CON_ADV_ID);
    (void)StartAdvertiser(NON_ADV_ID);
    (void)StartScaner();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "recovery finish");
}

static void BleDiscTurnOff(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "disc ble turn off");
    if (msg == NULL || msg->what != RECOVERY) {
        return;
    }
    (void)StopAdvertiser(NON_ADV_ID);
    (void)StopAdvertiser(CON_ADV_ID);
    (void)StopScaner();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "disc ble turn off finish");
}

static int32_t ReplyPassiveNonBroadcast(void)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ReplyPassiveNonBroadcast");
    SoftBusMessage *msg = CreateBleHandlerMsg(REPLY_PASSIVE_NON_BROADCAST, 0, 0, NULL);
    if (msg == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    g_discBleHandler.looper->PostMessage(g_discBleHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t RemoveRecvMsgFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "RemoveRecvMsgFunc");
    int64_t key = (int64_t)args;
    if (msg->what == PROCESS_TIME_OUT && msg->arg1 == key) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "find key");
        return 0;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "not find key");
    return 1;
}

static RecvMessage *GetRecvMessage(const char *key)
{
    if (key == NULL) {
        return NULL;
    }
    RecvMessage *msg;
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        if (memcmp((void *)key, (void *)msg->key, SHA_HASH_LEN) == 0) {
            return msg;
        }
    }
    return NULL;
}

static int32_t MatchRecvMessage(const uint32_t *publishInfoMap, uint32_t *capBitMap)
{
    if (capBitMap == NULL || publishInfoMap == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    (void)pthread_mutex_lock(&g_recvMessageInfo.lock);
    RecvMessage *msg;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "recv message cnt: %d", g_recvMessageInfo.numNeedResp);
    LIST_FOR_EACH_ENTRY(msg, &g_recvMessageInfo.node, RecvMessage, node) {
        for (uint32_t index = 0; index < CAPABILITY_NUM; index++) {
            capBitMap[index] = msg->capBitMap[index] & publishInfoMap[index];
        }
    }
    (void)pthread_mutex_unlock(&g_recvMessageInfo.lock);
    return SOFTBUS_OK;
}

static void StartTimeout(const char *key)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "StartTimeout");
    if (key == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "key is null");
        return;
    }
    if (pthread_mutex_lock(&g_recvMessageInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (GetRecvMessage(key) == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "key is not exists");
        pthread_mutex_unlock(&g_recvMessageInfo.lock);
        return;
    }
    pthread_mutex_unlock(&g_recvMessageInfo.lock);
    SoftBusMessage *msg = CreateBleHandlerMsg(PROCESS_TIME_OUT, (uint64_t)key, 0, NULL);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "malloc msg failed");
        return;
    }
    g_discBleHandler.looper->PostMessageDelay(g_discBleHandler.looper, msg, BLE_MSG_TIME_OUT);
}

static void RemoveTimeout(const char *key)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "RemoveTimeout");
    if (key == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "key is null");
        return;
    }
    if (pthread_mutex_lock(&g_recvMessageInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (GetRecvMessage(key) == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "key is not in recv message");
        pthread_mutex_unlock(&g_recvMessageInfo.lock);
        return;
    }
    pthread_mutex_unlock(&g_recvMessageInfo.lock);
    g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler,
        RemoveRecvMsgFunc, (void *)key);
}

static int32_t AddRecvMessage(const char *key, const uint32_t *capBitMap, bool needBrMac)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "AddRecvMessage");
    if (capBitMap == NULL || key == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "AddRecvMessage input param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_recvMessageInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    RecvMessage *recvMsg = GetRecvMessage(key);
    if (recvMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "key is not exit");
        recvMsg = SoftBusCalloc(sizeof(RecvMessage));
        if (recvMsg == NULL) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "malloc recv msg failed");
            pthread_mutex_unlock(&g_recvMessageInfo.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(&recvMsg->key, SHA_HASH_LEN, key, SHA_HASH_LEN) != EOK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Copy key to create recv msg failed");
            SoftBusFree(recvMsg);
            pthread_mutex_unlock(&g_recvMessageInfo.lock);
            return SOFTBUS_MEM_ERR;
        }
        for (uint32_t index = 0; index < CAPABILITY_NUM; index++) {
            recvMsg->capBitMap[index] = capBitMap[index];
        }
        recvMsg->needBrMac = needBrMac;
        g_recvMessageInfo.numNeedBrMac++;
        g_recvMessageInfo.numNeedResp++;
        ListTailInsert(&g_recvMessageInfo.node, &recvMsg->node);
        pthread_mutex_unlock(&g_recvMessageInfo.lock);
    } else {
        pthread_mutex_unlock(&g_recvMessageInfo.lock);
        RemoveTimeout(recvMsg->key);
    }
    StartTimeout(recvMsg->key);
    return SOFTBUS_OK;
}

static void RemoveRecvMessage(uint64_t key)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "RemoveRecvMessage");
    if (pthread_mutex_lock(&g_recvMessageInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    RecvMessage *recvMsg = GetRecvMessage((char *)key);
    if (recvMsg != NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "recvMsg founded");
        g_discBleHandler.looper->RemoveMessageCustom(g_discBleHandler.looper, &g_discBleHandler,
            RemoveRecvMsgFunc, key);
        if (recvMsg->needBrMac) {
            g_recvMessageInfo.numNeedBrMac--;
        }
        g_recvMessageInfo.numNeedResp--;
        ListDelete(&recvMsg->node);
        SoftBusFree(recvMsg);
    } else {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "recvMsg is not find.");
    }
    pthread_mutex_unlock(&g_recvMessageInfo.lock);
}

static void ClearRecvMessage(void)
{
    while (!IsListEmpty(&(g_recvMessageInfo.node))) {
        RecvMessage *msg = (RecvMessage *)LIST_ENTRY((&g_recvMessageInfo.node)->next, RecvMessage, node);
        ListDelete(&msg->node);
        SoftBusFree(msg);
    }
}

static void ProcessTimeout(SoftBusMessage *msg)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ProcessTimeout");
    if (msg == NULL || msg->what != PROCESS_TIME_OUT) {
        return;
    }
    RemoveRecvMessage(msg->arg1);
    UpdateAdvertiser(NON_ADV_ID);
}

static void DiscBleMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
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
            (void)StartScaner();
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
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "wrong msg what: %d", msg->what);
            break;
    }
    return;
}

static int32_t DiscBleLooperInit(void)
{
    g_discBleHandler.name = "ble_disc_handler";
    g_discBleHandler.HandleMessage = DiscBleMsgHandler;
    g_discBleHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_discBleHandler.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "get looper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitBleListener(void)
{
    g_bleListener.stateListenerId = SoftBusAddBtStateListener(&g_stateChangedListener);
    g_bleListener.scanListenerId = SoftBusAddScanListener(&g_scanListener);
    if (g_bleListener.stateListenerId < 0 || g_bleListener.scanListenerId < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

DiscoveryFuncInterface *DiscBleInit(DiscInnerCallback *discInnerCb)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "DiscBleInit");
    ListInit(&g_recvMessageInfo.node);
    if (discInnerCb == NULL || discInnerCb->OnDeviceFound == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "discInnerCb invalid.");
        goto EXIT;
    }
    g_discBleInnerCb = discInnerCb;
    if (pthread_mutex_init(&g_recvMessageInfo.lock, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Init ble recvMsg lock failed");
        goto EXIT;
    }
    if (DiscBleLooperInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "disc ble Init looper falied");
        goto EXIT;
    }
    if (DiscBleInitPublish() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "disc ble Init publish falied");
        goto EXIT;
    }
    if (DiscBleInitSubscribe() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "disc ble Init subscribe falied");
        goto EXIT;
    }
    if (InitBleListener() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "init ble listener failed");
        goto EXIT;
    }
    if (InitAdvertiser() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "init advertiser failed");
        goto EXIT;
    }
    if (InitScanner() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "init scanner failed");
        goto EXIT;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "DiscBleInit success");
    return &g_discBleFuncInterface;

EXIT:
    DiscBleDeinit();
    return NULL;
}

static bool CheckLockInit(pthread_mutex_t *lock)
{
    if (pthread_mutex_lock(lock) != 0) {
        return false;
    }
    pthread_mutex_unlock(lock);
    return true;
}

static void RecvMessageDeinit(void)
{
    ClearRecvMessage();
    if (CheckLockInit(&g_recvMessageInfo.lock)) {
        (void)pthread_mutex_destroy(&g_recvMessageInfo.lock);
    }
    g_recvMessageInfo.numNeedBrMac = 0;
    g_recvMessageInfo.numNeedResp = 0;
}

static void AdvertiserDeinit(void)
{
    (void)SoftBusReleaseAdvChannel(g_bleAdvertiser[CON_ADV_ID].advId);
    (void)SoftBusReleaseAdvChannel(g_bleAdvertiser[NON_ADV_ID].advId);
    for (uint32_t index = 0; index < NUM_ADVERTISER; index++) {
        (void)memset_s(&g_bleAdvertiser[index], sizeof(DiscBleAdvertiser), 0x0, sizeof(DiscBleAdvertiser));
    }
}

static void BleListenerDeinit(void)
{
    (void)SoftBusRemoveBtStateListener(g_bleListener.stateListenerId);
    (void)SoftBusRemoveScanListener(g_bleListener.scanListenerId);
}

static void DiscBleInfoDeinit(void)
{
    for (uint32_t index = 0; index < BLE_INFO_COUNT; index++) {
        (void)memset_s(&g_bleInfoManager[index], sizeof(DiscBleInfo), 0x0, sizeof(DiscBleInfo));
    }
}

void DiscBleDeinit(void)
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