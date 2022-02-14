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

#include "lnn_heartbeat_manager.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define BEAT_REQ_LIFETIME_IN_MEM (60 * 60 * HEARTBEAT_TIME_FACTOR)

typedef struct {
    ListNode node;
    DeviceInfo *device;
    int32_t weight;
    int32_t localMasterWeight;
    uint64_t lastUpdateTime;
} HeartbeatUpdateReq;

typedef struct {
    int32_t (*init)(LnnHeartbeatImplCallback *callback);
    int32_t (*onOnceBegin)(void);
    int32_t (*onOnceEnd)(void);
    int32_t (*stop)(void);
    int32_t (*deinit)(void);
} HeartbeatImpl;

static void BeatMgrRelayToMaster(const char *udidHash, ConnectionAddrType type);
static int32_t BeatMgrRecvHigherWight(const char *udidHash, int32_t weight, ConnectionAddrType type);
static int32_t BeatMgrUpdateDevInfo(DeviceInfo *device, int32_t weight, int32_t localMasterWeight);

static HeartbeatImpl g_heartbeatImpl[LNN_BEAT_IMPL_TYPE_MAX] = {
    [LNN_BEAT_IMPL_TYPE_BLE] = {
        .init = LnnInitBleHeartbeat,
        .onOnceBegin = LnnOnceBleBeatBegin,
        .onOnceEnd = LnnOnceBleBeatEnd,
        .stop = LnnStopBleHeartbeat,
        .deinit = LnnDeinitBleHeartbeat,
    },
};

static LnnHeartbeatImplCallback g_heartbeatCallback = {
    .onRelay = BeatMgrRelayToMaster,
    .onRecvHigherWeight = BeatMgrRecvHigherWight,
    .onUpdateDev = BeatMgrUpdateDevInfo,
};

static SoftBusList *g_beatUpdateInfoList = NULL;

static int32_t FirstSetUpdateReqTime(DeviceInfo *device, int32_t weight, int32_t localMasterWeight,
    uint64_t *updateTime)
{
    HeartbeatUpdateReq *item = NULL;
    item = (HeartbeatUpdateReq *)SoftBusMalloc(sizeof(HeartbeatUpdateReq));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat item malloc err");
        return SOFTBUS_MALLOC_ERR;
    }

    item->device = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (item->device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat device malloc err");
        SoftBusFree(item);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(item->device, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat device memcpy_s err");
        SoftBusFree(item->device);
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }

    item->lastUpdateTime = *updateTime;
    item->weight = weight;
    item->localMasterWeight = localMasterWeight;
    ListInit(&item->node);
    ListAdd(&g_beatUpdateInfoList->list, &item->node);
    g_beatUpdateInfoList->cnt++;
    return SOFTBUS_OK;
}

static int32_t SetUpdateReqTime(DeviceInfo *device, int32_t weight, int32_t localMasterWeight,
    uint64_t *updateTime)
{
    HeartbeatUpdateReq *item = NULL;
    HeartbeatUpdateReq *nextItem = NULL;
    if (SoftBusMutexLock(&g_beatUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock BeatMgrUpdateList fail");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_beatUpdateInfoList->list, HeartbeatUpdateReq, node) {
        if (memcmp((void *)item->device->devId, (void *)device->devId, SHORT_UDID_HASH_LEN) == 0 &&
            LnnGetDiscoveryType(item->device->addr[0].type) == LnnGetDiscoveryType(device->addr[0].type)) {
            item->lastUpdateTime = *updateTime;
            item->weight = weight;
            item->localMasterWeight = localMasterWeight;
            (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
            return SOFTBUS_OK;
        }
        if ((*updateTime - item->lastUpdateTime) > BEAT_REQ_LIFETIME_IN_MEM) {
            ListDelete(&item->node);
            SoftBusFree(item->device);
            SoftBusFree(item);
        }
    }

    FirstSetUpdateReqTime(device, weight, localMasterWeight, updateTime);
    (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
    return SOFTBUS_OK;
}

static bool IsRepeatedUpdateReq(const char *udidHash, ConnectionAddrType type, uint64_t *nowTime)
{
    /* ignore repeated (udidHash & DiscoveryType) update callbacks within 10 seconds */
    HeartbeatUpdateReq *item = NULL;
    if (SoftBusMutexLock(&g_beatUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock BeatMgrUpdateList fail");
        return false;
    }

    LIST_FOR_EACH_ENTRY(item, &g_beatUpdateInfoList->list, HeartbeatUpdateReq, node) {
        if (memcmp((void *)item->device->devId, (void *)udidHash, DISC_MAX_DEVICE_ID_LEN) == 0 &&
            LnnGetDiscoveryType(item->device->addr[0].type) == LnnGetDiscoveryType(type) &&
            (*nowTime - item->lastUpdateTime < HEARTBEAT_UPDATE_TIME_PRECISION)) {
            (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
    return false;
}

static int32_t GenHexStringHash(const unsigned char *str, int32_t len, char *hashStr)
{
    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat GenHexStringHash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    unsigned char hashResult[BEAT_SHA_HASH_LEN] = {0};
    int32_t ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat GenerateStrHash fail");
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, len + 1, hashResult, len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat ConvertBytesToHexString fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static NodeInfo *BeatGetMatchNode(const char *devId, const ConnectionAddrType type)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum, i;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat no online node");
        return NULL;
    }

    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    DiscoveryType discType = LnnGetDiscoveryType(type);
    for (i = 0; i < infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL || !LnnHasDiscoveryType(nodeInfo, discType)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "beat node online not have discType:%d", discType);
            continue;
        }
        if (GenHexStringHash((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
            SHORT_UDID_HASH_HEX_LEN, udidHash) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, devId, SHORT_UDID_HASH_HEX_LEN) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "beat node online udidHash:%s, devId:%s", udidHash, devId);
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static int32_t BeatMgrDeviceFound(const DeviceInfo *device)
{
    ConnectionAddr *addr = (ConnectionAddr *)device->addr;
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device addr is null");
        return SOFTBUS_ERR;
    }

    if (LnnNotifyDiscoveryDevice(addr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "notify device found fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BeatProcessUpdateReq(const DeviceInfo *device, const uint64_t *updateTime)
{
    NodeInfo *nodeInfo = BeatGetMatchNode(device->devId, device->addr[0].type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat find device [udidHash:%s, ConnectionAddrType:%02X]",
            device->devId, device->addr[0].type);
        (void)BeatMgrDeviceFound(device);
        return SOFTBUS_OK;
    }

    if (LnnSetDistributedHeartbeatTimestamp(nodeInfo->networkId, updateTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat update timeStamp err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_DEVICE_LOST, (uint64_t)device->addr[0].type,
        nodeInfo->networkId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove offline check err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    if (LnnOfflineTimingByHeartbeat(nodeInfo->networkId, device->addr[0].type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat set new offline check err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BeatMgrUpdateDevInfo(DeviceInfo *device, int32_t weight, int32_t localMasterWeight)
{
    SoftBusSysTime times;
    SoftBusGetTime(&times);
    uint64_t nowTime;

    nowTime = (uint64_t)times.sec * HEARTBEAT_TIME_FACTOR + (uint64_t)times.usec / HEARTBEAT_TIME_FACTOR;
    if (IsRepeatedUpdateReq(device->devId, device->addr[0].type, &nowTime) == true) {
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (SetUpdateReqTime(device, weight, localMasterWeight, &nowTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat updateMgrDev fail, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    char *deviceType = LnnConvertIdToDeviceType((uint16_t)device->devType);
    if (deviceType == NULL) {
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, ">> BeatMgrUpdateDevInfo OnTock [udidHash:%s, devTypeHex:%02X,"
        "devTypeStr:%s, ConnectionAddrType:%d, peerWeight:%d, localMasterWeight:%d, nowTime:%llu]", device->devId,
        device->devType, deviceType, device->addr[0].type, weight, localMasterWeight, nowTime);

    if (BeatProcessUpdateReq(device, &nowTime) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BeatMgrRecvHigherWight(const char *udidHash, int32_t weight, ConnectionAddrType type)
{
    char localMasterUdid[UDID_BUF_LEN] = {0};
    NodeInfo *nodeInfo = BeatGetMatchNode(udidHash, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BeatMgrRecvHigherWight udidhash:%s is not online yet", udidHash);
        return SOFTBUS_OK;
    }

    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, sizeof(localMasterUdid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get local master udid fail");
        return SOFTBUS_ERR;
    }
    if (strcmp(localMasterUdid, nodeInfo->deviceInfo.deviceUdid) != 0 &&
        LnnNotifyMasterElect(nodeInfo->networkId, nodeInfo->deviceInfo.deviceUdid, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat set local master info fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "BeatMgrRecvHigherWight udidHash:%s, weight:%d", udidHash, weight);
    return LnnHeartbeatAsNormalNode();
}

static void BeatMgrRelayToMaster(const char *udidHash, ConnectionAddrType type)
{
    NodeInfo *nodeInfo = BeatGetMatchNode(udidHash, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BeatMgrRelayToMaster udidhash:%s is not online yet", udidHash);
        return;
    }

    char localUdid[UDID_BUF_LEN] = {0};
    char localMasterUdid[UDID_BUF_LEN] = {0};
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN);
    if (strcmp(localMasterUdid, localUdid) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BeatMgrRelayToMaster process. localMasterUdid:%s, localUdid:%s",
            localMasterUdid, localUdid);
        (void)LnnHeartbeatRelayBeat(type);
    }
}

static void BeatInitUpdateList(void)
{
    if (g_beatUpdateInfoList != NULL) {
        return;
    }
    g_beatUpdateInfoList = CreateSoftBusList();
    if (g_beatUpdateInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create BeatMgrUpdateList fail.");
        return;
    }
    g_beatUpdateInfoList->cnt = 0;
}

static void BeatDeinitUpdateList(void)
{
    if (g_beatUpdateInfoList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_beatUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock BeatMgrUpdateList fail");
        return;
    }

    HeartbeatUpdateReq *reqItem = NULL;
    HeartbeatUpdateReq *nextreqItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(reqItem, nextreqItem, &g_beatUpdateInfoList->list, HeartbeatUpdateReq, node) {
        ListDelete(&reqItem->node);
        SoftBusFree(reqItem->device);
        SoftBusFree(reqItem);
    }
    (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
    DestroySoftBusList(g_beatUpdateInfoList);
    g_beatUpdateInfoList = NULL;
}

void LnnDumpBeatMgrUpdateList(void)
{
    HeartbeatUpdateReq *item = NULL;
    if (SoftBusMutexLock(&g_beatUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock BeatMgrUpdateList fail");
        return;
    }
    if (IsListEmpty(&g_beatUpdateInfoList->list)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpBeatMgrUpdateList count:0");
        (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
        return;
    }

    LIST_FOR_EACH_ENTRY(item, &g_beatUpdateInfoList->list, HeartbeatUpdateReq, node) {
        char *deviceType = LnnConvertIdToDeviceType((uint16_t)item->device->devType);
        if (deviceType == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get deviceType fail");
            (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
            return;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpBeatMgrUpdateList count:%d [udidHash:%s, deviceType:%s,"
            "ConnectionAddrType:%02X, weight:%d, localMasterWeight:%d, lastUpdateTime:%llu]",
            g_beatUpdateInfoList->cnt, item->device->devId, deviceType, item->device->addr[0].type, item->weight,
            item->localMasterWeight, item->lastUpdateTime);
    }
    (void)SoftBusMutexUnlock(&g_beatUpdateInfoList->lock);
}

void LnnDumpBeatOnlineNodeList(void)
{
    int32_t infoNum, i;
    uint64_t oldTimeStamp;
    NodeBasicInfo *info = NULL;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get node info fail");
        return;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnDumpBeatOnlineNodeList count:0");
        return;
    }
    for (i = 0; i < infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            continue;
        }
        if (LnnGetDistributedHeartbeatTimestamp(info[i].networkId, &oldTimeStamp) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get timeStamp err, networkId:%s", info[i].networkId);
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpBeatOnlineNodeList count:%d [udid:%s, networkId:%s,"
            "masterUdid:%s, masterWeight:%d, discoveryType:%d, oldTimeStamp:%llu]", infoNum,
            nodeInfo->deviceInfo.deviceUdid, nodeInfo->networkId, nodeInfo->masterUdid, nodeInfo->masterWeight,
            nodeInfo->discoveryType, oldTimeStamp);
    }
    SoftBusFree(info);
}

int32_t LnnHeartbeatMgrInit(void)
{
    uint32_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; ++i) {
        if (g_heartbeatImpl[i].init == NULL) {
            continue;
        }
        if (g_heartbeatImpl[i].init(&g_heartbeatCallback) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init heartbeat impl(%d) fail", i);
            return SOFTBUS_ERR;
        }
    }

    BeatInitUpdateList();
    return SOFTBUS_OK;
}

int32_t LnnHeartbeatMgrStart(void)
{
    uint32_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; ++i) {
        if (g_heartbeatImpl[i].onOnceBegin == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "not support heartbeat(%d)", i);
            continue;
        }
        if (g_heartbeatImpl[i].onOnceBegin() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start heartbeat impl(%d) fail", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnHeartbeatMgrStopAdv(void)
{
    uint32_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; ++i) {
        if (g_heartbeatImpl[i].onOnceEnd == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "not support heartbeat(%d)", i);
            continue;
        }
        if (g_heartbeatImpl[i].onOnceEnd() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "once heartbeat impl(%d) fail", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnHeartbeatMgrStop(void)
{
    uint32_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; ++i) {
        if (g_heartbeatImpl[i].stop == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "not support heartbeat(%d)", i);
            continue;
        }
        if (g_heartbeatImpl[i].stop() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop heartbeat impl(%d) fail", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void LnnHeartbeatMgrDeinit(void)
{
    uint32_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; ++i) {
        if (g_heartbeatImpl[i].deinit == NULL) {
            continue;
        }
        if (g_heartbeatImpl[i].deinit() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "deinit heartbeat impl(%d) fail", i);
            return;
        }
    }

    BeatDeinitUpdateList();
}
