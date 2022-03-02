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

#define BEAT_REQ_LIFETIME_IN_MEM (60 * 60 * HB_TIME_FACTOR)

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

static void HbMgrRelayToMaster(const char *udidHash, ConnectionAddrType type);
static int32_t HbMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type);
static int32_t HbMgrUpdateDevInfo(DeviceInfo *device, int32_t weight, int32_t localMasterWeight);

static HeartbeatImpl g_hbImpl[HB_IMPL_TYPE_MAX] = {
    [HB_IMPL_TYPE_BLE] = {
        .init = LnnInitBleHeartbeat,
        .onOnceBegin = LnnOnceBleHbBegin,
        .onOnceEnd = LnnOnceBleHbEnd,
        .stop = LnnStopBleHeartbeat,
        .deinit = LnnDeinitBleHeartbeat,
    },
};

static LnnHeartbeatImplCallback g_hbCallback = {
    .onRelay = HbMgrRelayToMaster,
    .onRecvHigherWeight = HbMgrRecvHigherWeight,
    .onUpdateDev = HbMgrUpdateDevInfo,
};

static SoftBusList *g_hbUpdateInfoList = NULL;

static int32_t FirstSetUpdateReqTime(DeviceInfo *device, int32_t weight, int32_t localMasterWeight, uint64_t updateTime)
{
    HeartbeatUpdateReq *item = NULL;

    item = (HeartbeatUpdateReq *)SoftBusMalloc(sizeof(HeartbeatUpdateReq));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB item malloc err");
        return SOFTBUS_MALLOC_ERR;
    }
    item->device = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (item->device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB calloc deviceInfo err");
        SoftBusFree(item);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(item->device, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB memcpy_s deviceInfo err");
        SoftBusFree(item->device);
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    item->lastUpdateTime = updateTime;
    item->weight = weight;
    item->localMasterWeight = localMasterWeight;
    ListInit(&item->node);
    ListAdd(&g_hbUpdateInfoList->list, &item->node);
    g_hbUpdateInfoList->cnt++;
    return SOFTBUS_OK;
}

static int32_t SetUpdateReqTime(DeviceInfo *device, int32_t weight, int32_t localMasterWeight, uint64_t updateTime)
{
    HeartbeatUpdateReq *item = NULL;
    HeartbeatUpdateReq *nextItem = NULL;

    if (SoftBusMutexLock(&g_hbUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB lock update info list fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hbUpdateInfoList->list, HeartbeatUpdateReq, node) {
        if (memcmp((void *)item->device->devId, (void *)device->devId, SHORT_UDID_HASH_LEN) == 0 &&
            LnnGetDiscoveryType(item->device->addr[0].type) == LnnGetDiscoveryType(device->addr[0].type)) {
            item->lastUpdateTime = updateTime;
            item->weight = weight;
            item->localMasterWeight = localMasterWeight;
            (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
            return SOFTBUS_OK;
        }
        if ((updateTime - item->lastUpdateTime) > BEAT_REQ_LIFETIME_IN_MEM) {
            ListDelete(&item->node);
            SoftBusFree(item->device);
            SoftBusFree(item);
        }
    }
    if (FirstSetUpdateReqTime(device, weight, localMasterWeight, updateTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first set update req time fail");
        (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
    return SOFTBUS_OK;
}

static bool IsRepeatedUpdateReq(const char *udidHash, ConnectionAddrType type, uint64_t nowTime)
{
    /* ignore repeated (udidHash & DiscoveryType) update request within 10 seconds */
    HeartbeatUpdateReq *item = NULL;

    if (SoftBusMutexLock(&g_hbUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB lock update info list fail");
        return false;
    }
    LIST_FOR_EACH_ENTRY(item, &g_hbUpdateInfoList->list, HeartbeatUpdateReq, node) {
        if (memcmp((void *)item->device->devId, (void *)udidHash, DISC_MAX_DEVICE_ID_LEN) == 0 &&
            LnnGetDiscoveryType(item->device->addr[0].type) == LnnGetDiscoveryType(type) &&
            (nowTime - item->lastUpdateTime < HB_UPDATE_INTERVAL_LEN)) {
            (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
    return false;
}

static int32_t GenHexStringHash(const unsigned char *str, uint32_t len, char *hashStr)
{
    int32_t ret;
    unsigned char hashResult[HB_SHA_HASH_LEN] = {0};

    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB gen str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB gen str hash fail, ret=%d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, len + 1, hashResult, len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB convert bytes to str hash fail ret=%d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static NodeInfo *HbGetMatchNode(const char *devId, const ConnectionAddrType type)
{
    int32_t infoNum, i;
    NodeBasicInfo *info = NULL;
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = {0};

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get all online node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB none online node");
        return NULL;
    }
    DiscoveryType discType = LnnGetDiscoveryType(type);
    for (i = 0; i < infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL || !LnnHasDiscoveryType(nodeInfo, discType)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB node online not have discType:%d", discType);
            continue;
        }
        if (GenHexStringHash((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
            SHORT_UDID_HASH_HEX_LEN, udidHash) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, devId, SHORT_UDID_HASH_HEX_LEN) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB node online udidHash:%s", udidHash);
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static int32_t HbMgrDiscoveryDevice(const DeviceInfo *device)
{
    ConnectionAddr *addr = (ConnectionAddr *)device->addr;
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB discovery device addr is null");
        return SOFTBUS_ERR;
    }
    if (LnnNotifyDiscoveryDevice(addr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB notify device found fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t HbProcessUpdateReq(const DeviceInfo *device, const uint64_t updateTime)
{
    NodeInfo *nodeInfo = HbGetMatchNode(device->devId, device->addr[0].type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) find device udidHash:%s, ConnectionAddrType:%02X",
            device->devId, device->addr[0].type);
        (void)HbMgrDiscoveryDevice(device);
        return SOFTBUS_OK;
    }
    if (LnnSetDistributedHeartbeatTimestamp(nodeInfo->networkId, updateTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB update timeStamp err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    if (LnnRemoveHbFsmMsg(EVENT_HB_DEVICE_LOST, (uint64_t)device->addr[0].type, nodeInfo->networkId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove offline check err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    if (LnnOfflineTimingByHeartbeat(nodeInfo->networkId, device->addr[0].type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set new offline check err, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t HbMgrUpdateDevInfo(DeviceInfo *device, int32_t weight, int32_t localMasterWeight)
{
    SoftBusSysTime times;
    SoftBusGetTime(&times);
    uint64_t nowTime;

    if (device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr update deviceInfo get invalid param");
        return SOFTBUS_ERR;
    }
    nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
    if (IsRepeatedUpdateReq(device->devId, device->addr[0].type, nowTime)) {
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (SetUpdateReqTime(device, weight, localMasterWeight, nowTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB update req time fail, udidHash:%s", device->devId);
        return SOFTBUS_ERR;
    }

    char *deviceType = LnnConvertIdToDeviceType((uint16_t)device->devType);
    if (deviceType == NULL) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, ">> heartbeat(HB) OnTock [udidHash:%s, devTypeHex:%02X,"
        "devTypeStr:%s, ConnectionAddrType:%d, peerWeight:%d, localMasterWeight:%d, nowTime:%llu]", device->devId,
        device->devType, deviceType, device->addr[0].type, weight, localMasterWeight, nowTime);
    return HbProcessUpdateReq(device, nowTime);
}

static int32_t HbMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type)
{
    char localMasterUdid[UDID_BUF_LEN] = {0};

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr recv higher weight get invalid param");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = HbGetMatchNode(udidHash, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB recv higher weight udidhash:%s is not online yet", udidHash);
        return SOFTBUS_OK;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, sizeof(localMasterUdid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get local master udid fail");
        return SOFTBUS_ERR;
    }
    if (strcmp(localMasterUdid, nodeInfo->deviceInfo.deviceUdid) != 0 &&
        LnnNotifyMasterElect(nodeInfo->networkId, nodeInfo->deviceInfo.deviceUdid, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set local master info fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB recv higher weight udidHash:%s, weight:%d", udidHash, weight);
    return SOFTBUS_OK;
}

static void HbMgrRelayToMaster(const char *udidHash, ConnectionAddrType type)
{
    char localUdid[UDID_BUF_LEN] = {0};
    char localMasterUdid[UDID_BUF_LEN] = {0};

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr relay to master get invalid param");
        return;
    }
    NodeInfo *nodeInfo = HbGetMatchNode(udidHash, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB relay to master udidhash:%s is not online yet", udidHash);
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB relay to master get udid err, udidhash:%s", udidHash);
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB relay to master get masterUdid err, udidhash:%s", udidHash);
        return;
    }
    if (strcmp(localMasterUdid, localUdid) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB relay to master process, udidhash:%s", udidHash);
        (void)LnnHbRelayToMaster(type);
    }
}

static int32_t HbInitUpdateList(void)
{
    if (g_hbUpdateInfoList != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB init update list get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    g_hbUpdateInfoList = CreateSoftBusList();
    if (g_hbUpdateInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB create update info list fail");
        return SOFTBUS_ERR;
    }
    g_hbUpdateInfoList->cnt = 0;
    return SOFTBUS_OK;
}

static void HbDeinitUpdateList(void)
{
    HeartbeatUpdateReq *reqItem = NULL;
    HeartbeatUpdateReq *nextreqItem = NULL;

    if (g_hbUpdateInfoList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_hbUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB lock update info list fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(reqItem, nextreqItem, &g_hbUpdateInfoList->list, HeartbeatUpdateReq, node) {
        ListDelete(&reqItem->node);
        SoftBusFree(reqItem->device);
        SoftBusFree(reqItem);
    }
    (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
    DestroySoftBusList(g_hbUpdateInfoList);
    g_hbUpdateInfoList = NULL;
}

void LnnDumpHbMgrUpdateList(void)
{
#define HB_DUMP_UPDATE_INFO_MAX_NUM 10
    int32_t dumpCount = 0;
    char *deviceType = NULL;
    HeartbeatUpdateReq *item = NULL;

    if (SoftBusMutexLock(&g_hbUpdateInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB lock update info list fail");
        return;
    }
    if (IsListEmpty(&g_hbUpdateInfoList->list)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpHbMgrUpdateList count=0");
        (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_hbUpdateInfoList->list, HeartbeatUpdateReq, node) {
        dumpCount++;
        if (dumpCount > HB_DUMP_UPDATE_INFO_MAX_NUM) {
            continue;
        }
        deviceType = LnnConvertIdToDeviceType((uint16_t)item->device->devType);
        if (deviceType == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get deviceType fail, devId:%s", item->device->devId);
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpHbMgrUpdateList count:%d [i:%d, udidHash:%s, "
            "deviceType:%s, ConnectionAddrType:%02X, weight:%d, localMasterWeight:%d, lastUpdateTime:%llu]",
            g_hbUpdateInfoList->cnt, dumpCount, item->device->devId, deviceType, item->device->addr[0].type,
            item->weight, item->localMasterWeight, item->lastUpdateTime);
    }
    (void)SoftBusMutexUnlock(&g_hbUpdateInfoList->lock);
}

void LnnDumpHbOnlineNodeList(void)
{
#define HB_DUMP_ONLINE_NODE_MAX_NUM 5
    int32_t infoNum, i;
    uint64_t oldTimeStamp;
    NodeBasicInfo *info = NULL;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get node info fail");
        return;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnDumpHbOnlineNodeList count=0");
        return;
    }
    for (i = 0; i < infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL || i > HB_DUMP_ONLINE_NODE_MAX_NUM) {
            continue;
        }
        if (LnnGetDistributedHeartbeatTimestamp(info[i].networkId, &oldTimeStamp) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get timeStamp err, nodeInfo i=%d", i);
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnDumpHbOnlineNodeList count:%d [i:%d, deviceName:%s,"
            "deviceTypeId:%d, masterWeight:%d, discoveryType:%d, oldTimeStamp:%llu]", infoNum, i + 1,
            nodeInfo->deviceInfo.deviceName, nodeInfo->deviceInfo.deviceTypeId, nodeInfo->masterWeight,
            nodeInfo->discoveryType, oldTimeStamp);
    }
    SoftBusFree(info);
}

int32_t LnnHbMgrInit(void)
{
    int32_t i, ret;
    for (i = 0; i < HB_IMPL_TYPE_MAX; ++i) {
        if (g_hbImpl[i].init == NULL) {
            continue;
        }
        ret = g_hbImpl[i].init(&g_hbCallback);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB init heartbeat impl(%d) fail, ret=%d", i, ret);
            return SOFTBUS_ERR;
        }
    }
    if (HbInitUpdateList() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB init update list fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnHbMgrOneCycleBegin(void)
{
    int32_t i, ret;
    for (i = 0; i < HB_IMPL_TYPE_MAX; ++i) {
        if (g_hbImpl[i].onOnceBegin == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat(%d)", i);
            continue;
        }
        ret = g_hbImpl[i].onOnceBegin();
        if (ret == SOFTBUS_NOT_IMPLEMENT) {
            continue;
        }
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start heartbeat impl(%d) fail, ret=%d", i, ret);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnHbMgrOneCycleEnd(void)
{
    int32_t i, ret;
    for (i = 0; i < HB_IMPL_TYPE_MAX; ++i) {
        if (g_hbImpl[i].onOnceEnd == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat(%d)", i);
            continue;
        }
        ret = g_hbImpl[i].onOnceEnd();
        if (ret == SOFTBUS_NOT_IMPLEMENT) {
            continue;
        }
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB once heartbeat impl(%d) fail, ret=%d", i, ret);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnHbMgrStop(void)
{
    int32_t i, ret;
    for (i = 0; i < HB_IMPL_TYPE_MAX; ++i) {
        if (g_hbImpl[i].stop == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat(%d)", i);
            continue;
        }
        ret = g_hbImpl[i].stop();
        if (ret == SOFTBUS_NOT_IMPLEMENT) {
            continue;
        }
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop heartbeat impl(%d) fail, ret=%d", i, ret);
            continue;
        }
    }
    return SOFTBUS_OK;
}

void LnnHbMgrDeinit(void)
{
    int32_t i;
    for (i = 0; i < HB_IMPL_TYPE_MAX; ++i) {
        if (g_hbImpl[i].deinit == NULL) {
            continue;
        }
        if (g_hbImpl[i].deinit() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB deinit heartbeat impl(%d) fail", i);
            continue;
        }
    }
    HbDeinitUpdateList();
}
