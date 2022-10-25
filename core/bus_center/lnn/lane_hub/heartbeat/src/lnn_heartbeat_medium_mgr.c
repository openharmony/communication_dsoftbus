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

#include "lnn_heartbeat_medium_mgr.h"

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
#include "lnn_heartbeat_utils.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define HB_RECV_INFO_SAVE_LEN (60 * 60 * HB_TIME_FACTOR)

typedef struct {
    ListNode node;
    DeviceInfo *device;
    int32_t weight;
    int32_t masterWeight;
    uint64_t lastRecvTime;
} LnnHeartbeatRecvInfo;

static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType);
static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, int32_t weight, int32_t masterWeight,
    LnnHeartbeatType hbType);
static int32_t HbMediumMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type,
    bool isReElect);

static LnnHeartbeatMediumMgr *g_hbMeidumMgr[HB_MAX_TYPE_COUNT] = {0};

static LnnHeartbeatMediumMgrCb g_hbMediumMgrCb = {
    .onRelay = HbMediumMgrRelayProcess,
    .onReceive = HbMediumMgrRecvProcess,
    .onRecvHigherWeight = HbMediumMgrRecvHigherWeight,
};

static SoftBusList *g_hbRecvList = NULL;

static int32_t HbFirstSaveRecvTime(DeviceInfo *device, int32_t weight, int32_t masterWeight, uint64_t recvTime)
{
    LnnHeartbeatRecvInfo *recvMsg = NULL;

    recvMsg = (LnnHeartbeatRecvInfo *)SoftBusMalloc(sizeof(LnnHeartbeatRecvInfo));
    if (recvMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium mgr malloc recvMsg err");
        return SOFTBUS_MALLOC_ERR;
    }
    recvMsg->device = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (recvMsg->device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium mgr deviceInfo calloc err");
        SoftBusFree(recvMsg);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(recvMsg->device, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB memcpy_s deviceInfo err");
        SoftBusFree(recvMsg->device);
        SoftBusFree(recvMsg);
        return SOFTBUS_MEM_ERR;
    }
    recvMsg->weight = weight;
    recvMsg->lastRecvTime = recvTime;
    recvMsg->masterWeight = masterWeight;
    ListInit(&recvMsg->node);
    ListAdd(&g_hbRecvList->list, &recvMsg->node);
    g_hbRecvList->cnt++;
    return SOFTBUS_OK;
}

static int32_t HbSaveRecvTimeToRemoveRepeat(DeviceInfo *device, int32_t weight, int32_t masterWeight, uint64_t recvTime)
{
    LnnHeartbeatRecvInfo *item = NULL;
    LnnHeartbeatRecvInfo *nextItem = NULL;

    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB save recv time lock recv info list fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        if (memcmp(item->device->devId, device->devId, HB_SHORT_UDID_HASH_LEN) == 0 &&
            LnnConvAddrTypeToDiscType(item->device->addr[0].type) == LnnConvAddrTypeToDiscType(device->addr[0].type)) {
            item->lastRecvTime = recvTime;
            item->weight = weight != 0 ? weight : item->weight;
            item->masterWeight = masterWeight;
            (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
            return SOFTBUS_OK;
        }
        if ((recvTime - item->lastRecvTime) > HB_RECV_INFO_SAVE_LEN) {
            ListDelete(&item->node);
            SoftBusFree(item->device);
            SoftBusFree(item);
            g_hbRecvList->cnt--;
        }
    }
    if (HbFirstSaveRecvTime(device, weight, masterWeight, recvTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first save recv time fail");
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
    return SOFTBUS_OK;
}

static bool HbIsRepeatedRecvInfo(const char *udidHash, ConnectionAddrType type, uint64_t nowTime)
{
    LnnHeartbeatRecvInfo *item = NULL;

    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check repeat lock recv info list fail");
        return false;
    }
    LIST_FOR_EACH_ENTRY(item, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        /* ignore repeated (udidHash & DiscoveryType) heartbeat within 10 seconds */
        if (memcmp(item->device->devId, udidHash, DISC_MAX_DEVICE_ID_LEN) == 0 &&
            LnnConvAddrTypeToDiscType(item->device->addr[0].type) == LnnConvAddrTypeToDiscType(type) &&
            (nowTime - item->lastRecvTime < HB_REMOVE_REPEAD_RECV_LEN)) {
            (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
    return false;
}

static const NodeInfo *HbGetOnlineNodeByRecvInfo(const char *recvUdidHash, const ConnectionAddrType recvAddrType)
{
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get all online node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB none online node");
        return NULL;
    }
    DiscoveryType discType = LnnConvAddrTypeToDiscType(recvAddrType);
    for (i = 0; i < infoNum; ++i) {
        const NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL || !LnnHasDiscoveryType(nodeInfo, discType)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB node online not have discType:%d", discType);
            continue;
        }
        if (LnnGenerateHexStringHash((const unsigned char *)nodeInfo->deviceInfo.deviceUdid, udidHash,
            HB_SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, recvUdidHash, HB_SHORT_UDID_HASH_HEX_LEN) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB node udidHash:%s networkId:%s is online",
                AnonymizesUDID(udidHash), AnonymizesNetworkID(info[i].networkId));
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static int32_t HbUpdateOfflineTimingByRecvInfo(const char *networkId, ConnectionAddrType type, LnnHeartbeatType hbType,
    uint64_t updateTime)
{
    if (LnnSetDLHeartbeatTimestamp(networkId, updateTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB update timeStamp err, networkId:%s",
            AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    if (hbType != HEARTBEAT_TYPE_BLE_V1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB only BLE_V1 support offline timing");
        return SOFTBUS_ERR;
    }
    if (LnnStopOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove offline check err, networkId:%s",
            AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    if (LnnStartOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set new offline check err, networkId:%s",
            AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, int32_t weight, int32_t masterWeight, LnnHeartbeatType hbType)
{
    uint64_t nowTime;
    SoftBusSysTime times;
    const char *devTypeStr = NULL;

    if (device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr recv process get invalid param");
        return SOFTBUS_ERR;
    }
    SoftBusGetTime(&times);
    nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
    if (HbIsRepeatedRecvInfo(device->devId, device->addr[0].type, nowTime)) {
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (HbSaveRecvTimeToRemoveRepeat(device, weight, masterWeight, nowTime) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB save recv time fail, udidHash:%s",
            AnonymizesUDID(device->devId));
        return SOFTBUS_ERR;
    }
    devTypeStr = LnnConvertIdToDeviceType((uint16_t)device->devType);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, ">> heartbeat(HB) OnTock [udidHash:%s, hbType:%d, devTypeHex:%02X, "
        "devTypeStr:%s, ConnectionAddrType:%d, peerWeight:%d, masterWeight:%d, nowTime:%" PRIu64 "]",
        AnonymizesUDID(device->devId), hbType, device->devType, devTypeStr != NULL ? devTypeStr : "",
        device->addr[0].type, weight, masterWeight, nowTime);

    const NodeInfo *nodeInfo = HbGetOnlineNodeByRecvInfo(device->devId, device->addr[0].type);
    if (nodeInfo != NULL) {
        return HbUpdateOfflineTimingByRecvInfo(nodeInfo->networkId, device->addr[0].type, hbType, nowTime);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) find device, udidHash:%s, ConnectionAddrType:%02X",
        AnonymizesUDID(device->devId), device->addr[0].type);
    if (LnnNotifyDiscoveryDevice(device->addr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr recv process notify device found fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_NETWORK_NODE_OFFLINE;
}

static int32_t HbMediumMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type,
    bool isReElect)
{
    const NodeInfo *nodeInfo = NULL;
    char masterUdid[UDID_BUF_LEN] = {0};
    bool isFromMaster = false;

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr recv higher weight get invalid param");
        return SOFTBUS_ERR;
    }
    nodeInfo = HbGetOnlineNodeByRecvInfo(udidHash, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB recv higher weight udidhash:%s is not online yet",
            AnonymizesUDID(udidHash));
        return SOFTBUS_OK;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, sizeof(masterUdid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get local master udid fail");
        return SOFTBUS_ERR;
    }
    isFromMaster = strcmp(masterUdid, nodeInfo->deviceInfo.deviceUdid) == 0 ? true : false;
    if (isReElect && !isFromMaster &&
        LnnNotifyMasterElect(nodeInfo->networkId, nodeInfo->deviceInfo.deviceUdid, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB notify master elect fail");
        return SOFTBUS_ERR;
    }
    if (isFromMaster) {
        LnnSetHbAsMasterNodeState(false);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB recv higher weight udidHash:%s, weight:%d",
        AnonymizesUDID(udidHash), weight);
    return SOFTBUS_OK;
}

static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType)
{
    (void)type;

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr relay get invalid param");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB mgr relay process, udidhash:%s", AnonymizesUDID(udidHash));
    if (LnnStartHbByTypeAndStrategy(hbType, STRATEGY_HB_SEND_SINGLE, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr relay process fail");
        return;
    }
}

static int32_t HbInitRecvList(void)
{
    if (g_hbRecvList != NULL) {
        return SOFTBUS_OK;
    }
    g_hbRecvList = CreateSoftBusList();
    if (g_hbRecvList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB create recv list fail");
        return SOFTBUS_ERR;
    }
    g_hbRecvList->cnt = 0;
    return SOFTBUS_OK;
}

static void HbDeinitRecvList(void)
{
    LnnHeartbeatRecvInfo *item = NULL;
    LnnHeartbeatRecvInfo *nextItem = NULL;

    if (g_hbRecvList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB deinit recv list lock recv info list fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item->device);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
    DestroySoftBusList(g_hbRecvList);
    g_hbRecvList = NULL;
}

void LnnDumpHbMgrRecvList(void)
{
#define HB_DUMP_UPDATE_INFO_MAX_NUM 10
    int32_t dumpCount = 0;
    char *deviceType = NULL;
    LnnHeartbeatRecvInfo *item = NULL;

    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB dump recv list lock recv info list fail");
        return;
    }
    if (IsListEmpty(&g_hbRecvList->list)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "DumpHbMgrRecvList count=0");
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        dumpCount++;
        if (dumpCount > HB_DUMP_UPDATE_INFO_MAX_NUM) {
            break;
        }
        deviceType = LnnConvertIdToDeviceType((uint16_t)item->device->devType);
        if (deviceType == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get deviceType fail, devId:%s", item->device->devId);
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "DumpRecvList count:%d [i:%d, udidHash:%s, "
            "deviceType:%s, ConnectionAddrType:%02X, weight:%d, masterWeight:%d, lastRecvTime:%" PRIu64 "]",
            g_hbRecvList->cnt, dumpCount, AnonymizesUDID(item->device->devId), deviceType,
            item->device->addr[0].type, item->weight, item->masterWeight, item->lastRecvTime);
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
}

void LnnDumpHbOnlineNodeList(void)
{
#define HB_DUMP_ONLINE_NODE_MAX_NUM 5
    int32_t i, infoNum;
    uint64_t oldTimeStamp;
    NodeBasicInfo *info = NULL;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get node info fail");
        return;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "DumpHbOnlineNodeList count=0");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        if (i > HB_DUMP_ONLINE_NODE_MAX_NUM) {
            break;
        }
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            continue;
        }
        if (LnnGetDLHeartbeatTimestamp(info[i].networkId, &oldTimeStamp) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get timeStamp err, nodeInfo i=%d", i);
            continue;
        }
        char *deviceTypeStr = LnnConvertIdToDeviceType(nodeInfo->deviceInfo.deviceTypeId);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "DumpOnlineNodeList count:%d [i:%d, deviceName:%s, "
            "deviceTypeId:%d, deviceTypeStr:%s, masterWeight:%d, discoveryType:%d, oldTimeStamp:%" PRIu64 "]",
            infoNum, i + 1, nodeInfo->deviceInfo.deviceName, nodeInfo->deviceInfo.deviceTypeId,
            deviceTypeStr != NULL ? deviceTypeStr : "", nodeInfo->masterWeight, nodeInfo->discoveryType, oldTimeStamp);
    }
    SoftBusFree(info);
}

int32_t LnnHbMediumMgrInit(void)
{
    if (LnnRegistBleHeartbeatMediumMgr() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist ble heartbeat manager fail");
        return SOFTBUS_ERR;
    }
    return HbInitRecvList();
}

static bool VisitHbMediumMgrSendBegin(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    int32_t id, ret;
    LnnHeartbeatCustSendData *custData = NULL;

    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send once begin get invalid param");
        return false;
    }
    custData = (LnnHeartbeatCustSendData *)data;
    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send once begin convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat type(%d)", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onSendOneHbBegin == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB manager send once begin cb is NULL, type(%d)", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onSendOneHbBegin(custData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin type(%d) fail, ret=%d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatCustSendData *custData)
{
    if (custData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrSendBegin, &custData->hbType, custData)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send begin hbType(%d) fail", custData->hbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool VisitHbMediumMgrSendEnd(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    int32_t id, ret;

    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager stop one cycle convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat type(%d)", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onSendOneHbEnd == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB manager send once end cb is NULL, type(%d)", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onSendOneHbEnd();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop one cycle type(%d) fail, ret=%d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatType *type)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrSendEnd, type, NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send end hbType(%d) fail", *type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool VisitHbMediumMgrStop(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    int32_t id, ret;

    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop heartbeat convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat type(%d)", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onStopHbByType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB manager stop cb is NULL, type(%d)", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onStopHbByType();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop heartbeat type(%d) fail, ret=%d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrStop, type, NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager stop hbType(%d) fail", *type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnHbMediumMgrDeinit(void)
{
    int32_t i;

    for (i = 0; i < HB_MAX_TYPE_COUNT; ++i) {
        if (g_hbMeidumMgr[i] == NULL || g_hbMeidumMgr[i]->deinit == NULL) {
            continue;
        }
        g_hbMeidumMgr[i]->deinit();
        g_hbMeidumMgr[i] = NULL;
    }
    HbDeinitRecvList();
}

int32_t LnnHbMediumMgrSetParam(const LnnHeartbeatMediumParam *param)
{
    int32_t id, ret;

    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    id = LnnConvertHbTypeToId(param->type);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param convert type fail");
        return SOFTBUS_ERR;
    }
    if (g_hbMeidumMgr[id] == NULL || g_hbMeidumMgr[id]->onSetMediumParam == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB not support heartbeat type(%d)", param->type);
        return SOFTBUS_NOT_IMPLEMENT;
    }
    ret = g_hbMeidumMgr[id]->onSetMediumParam(param);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param fail, type=%d, ret=%d", param->type, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
{
    int32_t i;

    for (i = 0; i < HB_MAX_TYPE_COUNT; ++i) {
        if (g_hbMeidumMgr[i] == NULL || g_hbMeidumMgr[i]->onUpdateSendInfo == NULL) {
            continue;
        }
        if (g_hbMeidumMgr[i]->onUpdateSendInfo(type) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager update send info fail, i=%d", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static bool VisitRegistHeartbeatMediumMgr(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    int32_t id;
    LnnHeartbeatMediumMgr *mgr = (LnnHeartbeatMediumMgr *)data;

    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist manager convert type fail");
        return false;
    }
    g_hbMeidumMgr[id] = mgr;
    return true;
}

int32_t LnnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    if (mgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist manager get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitRegistHeartbeatMediumMgr, &mgr->supportType, (void *)mgr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist manager fail");
        return SOFTBUS_ERR;
    }
    if (mgr->init != NULL) {
        return mgr->init(&g_hbMediumMgrCb);
    }
    return SOFTBUS_OK;
}

static bool VisitUnRegistHeartbeatMediumMgr(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    int32_t id;

    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB unregist manager convert type fail");
        return false;
    }
    g_hbMeidumMgr[id] = NULL;
    return true;
}

int32_t LnnUnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    if (mgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB unregist manager get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitUnRegistHeartbeatMediumMgr, &mgr->supportType, (void *)mgr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB unregist manager fail");
        return SOFTBUS_ERR;
    }
    if (mgr->deinit != NULL) {
        mgr->deinit();
    }
    return SOFTBUS_OK;
}
