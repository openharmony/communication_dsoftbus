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

#include "auth_interface.h"
#include "auth_device_common_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_device_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_adapter_bt_common.h"
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
    uint64_t lastJoinLnnTime;
} LnnHeartbeatRecvInfo;

static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType);
static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, int32_t weight, int32_t masterWeight,
    LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp);
static int32_t HbMediumMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type,
    bool isReElect);

static LnnHeartbeatMediumMgr *g_hbMeidumMgr[HB_MAX_TYPE_COUNT] = {0};

static LnnHeartbeatMediumMgrCb g_hbMediumMgrCb = {
    .onRelay = HbMediumMgrRelayProcess,
    .onReceive = HbMediumMgrRecvProcess,
    .onRecvHigherWeight = HbMediumMgrRecvHigherWeight,
};

static SoftBusList *g_hbRecvList = NULL;

static int32_t HbFirstSaveRecvTime(LnnHeartbeatRecvInfo *storedInfo, DeviceInfo *device, int32_t weight,
    int32_t masterWeight, uint64_t recvTime)
{
    LnnHeartbeatRecvInfo *recvInfo = NULL;

    recvInfo = (LnnHeartbeatRecvInfo *)SoftBusMalloc(sizeof(LnnHeartbeatRecvInfo));
    if (recvInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium mgr malloc recvInfo err");
        return SOFTBUS_MALLOC_ERR;
    }
    recvInfo->device = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (recvInfo->device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium mgr deviceInfo calloc err");
        SoftBusFree(recvInfo);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(recvInfo->device, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB memcpy_s deviceInfo err");
        SoftBusFree(recvInfo->device);
        SoftBusFree(recvInfo);
        return SOFTBUS_MEM_ERR;
    }
    recvInfo->weight = weight;
    recvInfo->lastRecvTime = recvTime;
    recvInfo->masterWeight = masterWeight;
    ListInit(&recvInfo->node);
    ListAdd(&g_hbRecvList->list, &recvInfo->node);
    g_hbRecvList->cnt++;
    storedInfo = recvInfo;
    return SOFTBUS_OK;
}

static int32_t HbSaveRecvTimeToRemoveRepeat(LnnHeartbeatRecvInfo *storedInfo, DeviceInfo *device, int32_t weight,
    int32_t masterWeight, uint64_t recvTime)
{
    if (storedInfo != NULL) {
        storedInfo->lastRecvTime = recvTime;
        storedInfo->weight = weight != 0 ? weight : storedInfo->weight;
        storedInfo->masterWeight = masterWeight;
        return SOFTBUS_OK;
    }
    return HbFirstSaveRecvTime(storedInfo, device, weight, masterWeight, recvTime);
}

static uint64_t HbGetRepeatThresholdByType(LnnHeartbeatType hbType)
{
    switch (hbType) {
        case HEARTBEAT_TYPE_BLE_V0:
            return HB_REPEAD_RECV_THRESHOLD;
        case HEARTBEAT_TYPE_BLE_V1:
            return HB_REPEAD_JOIN_LNN_THRESHOLD;
        default:
            return 0;
    }
}

static void UpdateOnlineInfoNoConnection(const char *networkId, HbRespData *hbResp)
{
    if (hbResp == NULL || hbResp->stateVersion == STATE_VERSION_INVALID) {
        LLOGD("isn't ble directly online, ignore");
        return;
    }
    NodeInfo nodeInfo = {0};
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGD("get nodeInfo fail");
        return;
    }
    uint32_t oldNetCapa = nodeInfo.netCapacity;
    if ((hbResp->capabiltiy & (1 << ENABLE_WIFI_CAP)) != 0) {
        (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_WIFI);
    }
    if ((hbResp->capabiltiy & (1 << P2P_GO)) != 0 || (hbResp->capabiltiy & (1 << P2P_GC)) != 0) {
        (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_WIFI_P2P);
    }
    (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_BLE);
    (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_BR);
    if (oldNetCapa == nodeInfo.netCapacity) {
        LLOGD("capa not change, don't update devInfo");
        return;
    }
    if (LnnSetDLConnCapability(networkId, nodeInfo.netCapacity) != SOFTBUS_OK) {
        LLOGE("update net capability fail");
        return;
    }
    int32_t ret = LnnSaveRemoteDeviceInfo(&nodeInfo);
    if (ret != SOFTBUS_OK) {
        LLOGD("update device info fail,ret:%d", ret);
        return;
    }
}

static int32_t HbGetOnlineNodeByRecvInfo(const char *recvUdidHash,
    const ConnectionAddrType recvAddrType, NodeInfo *nodeInfo, HbRespData *hbResp)
{
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get all online node info fail");
        return SOFTBUS_ERR;
    }
    if (info == NULL || infoNum == 0) {
        LLOGD("HB none online node");
        return SOFTBUS_ERR;
    }
    DiscoveryType discType = LnnConvAddrTypeToDiscType(recvAddrType);
    for (i = 0; i < infoNum; ++i) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, nodeInfo) != SOFTBUS_OK) {
            LLOGD("HB get nodeInfo fail");
            continue;
        }
        if (!LnnHasDiscoveryType(nodeInfo, discType)) {
            LLOGD("HB node online networkId:%s not have discType:%d", AnonymizesNetworkID(info[i].networkId), discType);
            continue;
        }
        if (LnnGenerateHexStringHash((const unsigned char *)nodeInfo->deviceInfo.deviceUdid, udidHash,
            HB_SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, recvUdidHash, HB_SHORT_UDID_HASH_HEX_LEN) == 0) {
            LLOGD("HB node udidHash:%s networkId:%s is online", AnonymizesUDID(udidHash),
                AnonymizesNetworkID(info[i].networkId));
            UpdateOnlineInfoNoConnection(info[i].networkId, hbResp);
            SoftBusFree(info);
            return SOFTBUS_OK;
        }
    }
    SoftBusFree(info);
    return SOFTBUS_ERR;
}

static int32_t HbUpdateOfflineTimingByRecvInfo(const char *networkId, ConnectionAddrType type, LnnHeartbeatType hbType,
    uint64_t updateTime)
{
    uint64_t oldTimeStamp;
    if (LnnGetDLHeartbeatTimestamp(networkId, &oldTimeStamp) != SOFTBUS_OK) {
        LLOGE("HB get timeStamp err, networkId:%s", AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    if (LnnSetDLHeartbeatTimestamp(networkId, updateTime) != SOFTBUS_OK) {
        LLOGE("HB update timeStamp err, networkId:%s", AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    LLOGI("HB recv to update timeStamp, networkId:%s, update timeStamp from:%" PRIu64 " to:%" PRIu64,
        AnonymizesNetworkID(networkId), oldTimeStamp, updateTime);
    if (hbType != HEARTBEAT_TYPE_BLE_V1 && hbType != HEARTBEAT_TYPE_BLE_V0) {
        LLOGD("HB only BLE_V1 and BLE_V0 support offline timing");
        return SOFTBUS_ERR;
    }
    if (LnnStopOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        LLOGE("HB remove offline check err, networkId:%s", AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    if (LnnStartOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        LLOGE("HB set new offline check err, networkId:%s", AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static LnnHeartbeatRecvInfo *HbGetStoredRecvInfo(const char *udidHash, ConnectionAddrType type, uint64_t recvTime)
{
    LnnHeartbeatRecvInfo *item = NULL;
    LnnHeartbeatRecvInfo *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        if ((recvTime - item->lastRecvTime) > HB_RECV_INFO_SAVE_LEN) {
            ListDelete(&item->node);
            SoftBusFree(item->device);
            SoftBusFree(item);
            g_hbRecvList->cnt--;
        }
        if (memcmp(item->device->devId, udidHash, DISC_MAX_DEVICE_ID_LEN) == 0 &&
            LnnConvAddrTypeToDiscType(item->device->addr[0].type) == LnnConvAddrTypeToDiscType(type)) {
            return item;
        }
    }
    return NULL;
}

static bool HbIsRepeatedRecvInfo(LnnHeartbeatType hbType, const LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (storedInfo == NULL) {
        return false;
    }
    return nowTime - storedInfo->lastRecvTime < HbGetRepeatThresholdByType(hbType);
}

static bool HbIsRepeatedJoinLnnRequest(LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (storedInfo == NULL) {
        return false;
    }
    if (nowTime - storedInfo->lastJoinLnnTime < HB_REPEAD_JOIN_LNN_THRESHOLD) {
        return true;
    }
    storedInfo->lastJoinLnnTime = nowTime;
    return false;
}

static bool HbIsNeedReAuth(const NodeInfo *nodeInfo, const char *newAccountHash)
{
    LLOGI("HB peer networkId:%s accountHash [%02X%02X -> %02X%02X]", AnonymizesNetworkID(nodeInfo->networkId),
        nodeInfo->accountHash[0], nodeInfo->accountHash[1], newAccountHash[0], newAccountHash[1]);
    return memcmp(nodeInfo->accountHash, newAccountHash, HB_SHORT_ACCOUNT_HASH_LEN) != 0;
}

static void HbDumpRecvDeviceInfo(const DeviceInfo *device, int32_t weight, int32_t masterWeight,
    LnnHeartbeatType hbType, uint64_t nowTime)
{
    const char *devTypeStr = LnnConvertIdToDeviceType((uint16_t)device->devType);
    LLOGI(">> heartbeat(HB) OnTock [udidHash:%s, accountHash:%02X%02X, hbType:%d, devTypeStr:%s, "
        "peerWeight:%d, masterWeight:%d, devTypeHex:%02X, ConnectionAddrType:%d, nowTime:%" PRIu64 "]",
        AnonymizesUDID(device->devId), device->accountHash[0], device->accountHash[1], hbType,
        devTypeStr != NULL ? devTypeStr : "", weight, masterWeight, device->devType, device->addr[0].type, nowTime);
}

static bool IsLocalSupportBleDirectOnline()
{
    uint64_t localFeatureCap = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeatureCap) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB build ble broadcast, get local feature cap failed");
        return false;
    }
    if ((localFeatureCap & (1 << BIT_BLE_DIRECT_ONLINE)) == 0) {
        return false;
    }
    return true;
}

static bool IsNeedConnectOnLine(DeviceInfo *device, HbRespData *hbResp)
{
    if (hbResp == NULL || hbResp->stateVersion == STATE_VERSION_INVALID) {
        LLOGI("don't support ble direct online because resp data");
        return true;
    }
    int32_t ret;
    NodeInfo deviceInfo = {0};
    if (!IsLocalSupportBleDirectOnline()) {
        LLOGI("ble don't support ble direct online");
        return true;
    }
    if (LnnRetrieveDeviceInfo(device->devId, &deviceInfo) != SOFTBUS_OK) {
        LLOGI("don't support ble direct online because device info not exist");
        return true;
    }
    if ((int32_t)hbResp->stateVersion != deviceInfo.stateVersion) {
        LLOGI("don't support ble direct online because state version change");
        return true;
    }
    AuthDeviceKeyInfo keyInfo = {0};
    LLOGI("AuthFindDeviceKey = %s", device->devId);
    if (AuthFindDeviceKey(device->devId, AUTH_LINK_TYPE_BLE, &keyInfo) != SOFTBUS_OK) {
        LLOGI("don't support ble direct online because key not exist");
        return true;
    }

    // update capability
    if ((hbResp->capabiltiy & (1 << ENABLE_WIFI_CAP)) != 0) {
        (void)LnnSetNetCapability(&deviceInfo.netCapacity, BIT_WIFI);
    }
    if ((hbResp->capabiltiy & (1 << P2P_GO)) != 0 || (hbResp->capabiltiy & (1 << P2P_GC))) {
        (void)LnnSetNetCapability(&deviceInfo.netCapacity, BIT_WIFI_P2P);
    }
    (void)LnnSetNetCapability(&deviceInfo.netCapacity, BIT_BR);
    (void)LnnSetNetCapability(&deviceInfo.netCapacity, BIT_BLE);
    if ((ret = LnnSaveRemoteDeviceInfo(&deviceInfo)) != SOFTBUS_OK) {
        LLOGE("don't support ble direct online because update device info fail ret = %d", ret);
        return true;
    }
    LLOGI("support ble direct online");
    return false;
}

static int32_t HbNotifyReceiveDevice(DeviceInfo *device, int32_t weight,
    int32_t masterWeight, LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp)
{
    uint64_t nowTime;
    SoftBusSysTime times = {0};
    SoftBusGetTime(&times);
    nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        LLOGE("HB mgr lock recv info list fail");
        return SOFTBUS_LOCK_ERR;
    }
    LnnHeartbeatRecvInfo *storedInfo = HbGetStoredRecvInfo(device->devId, device->addr[0].type, nowTime);
    if (HbIsRepeatedRecvInfo(hbType, storedInfo, nowTime)) {
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (HbSaveRecvTimeToRemoveRepeat(storedInfo, device, weight, masterWeight, nowTime) != SOFTBUS_OK) {
        LLOGE("HB save recv time fail, udidHash:%s", AnonymizesUDID(device->devId));
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return SOFTBUS_ERR;
    }
    if (isOnlineDirectly) {
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        (void)HbUpdateOfflineTimingByRecvInfo(device->devId, device->addr[0].type, hbType, nowTime);
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    HbDumpRecvDeviceInfo(device, weight, masterWeight, hbType, nowTime);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    if (HbGetOnlineNodeByRecvInfo(device->devId, device->addr[0].type, &nodeInfo, hbResp) == SOFTBUS_OK) {
        if (!HbIsNeedReAuth(&nodeInfo, device->accountHash)) {
            (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
            return HbUpdateOfflineTimingByRecvInfo(nodeInfo.networkId, device->addr[0].type, hbType, nowTime);
        }
        LLOGD("HB recv account changed, offline to auth again, udidHash:%s", AnonymizesUDID(device->devId));
        LnnRequestLeaveSpecific(nodeInfo.networkId, LnnConvertHbTypeToConnAddrType(hbType));
    }
    if (HbIsRepeatedJoinLnnRequest(storedInfo, nowTime)) {
        LLOGD("HB recv but ignore repeated join lnn request, udidHash:%s, isNeedOnline:%d",
            AnonymizesUDID(device->devId), device->isOnline);
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
    bool isConnect = IsNeedConnectOnLine(device, hbResp);
    LLOGI("heartbeat(HB) find device, udidHash:%s, ConnectionAddrType:%02X, isConnect = %d",
        AnonymizesUDID(device->devId), device->addr[0].type, isConnect);
    if (LnnNotifyDiscoveryDevice(device->addr, isConnect) != SOFTBUS_OK) {
        LLOGE("HB mgr recv process notify device found fail");
        return SOFTBUS_ERR;
    }
    if (isConnect) {
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    } else {
        return SOFTBUS_NETWORK_NODE_DIRECT_ONLINE;
    }
    return SOFTBUS_NETWORK_NODE_OFFLINE;
}

static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, int32_t weight,
    int32_t masterWeight, LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp)
{
    if (device == NULL) {
        LLOGE("HB mgr recv process get invalid param");
        return SOFTBUS_ERR;
    }
    if (!AuthIsPotentialTrusted(device)) {
        LLOGW(">> heartbeat(HB) OnTock is not potential trusted, udidHash:%s, accountHash:%02X%02X",
            AnonymizesUDID(device->devId), device->accountHash[0], device->accountHash[1]);
        return SOFTBUS_NETWORK_HEARTBEAT_UNTRUSTED;
    }
    return HbNotifyReceiveDevice(device, weight, masterWeight, hbType, isOnlineDirectly, hbResp);
}

static int32_t HbMediumMgrRecvHigherWeight(const char *udidHash, int32_t weight, ConnectionAddrType type,
    bool isReElect)
{
    NodeInfo nodeInfo;
    char masterUdid[UDID_BUF_LEN] = {0};
    bool isFromMaster = false;

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr recv higher weight get invalid param");
        return SOFTBUS_ERR;
    }
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    if (HbGetOnlineNodeByRecvInfo(udidHash, type, &nodeInfo, NULL) != SOFTBUS_OK) {
        LLOGD("HB recv higher weight udidhash:%s is not online yet", AnonymizesUDID(udidHash));
        return SOFTBUS_OK;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, sizeof(masterUdid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get local master udid fail");
        return SOFTBUS_ERR;
    }
    isFromMaster = strcmp(masterUdid, nodeInfo.deviceInfo.deviceUdid) == 0 ? true : false;
    if (isReElect && !isFromMaster &&
        LnnNotifyMasterElect(nodeInfo.networkId, nodeInfo.deviceInfo.deviceUdid, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB notify master elect fail");
        return SOFTBUS_ERR;
    }
    if (isFromMaster) {
        LnnSetHbAsMasterNodeState(false);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB recv higher weight udidHash:%s, weight:%d, masterUdid:%s",
        AnonymizesUDID(udidHash), weight, AnonymizesUDID(masterUdid));
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type,
    LnnHeartbeatType hbType)
{
    (void)type;

    if (udidHash == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB mgr relay get invalid param");
        return;
    }
    LLOGD("HB mgr relay process, udidhash:%s", AnonymizesUDID(udidHash));
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

void LnnHbClearRecvList(void)
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
}

NO_SANITIZE("cfi")  void LnnDumpHbMgrRecvList(void)
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
        LLOGD("DumpHbMgrRecvList count=0");
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get deviceType fail, udidHash:%s",
                AnonymizesUDID(item->device->devId));
            continue;
        }
        LLOGD("DumpRecvList count:%d [i:%d, udidHash:%s, deviceType:%s, ConnectionAddrType:%02X, weight:%d, "
            "masterWeight:%d, lastRecvTime:%" PRIu64 "]", g_hbRecvList->cnt, dumpCount,
            AnonymizesUDID(item->device->devId), deviceType, item->device->addr[0].type, item->weight,
            item->masterWeight, item->lastRecvTime);
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
}

NO_SANITIZE("cfi") void LnnDumpHbOnlineNodeList(void)
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
        LLOGD("DumpHbOnlineNodeList count=0");
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    for (i = 0; i < infoNum; ++i) {
        if (i > HB_DUMP_ONLINE_NODE_MAX_NUM) {
            break;
        }
        if (LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            continue;
        }
        if (LnnGetDLHeartbeatTimestamp(info[i].networkId, &oldTimeStamp) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get timeStamp err, nodeInfo i=%d", i);
            continue;
        }
        char *deviceTypeStr = LnnConvertIdToDeviceType(nodeInfo.deviceInfo.deviceTypeId);
        LLOGD("DumpOnlineNodeList count:%d [i:%d, deviceName:%s, deviceTypeId:%d, deviceTypeStr:%s, masterWeight:%d, "
            "discoveryType:%d, oldTimeStamp:%" PRIu64 "]", infoNum, i + 1, nodeInfo.deviceInfo.deviceName,
            nodeInfo.deviceInfo.deviceTypeId, deviceTypeStr != NULL ? deviceTypeStr : "",
            nodeInfo.masterWeight, nodeInfo.discoveryType, oldTimeStamp);
    }
    SoftBusFree(info);
}

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrInit(void)
{
    if (LnnRegistBleHeartbeatMediumMgr() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist ble heartbeat manager fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterBleLpDeviceMediumMgr() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SH regist LpDevice manager fail");
        return SOFTBUS_ERR;
    }
    return HbInitRecvList();
}

NO_SANITIZE("cfi") static bool VisitHbMediumMgrSendBegin(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType,
    void *data)
{
    (void)typeSet;
    int32_t id, ret;
    LnnHeartbeatSendBeginData *custData = NULL;

    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send once begin get invalid param");
        return false;
    }
    custData = (LnnHeartbeatSendBeginData *)data;
    custData->hbType = eachType;
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

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData)
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

NO_SANITIZE("cfi") static bool VisitHbMediumMgrSendEnd(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType,
    void *data)
{
    (void)typeSet;
    (void)data;
    int32_t id, ret;
    LnnHeartbeatSendEndData *custData = NULL;

    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send once end get invalid param");
        return false;
    }
    if (eachType == HEARTBEAT_TYPE_BLE_V3) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "V3 don't stop");
        return true;
    }
    custData = (LnnHeartbeatSendEndData *)data;
    custData->hbType = eachType;
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
    ret = g_hbMeidumMgr[id]->onSendOneHbEnd(custData);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop one cycle type(%d) fail, ret=%d", eachType, ret);
        return false;
    }
    return true;
}

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *custData)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrSendEnd, &custData->hbType, custData)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager send end hbType(%d) fail", custData->hbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static bool VisitHbMediumMgrStop(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
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

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrStop, type, NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager stop hbType(%d) fail", *type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void LnnHbMediumMgrDeinit(void)
{
    int32_t i;

    for (i = 0; i < HB_MAX_TYPE_COUNT; ++i) {
        /* HEARTBEAT_TYPE_BLE_V0 and HEARTBEAT_TYPE_BLE_V1 have the same medium manager. */
        if (i == LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V1)) {
            continue;
        }
        if (g_hbMeidumMgr[i] == NULL || g_hbMeidumMgr[i]->deinit == NULL) {
            continue;
        }
        g_hbMeidumMgr[i]->deinit();
        g_hbMeidumMgr[i] = NULL;
    }
    HbDeinitRecvList();
}

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrSetParam(const LnnHeartbeatMediumParam *param)
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

NO_SANITIZE("cfi") int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
{
    int32_t i;

    for (i = 0; i < HB_MAX_TYPE_COUNT; ++i) {
        /* HEARTBEAT_TYPE_BLE_V0 and HEARTBEAT_TYPE_BLE_V1 have the same medium manager. */
        if (i == LnnConvertHbTypeToId(HEARTBEAT_TYPE_BLE_V1)) {
            continue;
        }
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Regeist medium manager id = %d", id);
    g_hbMeidumMgr[id] = mgr;
    return true;
}

NO_SANITIZE("cfi") int32_t LnnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    // TODO: One-to-one correspondence between LnnHeartbeatMediumMgr and implementation.
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

NO_SANITIZE("cfi") int32_t LnnUnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
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
