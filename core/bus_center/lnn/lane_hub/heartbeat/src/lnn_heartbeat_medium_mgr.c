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

#include "anonymizer.h"
#include "auth_manager.h"
#include "auth_device_common_key.h"
#include "auth_deviceprofile.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_device_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_lane_vap_info.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_parameter_utils.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define INVALID_BR_MAC_ADDR "00:00:00:00:00:00"

#define HB_VERSION_V2         0x04
#define HB_RECV_INFO_SAVE_LEN (60 * 60 * HB_TIME_FACTOR)
#define HB_REAUTH_TIME        (10 * HB_TIME_FACTOR)
#define HB_DFX_DELAY_TIME     (7 * HB_TIME_FACTOR)
#define PC_RESTRICT_TIME      3
typedef struct {
    ListNode node;
    DeviceInfo *device;
    int32_t weight;
    int32_t masterWeight;
    uint64_t lastRecvTime;
    uint64_t lastJoinLnnTime;
} LnnHeartbeatRecvInfo;

typedef struct {
    ConnectOnlineReason connectReason;
    bool isDirectlyHb;
    bool isConnect;
} LnnConnectCondition;

static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType);
static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, const LnnHeartbeatWeight *mediumWeight,
    LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp);
static int32_t HbMediumMgrRecvHigherWeight(
    const char *udidHash, int32_t weight, ConnectionAddrType type, bool isReElect, bool isPeerScreenOn);
static void HbMediumMgrRecvLpInfo(const char *networkId, uint64_t nowTime);

static LnnHeartbeatMediumMgr *g_hbMeidumMgr[HB_MAX_TYPE_COUNT] = { 0 };

static LnnHeartbeatMediumMgrCb g_hbMediumMgrCb = {
    .onRelay = HbMediumMgrRelayProcess,
    .onReceive = HbMediumMgrRecvProcess,
    .onRecvHigherWeight = HbMediumMgrRecvHigherWeight,
    .onRecvLpInfo = HbMediumMgrRecvLpInfo,
};

static SoftBusList *g_hbRecvList = NULL;

static int32_t HbFirstSaveRecvTime(
    LnnHeartbeatRecvInfo *storedInfo, DeviceInfo *device, int32_t weight, int32_t masterWeight, uint64_t recvTime)
{
    LnnHeartbeatRecvInfo *recvInfo = NULL;

    recvInfo = (LnnHeartbeatRecvInfo *)SoftBusCalloc(sizeof(LnnHeartbeatRecvInfo));
    if (recvInfo == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "medium mgr malloc recvInfo err");
        return SOFTBUS_MALLOC_ERR;
    }
    recvInfo->device = (DeviceInfo *)SoftBusCalloc(sizeof(DeviceInfo));
    if (recvInfo->device == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "medium mgr deviceInfo calloc err");
        SoftBusFree(recvInfo);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(recvInfo->device, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "memcpy_s deviceInfo err");
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

static int32_t HbSaveRecvTimeToRemoveRepeat(
    LnnHeartbeatRecvInfo *storedInfo, DeviceInfo *device, int32_t weight, int32_t masterWeight, uint64_t recvTime)
{
    if (storedInfo != NULL) {
        storedInfo->lastRecvTime = recvTime;
        storedInfo->weight = weight != 0 ? weight : storedInfo->weight;
        storedInfo->masterWeight = masterWeight;
        storedInfo->device->isOnline = device->isOnline;
        return SOFTBUS_OK;
    }
    int32_t ret = HbFirstSaveRecvTime(storedInfo, device, weight, masterWeight, recvTime);
    if (ret != SOFTBUS_OK) {
        char *anonyUdid = NULL;
        Anonymize(device->devId, &anonyUdid);
        LNN_LOGE(LNN_HEART_BEAT, "save recv time fail, udidHash=%{public}s", AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
    }
    return ret;
}

static uint64_t HbGetRepeatThresholdByType(LnnHeartbeatType hbType)
{
    if (LnnIsMultiDeviceOnline()) {
        return HB_REPEAD_RECV_THRESHOLD_MULTI_DEVICE;
    }
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
        LNN_LOGD(LNN_HEART_BEAT, "isn't ble directly online, ignore");
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGD(LNN_HEART_BEAT, "get nodeInfo fail");
        return;
    }
    if (nodeInfo.deviceInfo.deviceTypeId == TYPE_PC_ID) {
        LNN_LOGI(LNN_HEART_BEAT, "winpc no need update netCapacity");
        return;
    }
    uint32_t oldNetCapa = nodeInfo.netCapacity;
    if ((hbResp->capabiltiy & ENABLE_WIFI_CAP) != 0) {
        (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_WIFI);
    } else {
        (void)LnnClearNetCapability(&nodeInfo.netCapacity, BIT_WIFI);
        (void)LnnClearNetCapability(&nodeInfo.netCapacity, BIT_WIFI_5G);
        (void)LnnClearNetCapability(&nodeInfo.netCapacity, BIT_WIFI_24G);
    }
    if ((hbResp->capabiltiy & P2P_GO) != 0 || (hbResp->capabiltiy & P2P_GC) != 0) {
        (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_WIFI_P2P);
    } else {
        (void)LnnClearNetCapability(&nodeInfo.netCapacity, BIT_WIFI_P2P);
    }
    if ((hbResp->capabiltiy & DISABLE_BR_CAP) != 0) {
        (void)LnnClearNetCapability(&nodeInfo.netCapacity, BIT_BR);
    } else {
        (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_BR);
    }
    (void)LnnSetNetCapability(&nodeInfo.netCapacity, BIT_BLE);
    if (oldNetCapa == nodeInfo.netCapacity) {
        LNN_LOGD(LNN_HEART_BEAT, "capa not change, don't update devInfo");
        return;
    }
    if (LnnSetDLConnCapability(networkId, nodeInfo.netCapacity) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "update net capability fail");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_HEART_BEAT, "networkId=%{public}s capability change:%{public}u->%{public}u",
        AnonymizeWrapper(anonyNetworkId), oldNetCapa, nodeInfo.netCapacity);
    AnonymizeFree(anonyNetworkId);
}

static int32_t HbGetOnlineNodeByRecvInfo(
    const char *recvUdidHash, const ConnectionAddrType recvAddrType, NodeInfo *nodeInfo, HbRespData *hbResp)
{
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t ret = LnnGetAllOnlineNodeInfo(&info, &infoNum);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR, LNN_HEART_BEAT,
        "get all online node info fail");
    LNN_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_NO_ONLINE_DEVICE, LNN_HEART_BEAT, "none online node");
    LNN_CHECK_AND_RETURN_RET_LOGE(infoNum != 0, SOFTBUS_NO_ONLINE_DEVICE, LNN_HEART_BEAT, "none online node");
    DiscoveryType discType = LnnConvAddrTypeToDiscType(recvAddrType);
    for (int32_t i = 0; i < infoNum; ++i) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, nodeInfo) != SOFTBUS_OK) {
            LNN_LOGD(LNN_HEART_BEAT, "get nodeInfo fail");
            continue;
        }
        if (!LnnHasDiscoveryType(nodeInfo, discType)) {
            char *anonyNetworkId = NULL;
            Anonymize(info[i].networkId, &anonyNetworkId);
            LNN_LOGD(LNN_HEART_BEAT, "node online not have discType. networkId=%{public}s, discType=%{public}d",
                AnonymizeWrapper(anonyNetworkId), discType);
            AnonymizeFree(anonyNetworkId);
            continue;
        }
        if (LnnGenerateHexStringHash((const unsigned char *)nodeInfo->deviceInfo.deviceUdid, udidHash,
            HB_SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, recvUdidHash, HB_SHORT_UDID_HASH_HEX_LEN) == 0) {
            char *anonyNetworkId = NULL;
            char *anonyUdid = NULL;
            Anonymize(udidHash, &anonyUdid);
            Anonymize(info[i].networkId, &anonyNetworkId);
            LNN_LOGD(LNN_HEART_BEAT, "node is online. udidHash=%{public}s, networkId=%{public}s",
                AnonymizeWrapper(anonyUdid), AnonymizeWrapper(anonyNetworkId));
            AnonymizeFree(anonyNetworkId);
            AnonymizeFree(anonyUdid);
            UpdateOnlineInfoNoConnection(info[i].networkId, hbResp);
            SoftBusFree(info);
            return SOFTBUS_OK;
        }
    }
    SoftBusFree(info);
    return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
}

static int32_t HbUpdateOfflineTimingByRecvInfo(
    const char *networkId, ConnectionAddrType type, LnnHeartbeatType hbType, uint64_t updateTime)
{
    uint64_t oldTimestamp;
    char *anonyNetworkId = NULL;
    if (LnnGetDLHeartbeatTimestamp(networkId, &oldTimestamp) != SOFTBUS_OK) {
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_HEART_BEAT, "get timestamp err, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR;
    }
    if (LnnSetDLHeartbeatTimestamp(networkId, updateTime) != SOFTBUS_OK) {
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_HEART_BEAT, "update timestamp err, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR;
    }
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_HEART_BEAT,
        "recv to update timestamp, networkId=%{public}s, timestamp:%{public}" PRIu64 "->%{public}" PRIu64,
        AnonymizeWrapper(anonyNetworkId), oldTimestamp, updateTime);
    if (hbType != HEARTBEAT_TYPE_BLE_V1 && hbType != HEARTBEAT_TYPE_BLE_V0) {
        LNN_LOGD(LNN_HEART_BEAT, "only BLE_V1 and BLE_V0 support offline timing");
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NOT_SUPPORT;
    }
    if (LnnStopOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "remove offline check err, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_HB_STOP_STRATEGY_FAIL;
    }
    if (LnnStartOfflineTimingStrategy(networkId, type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "set new offline check err, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    AnonymizeFree(anonyNetworkId);
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
            continue;
        }
        if (memcmp(item->device->devId, udidHash, DISC_MAX_DEVICE_ID_LEN) == 0 &&
            LnnConvAddrTypeToDiscType(item->device->addr[0].type) == LnnConvAddrTypeToDiscType(type)) {
            return item;
        }
    }
    return NULL;
}

static bool HbIsRepeatedRecvInfo(
    LnnHeartbeatType hbType, const LnnHeartbeatRecvInfo *storedInfo, DeviceInfo *device, uint64_t nowTime)
{
    if (storedInfo == NULL) {
        return false;
    }
    if (nowTime - storedInfo->lastRecvTime >= HbGetRepeatThresholdByType(hbType)) {
        return false;
    }
    if (!storedInfo->device->isOnline && device->isOnline) {
        return false;
    }
    return true;
}

static bool HbIsRepeatedJoinLnnRequest(LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (storedInfo == NULL) {
        return false;
    }
    if (nowTime - storedInfo->lastJoinLnnTime < HB_REPEAD_JOIN_LNN_THRESHOLD) {
        char *anonyUdid = NULL;
        Anonymize(storedInfo->device->devId, &anonyUdid);
        LNN_LOGD(LNN_HEART_BEAT, "recv but ignore repeated join lnn request, udidHash=%{public}s",
            AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        return true;
    }
    storedInfo->lastJoinLnnTime = nowTime;
    return false;
}

static bool HbIsNeedReAuth(const NodeInfo *nodeInfo, const char *newAccountHash)
{
    char *anonyNetworkId = NULL;
    Anonymize(nodeInfo->networkId, &anonyNetworkId);
    LNN_LOGI(LNN_HEART_BEAT,
        "peer networkId=%{public}s, accountHash:%{public}02X%{public}02X->%{public}02X%{public}02X",
        AnonymizeWrapper(anonyNetworkId), nodeInfo->accountHash[0], nodeInfo->accountHash[1],
        newAccountHash[0], newAccountHash[1]);
    AnonymizeFree(anonyNetworkId);
    return memcmp(nodeInfo->accountHash, newAccountHash, HB_SHORT_ACCOUNT_HASH_LEN) != 0;
}

static void HbDumpRecvDeviceInfo(
    const DeviceInfo *device, int32_t weight, int32_t masterWeight, LnnHeartbeatType hbType, uint64_t nowTime)
{
    char *anonyUdid = NULL;
    const char *devTypeStr = LnnConvertIdToDeviceType((uint16_t)device->devType);
    Anonymize(device->devId, &anonyUdid);
    LNN_LOGI(LNN_HEART_BEAT,
        "heartbeat(HB) OnTock, udidHash=%{public}s, accountHash=%{public}02X%{public}02X, hbType=%{public}d, "
        "devTypeStr=%{public}s, peerWeight=%{public}d, masterWeight=%{public}d, devTypeHex=%{public}02X, "
        "ConnectionAddrType=%{public}d, nowTime=%{public}" PRIu64,
        AnonymizeWrapper(anonyUdid), device->accountHash[0], device->accountHash[1],
        hbType, devTypeStr != NULL ? devTypeStr : "", weight,
        masterWeight, device->devType, device->addr[0].type, nowTime);
    AnonymizeFree(anonyUdid);
}

static bool IsLocalSupportBleDirectOnline()
{
    uint64_t localFeatureCap = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeatureCap) != SOFTBUS_OK) {
        LNN_LOGW(LNN_HEART_BEAT, "build ble broadcast, get local feature cap failed");
        return false;
    }
    if ((localFeatureCap & (1 << BIT_BLE_DIRECT_ONLINE)) == 0) {
        return false;
    }
    return true;
}

static bool IsLocalSupportThreeState()
{
    uint64_t localFeatureCap = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeatureCap) != SOFTBUS_OK) {
        LNN_LOGW(LNN_HEART_BEAT, "build ble broadcast, get local feature cap failed");
        return false;
    }
    if ((localFeatureCap & (1 << BIT_SUPPORT_THREE_STATE)) == 0) {
        return false;
    }
    return true;
}

static void SetDeviceNetCapability(uint32_t *deviceInfoNetCapacity, HbRespData *hbResp)
{
    uint32_t oldNetCapa = *deviceInfoNetCapacity;
    if ((hbResp->capabiltiy & ENABLE_WIFI_CAP) != 0) {
        (void)LnnSetNetCapability(deviceInfoNetCapacity, BIT_WIFI);
    } else {
        (void)LnnClearNetCapability(deviceInfoNetCapacity, BIT_WIFI);
        (void)LnnClearNetCapability(deviceInfoNetCapacity, BIT_WIFI_5G);
        (void)LnnClearNetCapability(deviceInfoNetCapacity, BIT_WIFI_24G);
    }
    if ((hbResp->capabiltiy & DISABLE_BR_CAP) != 0) {
        (void)LnnClearNetCapability(deviceInfoNetCapacity, BIT_BR);
    } else {
        (void)LnnSetNetCapability(deviceInfoNetCapacity, BIT_BR);
    }
    if ((hbResp->capabiltiy & P2P_GO) != 0 || (hbResp->capabiltiy & P2P_GC)) {
        (void)LnnSetNetCapability(deviceInfoNetCapacity, BIT_WIFI_P2P);
    } else {
        (void)LnnClearNetCapability(deviceInfoNetCapacity, BIT_WIFI_P2P);
    }
    (void)LnnSetNetCapability(deviceInfoNetCapacity, BIT_BLE);
    LNN_LOGI(LNN_HEART_BEAT, "capability change:%{public}u->%{public}u", oldNetCapa, *deviceInfoNetCapacity);
}

static int32_t SetDeviceScreenStatus(NodeInfo *nodeInfo, bool isScreenOn)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "nodeInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    nodeInfo->isScreenOn = isScreenOn;
    char *anonyDeviceUdid = NULL;
    Anonymize(nodeInfo->deviceInfo.deviceUdid, &anonyDeviceUdid);
    LNN_LOGI(LNN_HEART_BEAT, "udid=%{public}s, prepare to set screen status to %{public}s from hbResp",
        AnonymizeWrapper(anonyDeviceUdid), isScreenOn ? "on" : "off");
    AnonymizeFree(anonyDeviceUdid);
    return SOFTBUS_OK;
}

static bool IsStateVersionChanged(
    const HbRespData *hbResp, const NodeInfo *deviceInfo, int32_t *stateVersion, ConnectOnlineReason *connectReason)
{
    if (LnnGetLocalNumInfo(NUM_KEY_STATE_VERSION, stateVersion) == SOFTBUS_OK &&
        *stateVersion != deviceInfo->localStateVersion) {
        *connectReason = LOCAL_STATE_VERSION_CHANGED;
        LNN_LOGI(LNN_HEART_BEAT, "don't support ble direct online because local stateVersion=%{public}d->%{public}d",
            deviceInfo->localStateVersion, *stateVersion);
        return true;
    }
    if ((int32_t)hbResp->stateVersion != deviceInfo->stateVersion) {
        *connectReason = PEER_STATE_VERSION_CHANGED;
        LNN_LOGI(LNN_HEART_BEAT, "don't support ble direct online because peer stateVersion=%{public}d->%{public}d",
            deviceInfo->stateVersion, (int32_t)hbResp->stateVersion);
        return true;
    }
    return false;
}

static bool IsInvalidBrmac(const char *macAddr)
{
    if (strlen(macAddr) == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "macAddr is null");
        return true;
    }
    if (strcmp(macAddr, INVALID_BR_MAC_ADDR) == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "macAddr is invalid");
        return true;
    }
    return false;
}

static bool IsUuidChange(const char *oldUuid, const HbRespData *hbResp, uint32_t len)
{
    char zeroUuid[UUID_BUF_LEN] = { 0 };
    uint8_t uuidHash[SHA_256_HASH_LEN] = { 0 };

    if (oldUuid == NULL || hbResp == NULL) {
        LNN_LOGD(LNN_HEART_BEAT, "invalid param");
        return false;
    }
    if (memcmp(zeroUuid, hbResp->shortUuid, len) == 0) {
        LNN_LOGD(LNN_HEART_BEAT, "ignore zero uuid");
        return false;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)oldUuid, strlen(oldUuid), (unsigned char *)uuidHash) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "gen uuid hash err");
        return false;
    }
    if (memcmp(uuidHash, hbResp->shortUuid, len) != 0) {
        LNN_LOGE(LNN_HEART_BEAT,
            "don't support ble direct online because uuid change %{public}02x%{public}02x->%{public}02x%{public}02x",
            uuidHash[0], uuidHash[1], (hbResp->shortUuid)[0], (hbResp->shortUuid)[1]);
        return true;
    }
    return false;
}

static int32_t UpdateUserIdCheckSum(NodeInfo *deviceInfo, HbRespData *hbResp)
{
    if (deviceInfo == NULL || hbResp == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "deviceInfo or hbResp is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t userIdCheckSum[USERID_CHECKSUM_LEN] = {0};
    if (memcmp(hbResp->userIdCheckSum, userIdCheckSum, USERID_CHECKSUM_LEN) == 0) {
        LNN_LOGI(LNN_HEART_BEAT, "checkSum is null no need update");
        return SOFTBUS_OK;
    }
    int32_t ret = memcpy_s(deviceInfo->userIdCheckSum, USERID_CHECKSUM_LEN, hbResp->userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "memcpy failed");
    }
    uint8_t noEncryptUserId[USERID_LEN] = {0xFF, 0xFF, 0xFF, 0xFF};
    if (memcmp(noEncryptUserId, hbResp->advUserId, USERID_LEN) == 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint8_t defaultUserId[USERID_LEN] = {0};
    if ((memcmp(defaultUserId, hbResp->advUserId, USERID_LEN) != 0) &&
        DecryptUserId(deviceInfo, hbResp->advUserId, USERID_LEN) != SOFTBUS_OK) {
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsNeedConnectOnLine(DeviceInfo *device, HbRespData *hbResp, ConnectOnlineReason *connectReason)
{
    LNN_CHECK_AND_RETURN_RET_LOGE((hbResp != NULL) && (hbResp->stateVersion != STATE_VERSION_INVALID),
        true, LNN_HEART_BEAT,  "ble don't support ble direct online");
    int32_t ret, stateVersion;
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (!IsLocalSupportBleDirectOnline()) {
        LNN_LOGI(LNN_HEART_BEAT, "ble don't support ble direct online");
        return true;
    }
    if (LnnRetrieveDeviceInfo(device->devId, &deviceInfo) != SOFTBUS_OK ||
        IsInvalidBrmac(deviceInfo.connectInfo.macAddr)) {
        *connectReason = BLE_FIRST_CONNECT;
        LNN_LOGI(LNN_HEART_BEAT, "don't support ble direct online because retrieve fail, "
            "stateVersion=%{public}d->%{public}d", deviceInfo.stateVersion, (int32_t)hbResp->stateVersion);
        return true;
    }
    if (IsStateVersionChanged(hbResp, &deviceInfo, &stateVersion, connectReason)) {
        LNN_LOGI(LNN_HEART_BEAT, "don't support ble direct online because state version change");
        return true;
    }
    AuthDeviceKeyInfo keyInfo = { 0 };
    if ((!IsCloudSyncEnabled() || !IsFeatureSupport(deviceInfo.feature, BIT_CLOUD_SYNC_DEVICE_INFO)) &&
        AuthFindDeviceKey(device->devId, AUTH_LINK_TYPE_BLE, &keyInfo) != SOFTBUS_OK &&
        AuthFindLatestNormalizeKey(device->devId, &keyInfo, true) != SOFTBUS_OK) {
        *connectReason = DEVICEKEY_NOT_EXISTED;
        LNN_LOGE(LNN_HEART_BEAT, "don't support ble direct online because key not exist");
        return true;
    }
    (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    SetDeviceNetCapability(&deviceInfo.netCapacity, hbResp);
    (void)SetDeviceScreenStatus(&deviceInfo, hbResp->isScreenOn);
    LNN_CHECK_AND_RETURN_RET_LOGE(UpdateUserIdCheckSum(&deviceInfo, hbResp) == SOFTBUS_OK,
        true, LNN_HEART_BEAT, "don't support ble direct online because UpdateUserIdCheckSum fail");
    if ((ret = LnnUpdateRemoteDeviceInfo(&deviceInfo)) != SOFTBUS_OK) {
        *connectReason = UPDATE_REMOTE_DEVICE_INFO_FAILED;
        LNN_LOGE(LNN_HEART_BEAT, "don't support ble direct online because update device info fail ret=%{public}d", ret);
        return true;
    }
    if ((deviceInfo.deviceInfo.osType == OH_OS_TYPE) && (!IsCipherManagerFindKey(deviceInfo.deviceInfo.deviceUdid))) {
        *connectReason = FIND_REMOTE_CIPHERKEY_FAILED;
        LNN_LOGE(LNN_HEART_BEAT, "don't support ble direct online because broadcast key");
        return true;
    }
    if (IsUuidChange(deviceInfo.uuid, hbResp, HB_SHORT_UUID_LEN)) {
        return true;
    }
    LNN_LOGI(LNN_HEART_BEAT, "support ble direct online");
    return false;
}

static bool HbIsRepeatedReAuthRequest(LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (storedInfo == NULL) {
        return false;
    }
    if (nowTime - storedInfo->lastJoinLnnTime < HB_REAUTH_TIME) {
        return true;
    }
    storedInfo->lastJoinLnnTime = nowTime;
    return false;
}

static bool HbIsValidJoinLnnRequest(DeviceInfo *device, HbRespData *hbResp)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (!IsLocalSupportThreeState()) {
        LNN_LOGI(LNN_HEART_BEAT, "local don't support three state");
        return true;
    }
    if (LnnRetrieveDeviceInfo(device->devId, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_HEART_BEAT, "retrieve device info failed");
        return true;
    }
    if ((nodeInfo.feature & (1 << BIT_SUPPORT_THREE_STATE)) == 0 && SoftBusGetBrState() == BR_DISABLE) {
        char *anonyUdid = NULL;
        Anonymize(device->devId, &anonyUdid);
        LNN_LOGI(LNN_HEART_BEAT, "peer udidHash=%{public}s don't support three state and local br off",
            AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        return false;
    }
    return true;
}

static uint64_t GetNowTime()
{
    SoftBusSysTime times = { 0 };
    SoftBusGetTime(&times);
    return (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
}

static void CopyBleReportExtra(const LnnBleReportExtra *bleExtra, LnnEventExtra *extra)
{
    if (bleExtra == NULL || extra == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid param");
        return;
    }

    extra->onlineNum = bleExtra->extra.onlineNum;
    extra->errcode = bleExtra->extra.errcode;
    extra->lnnType = bleExtra->extra.lnnType;
    extra->result = bleExtra->extra.result;
    extra->localUdidHash = bleExtra->extra.localUdidHash;
    extra->peerUdidHash = bleExtra->extra.peerUdidHash;
    extra->osType = bleExtra->extra.osType;
    extra->localDeviceType = bleExtra->extra.localDeviceType;
    extra->peerDeviceType = bleExtra->extra.peerDeviceType;
    extra->connOnlineReason = bleExtra->extra.connOnlineReason;
    if (bleExtra->extra.peerNetworkId[0] != '\0') {
        extra->onlineType = bleExtra->extra.onlineType;
        extra->peerNetworkId = bleExtra->extra.peerNetworkId;
        extra->peerUdid = bleExtra->extra.peerUdid;
        extra->peerBleMac = bleExtra->extra.peerBleMac;
    }
}

static void HbProcessDfxMessage(void *para)
{
    if (para == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid para");
        return;
    }
    LnnBleReportExtra bleExtra;
    (void)memset_s(&bleExtra, sizeof(LnnBleReportExtra), 0, sizeof(LnnBleReportExtra));
    if (GetNodeFromLnnBleReportExtraMap((char *)para, &bleExtra) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get ble report node from lnnBleReportExtraMap fail");
        SoftBusFree(para);
        return;
    }
    if (bleExtra.status == BLE_REPORT_EVENT_SUCCESS || bleExtra.status == BLE_REPORT_EVENT_INIT) {
        DeleteNodeFromLnnBleReportExtraMap((char *)para);
        SoftBusFree(para);
        return;
    }
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    CopyBleReportExtra(&bleExtra, &extra);
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
    LNN_LOGI(LNN_HEART_BEAT, "the device online failed within 7 seconds.");
    DeleteNodeFromLnnBleReportExtraMap((char *)para);
    SoftBusFree(para);
}

static int32_t HbAddAsyncProcessCallbackDelay(DeviceInfo *device, bool *IsRestrict)
{
    if (device == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    LnnBleReportExtra bleExtra;
    (void)memset_s(&bleExtra, sizeof(LnnBleReportExtra), 0, sizeof(LnnBleReportExtra));
    if (device->addr[0].type == CONNECTION_ADDR_BLE) {
        char *udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
        if (udidHash == NULL) {
            LNN_LOGE(LNN_HEART_BEAT, "udidHash calloc fail");
            return SOFTBUS_MALLOC_ERR;
        }
        ret = ConvertBytesToHexString(
            udidHash, SHORT_UDID_HASH_HEX_LEN + 1, device->addr[0].info.ble.udidHash, SHORT_UDID_HASH_LEN);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "convert bytes to string fail");
            SoftBusFree(udidHash);
            return ret;
        }
        uint32_t count = 0;
        if (GetNodeFromPcRestrictMap(udidHash, &count) == SOFTBUS_OK && count == PC_RESTRICT_TIME) {
            LNN_LOGI(LNN_HEART_BEAT, "restrict pc");
            *IsRestrict = true;
        }
        if (!IsExistLnnDfxNodeByUdidHash(udidHash, &bleExtra)) {
            bleExtra.status = BLE_REPORT_EVENT_INIT;
            AddNodeToLnnBleReportExtraMap(udidHash, &bleExtra);
            ret = LnnAsyncCallbackDelayHelper(
                GetLooper(LOOP_TYPE_DEFAULT), HbProcessDfxMessage, (void *)udidHash, HB_DFX_DELAY_TIME);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "HbProcessDfxMessage failed, due to set async callback fail");
                SoftBusFree(udidHash);
                return ret;
            }
            // udidHash will free When the callback function HbProcessDfxMessage is started.
            return SOFTBUS_OK;
        }
        SoftBusFree(udidHash);
    }
    return SOFTBUS_OK;
}

static void ProcessUdidAnonymize(char *devId)
{
    char *anonyUdid = NULL;
    Anonymize(devId, &anonyUdid);
    LNN_LOGD(LNN_HEART_BEAT, "recv but ignore repeated join lnn request, udidHash=%{public}s",
        AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

static int32_t SoftBusNetNodeResult(DeviceInfo *device, HbRespData *hbResp,
    LnnConnectCondition *connectCondition, LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    char *anonyUdid = NULL;
    Anonymize(device->devId, &anonyUdid);
    LNN_LOGI(LNN_HEART_BEAT,
        "heartbeat(HB) find device, udidHash=%{public}s, ConnectionAddrType=%{public}02X, isConnect=%{public}d, "
        "connectReason=%{public}u", AnonymizeWrapper(anonyUdid),
        device->addr[0].type, connectCondition->isConnect, connectCondition->connectReason);
    AnonymizeFree(anonyUdid);

    LnnDfxDeviceInfoReport info;
    (void)memset_s(&info, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    if (hbResp != NULL) {
        info.osType = ((hbResp->capabiltiy & BLE_TRIGGER_HML) != 0) ? OH_OS_TYPE : HO_OS_TYPE;
    } else {
        info.osType = HO_OS_TYPE;
    }
    info.type = device->devType;
    info.bleConnectReason = connectCondition->connectReason;
    bool IsRestrict = false;
    if (HbAddAsyncProcessCallbackDelay(device, &IsRestrict) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HbAddAsyncProcessCallbackDelay fail");
    }
    if (IsRestrict) {
        return SOFTBUS_NETWORK_PC_RESTRICT;
    }
    if (HbIsRepeatedJoinLnnRequest(storedInfo, nowTime)) {
        ProcessUdidAnonymize(device->devId);
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (LnnNotifyDiscoveryDevice(device->addr, &info, connectCondition->isConnect) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "mgr recv process notify device found fail");
        return SOFTBUS_NETWORK_NOTIFY_DISCOVERY_DEV_ERR;
    }
    if (connectCondition->isDirectlyHb) {
        return SOFTBUS_NETWORK_HEARTBEAT_DIRECT;
    }
    if (connectCondition->isConnect) {
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    } else {
        return SOFTBUS_NETWORK_NODE_DIRECT_ONLINE;
    }
}

static void DfxRecordHeartBeatAuthStart(const AuthConnInfo *connInfo, const char *packageName, uint32_t requestId)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authRequestId = (int32_t)requestId;

    if (connInfo != NULL) {
        extra.authLinkType = connInfo->type;
    }
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) &&
        strncpy_s(pkgName, PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH, extra);
}

static int32_t HbOnlineNodeAuth(DeviceInfo *device, LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (!device->isOnline) {
        LNN_LOGW(LNN_HEART_BEAT, "ignore lnn request, not support connect");
        return SOFTBUS_OK;
    }
    if (HbIsRepeatedReAuthRequest(storedInfo, nowTime)) {
        LNN_LOGE(LNN_HEART_BEAT, "reauth request repeated");
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    AuthConnInfo authConn;
    uint32_t requestId = AuthGenRequestId();
    (void)LnnConvertAddrToAuthConnInfo(device->addr, &authConn);
    DfxRecordHeartBeatAuthStart(&authConn, LNN_DEFAULT_PKG_NAME, requestId);
    if (AuthStartVerify(&authConn, requestId, LnnGetReAuthVerifyCallback(), AUTH_MODULE_LNN, false) != SOFTBUS_OK) {
        LNN_LOGI(LNN_HEART_BEAT, "AuthStartVerify error");
        return SOFTBUS_AUTH_START_VERIFY_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t HbSuspendReAuth(DeviceInfo *device)
{
    if (device->addr[0].type == CONNECTION_ADDR_BLE) {
        char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
        if (ConvertBytesToUpperCaseHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1, device->addr[0].info.ble.udidHash,
                SHORT_UDID_HASH_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "convert bytes to string fail");
            return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
        }
        if (IsNeedAuthLimit(udidHash)) {
            char *anonyUdidHash = NULL;
            Anonymize(udidHash, &anonyUdidHash);
            LNN_LOGI(LNN_HEART_BEAT, "current device need delay authentication, type=%{public}d, udidHash=%{public}s",
                device->addr[0].type, AnonymizeWrapper(anonyUdidHash));
            AnonymizeFree(anonyUdidHash);
            return SOFTBUS_NETWORK_BLE_CONNECT_SUSPEND;
        }
    }
    return SOFTBUS_OK;
}

static int32_t CheckReceiveDeviceInfo(
    DeviceInfo *device, LnnHeartbeatType hbType, const LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    if (HbIsRepeatedRecvInfo(hbType, storedInfo, device, nowTime)) {
        LNN_LOGD(LNN_HEART_BEAT, "repeat receive info");
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    if (HbSuspendReAuth(device) == SOFTBUS_NETWORK_BLE_CONNECT_SUSPEND) {
        return SOFTBUS_NETWORK_BLE_CONNECT_SUSPEND;
    }
    return SOFTBUS_OK;
}

static int32_t CheckJoinLnnRequest(DeviceInfo *device, HbRespData *hbResp)
{
    if (!HbIsValidJoinLnnRequest(device, hbResp)) {
        return SOFTBUS_NETWORK_JOIN_REQUEST_ERR;
    }
    return SOFTBUS_OK;
}

static void ProcRespVapChange(DeviceInfo *device, HbRespData *hbResp)
{
    if (device == NULL || hbResp == NULL) {
        LNN_LOGD(LNN_HEART_BEAT, "param is nullptr");
        return;
    }
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    int32_t ret = LnnGetAllOnlineNodeInfo(&info, &infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get all online node info fail");
        return;
    }
    if (info == NULL) {
        LNN_LOGD(LNN_HEART_BEAT, "online info is null");
        return;
    }
    if (infoNum == 0) {
        LNN_LOGW(LNN_HEART_BEAT, "none online node");
        SoftBusFree(info);
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            LNN_LOGD(LNN_HEART_BEAT, "get nodeInfo fail");
            continue;
        }
        if (LnnGenerateHexStringHash((const unsigned char *)nodeInfo.deviceInfo.deviceUdid, udidHash,
            HB_SHORT_UDID_HASH_HEX_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(udidHash, device->devId, HB_SHORT_UDID_HASH_HEX_LEN) == 0) {
            LNN_LOGD(LNN_HEART_BEAT, "hbResp preChannelCode=%{public}d", hbResp->preferChannel);
            (void)LnnAddRemoteChannelCode(nodeInfo.deviceInfo.deviceUdid, hbResp->preferChannel);
            SoftBusFree(info);
            return;
        }
    }
    SoftBusFree(info);
}

static bool IsSupportCloudSync(DeviceInfo *device)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint64_t localFeature = 0;
    if (LnnRetrieveDeviceInfo(device->devId, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "don't support cloud sync beacause retrive info fail");
        return false;
    }
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "don't support cloud sync beacause get local feature fail");
        return false;
    }
    return IsFeatureSupport(localFeature, BIT_CLOUD_SYNC_DEVICE_INFO) &&
        IsFeatureSupport(info.feature, BIT_CLOUD_SYNC_DEVICE_INFO);
}

static bool IsDirectlyHeartBeat(DeviceInfo *device, HbRespData *hbResp)
{
    if (device == NULL || hbResp == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "device or resp is null");
        return false;
    }
    if (hbResp->hbVersion == HB_VERSION_V2) {
        LNN_LOGE(LNN_HEART_BEAT, "hb version is v2");
        return true;
    }
    return false;
}

static int32_t CheckJoinLnnConnectResult(
    DeviceInfo *device, HbRespData *hbResp, bool isDirectlyHb, LnnHeartbeatRecvInfo *storedInfo, uint64_t nowTime)
{
    LnnConnectCondition connectCondition;
    int32_t res = CheckJoinLnnRequest(device, hbResp);
    if (res != SOFTBUS_OK) {
        return res;
    }
    connectCondition.connectReason = CONNECT_INITIAL_VALUE;
    connectCondition.isDirectlyHb = isDirectlyHb;
    connectCondition.isConnect = IsNeedConnectOnLine(device, hbResp, &connectCondition.connectReason);
    if (connectCondition.isConnect && !device->isOnline) {
        if (IsSupportCloudSync(device)) {
            return SOFTBUS_NETWORK_PEER_NODE_CONNECT;
        }
        return SOFTBUS_NETWORK_NOT_CONNECTABLE;
    }
    return SoftBusNetNodeResult(device, hbResp, &connectCondition, storedInfo, nowTime);
}

static void CheckUserIdCheckSumChange(HbRespData *hbResp, NodeInfo *nodeInfo)
{
    if (hbResp == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid param");
        return;
    }
    int32_t userIdCheckSum = 0;
    int32_t ret = memcpy_s(&userIdCheckSum, sizeof(int32_t), hbResp->userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "memcpy failed! userIdchecksum:%{public}d", userIdCheckSum);
        return;
    }
    if (userIdCheckSum == 0) {
        LNN_LOGW(LNN_HEART_BEAT, "useridchecksum all zero");
        return;
    }
    bool isChange = false;
    ret = memcmp(hbResp->userIdCheckSum, nodeInfo->userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != 0) {
        isChange = true;
    }
    if (isChange) {
        LNN_LOGI(LNN_HEART_BEAT, "adv userIdCheckSum changed!");
        NotifyForegroundUseridChange(nodeInfo->networkId, nodeInfo->discoveryType, isChange);
        LnnSetDLConnUserIdCheckSum(nodeInfo->networkId, userIdCheckSum);
    }
}

static bool IsNetworkIdChange(DeviceInfo *device, NodeInfo *remoteInfo, HbRespData *hbResp)
{
    if (device == NULL || remoteInfo == NULL || hbResp == NULL) {
        LNN_LOGD(LNN_HEART_BEAT, "invalid param");
        return false;
    }

    if (!LnnIsNodeOnline(remoteInfo)) {
        return false;
    }
    if ((int32_t)hbResp->stateVersion == remoteInfo->stateVersion) {
        return false;
    }

    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfo(device->devId, &cacheInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "retrieve device info fail");
        return false;
    }

    if (strcmp(cacheInfo.networkId, remoteInfo->networkId) == 0) {
        return false;
    }
    char *cacheNetworkId = NULL;
    char *remoteNetworkId = NULL;
    Anonymize(cacheInfo.networkId, &cacheNetworkId);
    Anonymize(remoteInfo->networkId, &remoteNetworkId);
    LNN_LOGI(LNN_HEART_BEAT, "cacheNetworkId=%{public}s; remoteNetworkId=%{public}s",
        AnonymizeWrapper(cacheNetworkId), AnonymizeWrapper(remoteNetworkId));
    AnonymizeFree(cacheNetworkId);
    AnonymizeFree(remoteNetworkId);
    return true;
}

static int32_t HbNotifyReceiveDevice(DeviceInfo *device, const LnnHeartbeatWeight *mediumWeight,
    LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp)
{
    uint64_t nowTime = GetNowTime();
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_hbRecvList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        LNN_HEART_BEAT, "try to lock failed");
    LnnHeartbeatRecvInfo *storedInfo = HbGetStoredRecvInfo(device->devId, device->addr[0].type, nowTime);
    int32_t res = CheckReceiveDeviceInfo(device, hbType, storedInfo, nowTime);
    if (res != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return res;
    }
    if (HbSaveRecvTimeToRemoveRepeat(
        storedInfo, device, mediumWeight->weight, mediumWeight->localMasterWeight, nowTime) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return SOFTBUS_NETWORK_HB_SAVE_RECV_TIME_FAIL;
    }
    if (isOnlineDirectly) {
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        (void)HbUpdateOfflineTimingByRecvInfo(device->devId, device->addr[0].type, hbType, nowTime);
        return SOFTBUS_NETWORK_HEARTBEAT_REPEATED;
    }
    HbDumpRecvDeviceInfo(device, mediumWeight->weight, mediumWeight->localMasterWeight, hbType, nowTime);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    bool isDirectlyHb = IsDirectlyHeartBeat(device, hbResp);
    if (HbGetOnlineNodeByRecvInfo(device->devId, device->addr[0].type, &nodeInfo, hbResp) == SOFTBUS_OK) {
        CheckUserIdCheckSumChange(hbResp, &nodeInfo);
        if (isDirectlyHb || (!HbIsNeedReAuth(&nodeInfo, device->accountHash) &&
            !IsUuidChange(nodeInfo.uuid, hbResp, HB_SHORT_UUID_LEN) &&
            !IsNetworkIdChange(device, &nodeInfo, hbResp))) {
            (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
            return HbUpdateOfflineTimingByRecvInfo(nodeInfo.networkId, device->addr[0].type, hbType, nowTime);
        }
        res = HbOnlineNodeAuth(device, storedInfo, nowTime);
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return res;
    }
    res = CheckJoinLnnConnectResult(device, hbResp, isDirectlyHb, storedInfo, nowTime);
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
    return res;
}

static int32_t HbMediumMgrRecvProcess(DeviceInfo *device, const LnnHeartbeatWeight *mediumWeight,
    LnnHeartbeatType hbType, bool isOnlineDirectly, HbRespData *hbResp)
{
    if (device == NULL || mediumWeight == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "mgr recv process get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!AuthIsPotentialTrusted(device)) {
        char *anonyUdid = NULL;
        Anonymize(device->devId, &anonyUdid);
        LNN_LOGW(LNN_HEART_BEAT,
            ">> heartbeat(HB) OnTock is not potential trusted, udid=%{public}s, accountHash=%{public}02X%{public}02X",
            AnonymizeWrapper(anonyUdid), device->accountHash[0], device->accountHash[1]);
        AnonymizeFree(anonyUdid);
        return SOFTBUS_NETWORK_HEARTBEAT_UNTRUSTED;
    }
    ProcRespVapChange(device, hbResp);
    return HbNotifyReceiveDevice(device, mediumWeight, hbType, isOnlineDirectly, hbResp);
}

static int32_t HbMediumMgrRecvHigherWeight(
    const char *udidHash, int32_t weight, ConnectionAddrType type, bool isReElect, bool isPeerScreenOn)
{
    NodeInfo nodeInfo;
    char masterUdid[UDID_BUF_LEN] = { 0 };
    bool isFromMaster = false;

    if (udidHash == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "mgr recv higher weight get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    if (HbGetOnlineNodeByRecvInfo(udidHash, type, &nodeInfo, NULL) != SOFTBUS_OK) {
        char *anonyUdid = NULL;
        Anonymize(udidHash, &anonyUdid);
        LNN_LOGD(LNN_HEART_BEAT, "recv higher weight is not online yet. udidhash=%{public}s",
            AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        return SOFTBUS_OK;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, sizeof(masterUdid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get local master udid fail");
        return SOFTBUS_NETWORK_GET_LEDGER_INFO_ERR;
    }
    isFromMaster = strcmp(masterUdid, nodeInfo.deviceInfo.deviceUdid) == 0 ? true : false;
    if (isReElect && !isFromMaster &&
        LnnNotifyMasterElect(nodeInfo.networkId, nodeInfo.deviceInfo.deviceUdid, weight) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "notify master elect fail");
        return SOFTBUS_NETWORK_NOTIFY_MASTER_ELECT_ERR;
    }
    if (isFromMaster && isPeerScreenOn) {
        LnnSetHbAsMasterNodeState(false);
    }
    char *anonyUdid = NULL;
    Anonymize(udidHash, &anonyUdid);
    char *anonyMasterUdid = NULL;
    Anonymize(masterUdid, &anonyMasterUdid);
    LNN_LOGI(LNN_HEART_BEAT, "recv higher weight udidHash=%{public}s, weight=%{public}d, masterUdid=%{public}s",
        AnonymizeWrapper(anonyUdid), weight, AnonymizeWrapper(anonyMasterUdid));
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyMasterUdid);
    return SOFTBUS_OK;
}

static void HbMediumMgrRecvLpInfo(const char *networkId, uint64_t nowTime)
{
    if (HbUpdateOfflineTimingByRecvInfo(networkId, CONNECTION_ADDR_BLE, HEARTBEAT_TYPE_BLE_V4, nowTime) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB medium mgr update time stamp fail");
    }
}

static void HbMediumMgrRelayProcess(const char *udidHash, ConnectionAddrType type, LnnHeartbeatType hbType)
{
    (void)type;

    if (udidHash == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "mgr relay get invalid param");
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(udidHash, &anonyUdid);
    LNN_LOGD(LNN_HEART_BEAT, "mgr relay process, udidhash=%{public}s, hbType=%{public}d",
        AnonymizeWrapper(anonyUdid), hbType);
    AnonymizeFree(anonyUdid);
    if (LnnStartHbByTypeAndStrategy(hbType | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "mgr relay process fail");
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
        LNN_LOGE(LNN_INIT, "create recv list fail");
        return SOFTBUS_CREATE_LIST_ERR;
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
        LNN_LOGE(LNN_INIT, "deinit recv list lock recv info list fail");
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
        LNN_LOGE(LNN_HEART_BEAT, "deinit recv list lock recv info list fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item->device);
        SoftBusFree(item);
    }
    g_hbRecvList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
}

void LnnDumpHbMgrRecvList(void)
{
#define HB_DUMP_UPDATE_INFO_MAX_NUM 10
    int32_t dumpCount = 0;
    char *deviceType = NULL;
    LnnHeartbeatRecvInfo *item = NULL;

    if (SoftBusMutexLock(&g_hbRecvList->lock) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "dump recv list lock recv info list fail");
        return;
    }
    if (IsListEmpty(&g_hbRecvList->list)) {
        LNN_LOGD(LNN_HEART_BEAT, "DumpHbMgrRecvList count=0");
        (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_hbRecvList->list, LnnHeartbeatRecvInfo, node) {
        char *anonyUdid = NULL;
        dumpCount++;
        if (dumpCount > HB_DUMP_UPDATE_INFO_MAX_NUM) {
            break;
        }
        deviceType = LnnConvertIdToDeviceType((uint16_t)item->device->devType);
        if (deviceType == NULL) {
            Anonymize(item->device->devId, &anonyUdid);
            LNN_LOGE(LNN_HEART_BEAT, "get deviceType fail, udidHash=%{public}s", AnonymizeWrapper(anonyUdid));
            AnonymizeFree(anonyUdid);
            continue;
        }
        Anonymize(item->device->devId, &anonyUdid);
        LNN_LOGD(LNN_HEART_BEAT,
            "DumpRecvList count=%{public}d, i=%{public}d, udidHash=%{public}s, deviceType=%{public}s, "
            "ConnectionAddrType=%{public}02X, weight=%{public}d, masterWeight=%{public}d, "
            "lastRecvTime=%{public}" PRIu64, g_hbRecvList->cnt, dumpCount,
            AnonymizeWrapper(anonyUdid), deviceType, item->device->addr[0].type, item->weight,
            item->masterWeight, item->lastRecvTime);
        AnonymizeFree(anonyUdid);
    }
    (void)SoftBusMutexUnlock(&g_hbRecvList->lock);
}

void LnnDumpHbOnlineNodeList(void)
{
#define HB_DUMP_ONLINE_NODE_MAX_NUM 5
    int32_t infoNum = 0;
    uint64_t oldTimestamp;
    NodeBasicInfo *info = NULL;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get node info fail");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGD(LNN_HEART_BEAT, "DumpHbOnlineNodeList count=0");
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    for (int32_t i = 0; i < infoNum; ++i) {
        if (i > HB_DUMP_ONLINE_NODE_MAX_NUM) {
            break;
        }
        if (LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            continue;
        }
        if (LnnGetDLHeartbeatTimestamp(info[i].networkId, &oldTimestamp) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "get timestamp err, nodeInfo i=%{public}d", i);
            continue;
        }
        char *deviceTypeStr = LnnConvertIdToDeviceType(nodeInfo.deviceInfo.deviceTypeId);
        char *anonyDeviceName = NULL;
        Anonymize(nodeInfo.deviceInfo.deviceName, &anonyDeviceName);
        LNN_LOGD(LNN_HEART_BEAT,
            "DumpOnlineNodeList count=%{public}d, i=%{public}d, deviceName=%{public}s, deviceTypeId=%{public}d, "
            "deviceTypeStr=%{public}s, masterWeight=%{public}d, discoveryType=%{public}d, "
            "oldTimestamp=%{public}" PRIu64 "",
            infoNum, i + 1, AnonymizeWrapper(anonyDeviceName), nodeInfo.deviceInfo.deviceTypeId,
            deviceTypeStr != NULL ? deviceTypeStr : "", nodeInfo.masterWeight, nodeInfo.discoveryType, oldTimestamp);
        AnonymizeFree(anonyDeviceName);
    }
    SoftBusFree(info);
}

int32_t LnnHbMediumMgrInit(void)
{
    if (LnnRegistBleHeartbeatMediumMgr() != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "regist ble heartbeat manager fail");
        return SOFTBUS_NETWORK_HB_MGR_REG_FAIL;
    }
    if (LnnRegisterBleLpDeviceMediumMgr() != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "LP regist LpDevice manager fail");
        return SOFTBUS_NETWORK_HB_MGR_REG_FAIL;
    }
    return HbInitRecvList();
}

static bool VisitHbMediumMgrSendBegin(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    int32_t id, ret;
    LnnHeartbeatSendBeginData *custData = NULL;

    if (data == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "manager send once begin get invalid param");
        return false;
    }
    custData = (LnnHeartbeatSendBeginData *)data;
    custData->hbType = eachType;
    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        LNN_LOGE(LNN_HEART_BEAT, "manager send once begin convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        LNN_LOGW(LNN_HEART_BEAT, "not support heartbeat type=%{public}d", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onSendOneHbBegin == NULL) {
        LNN_LOGW(LNN_HEART_BEAT, "manager send once begin cb is NULL, type=%{public}d", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onSendOneHbBegin(custData);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "send once begin fail, type=%{public}d, ret=%{public}d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData)
{
    if (custData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrSendBegin, &custData->hbType, custData)) {
        LNN_LOGE(LNN_HEART_BEAT, "manager hb send begin fail. hbType=%{public}d", custData->hbType);
        return SOFTBUS_NETWORK_HB_SEND_BEGIN_FAILED;
    }
    return SOFTBUS_OK;
}

static bool VisitHbMediumMgrSendEnd(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    int32_t id, ret;
    LnnHeartbeatSendEndData *custData = NULL;

    if (data == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "manager send once end get invalid param");
        return false;
    }
    if (eachType == HEARTBEAT_TYPE_BLE_V3) {
        LNN_LOGI(LNN_HEART_BEAT, "V3 don't stop");
        return true;
    }
    custData = (LnnHeartbeatSendEndData *)data;
    custData->hbType = eachType;
    id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        LNN_LOGE(LNN_HEART_BEAT, "manager stop one cycle convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        LNN_LOGW(LNN_HEART_BEAT, "not support heartbeat type=%{public}d", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onSendOneHbEnd == NULL) {
        LNN_LOGW(LNN_HEART_BEAT, "manager send once end cb is NULL, type=%{public}d", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onSendOneHbEnd(custData);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "stop one cycle hb fail, type=%{public}d, ret=%{public}d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *custData)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrSendEnd, &custData->hbType, custData)) {
        LNN_LOGE(LNN_HEART_BEAT, "manager hb send end fail. hbType=%{public}d", custData->hbType);
        return SOFTBUS_NETWORK_HB_SEND_END_FAILED;
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
        LNN_LOGE(LNN_HEART_BEAT, "stop heartbeat convert type fail");
        return false;
    }
    if (g_hbMeidumMgr[id] == NULL || (eachType & g_hbMeidumMgr[id]->supportType) == 0) {
        LNN_LOGW(LNN_HEART_BEAT, "not support heartbeat type=%{public}d", eachType);
        return true;
    }
    if (g_hbMeidumMgr[id]->onStopHbByType == NULL) {
        LNN_LOGW(LNN_HEART_BEAT, "manager stop cb is NULL, type=%{public}d", eachType);
        return true;
    }
    ret = g_hbMeidumMgr[id]->onStopHbByType();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "stop heartbeat fail, type=%{public}d, ret=%{public}d", eachType, ret);
        return false;
    }
    return true;
}

int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    if (!LnnVisitHbTypeSet(VisitHbMediumMgrStop, type, NULL)) {
        LNN_LOGE(LNN_HEART_BEAT, "manager stop fail. hbType=%{public}d", *type);
        return SOFTBUS_NETWORK_HB_STOP_PROCESS_FAIL;
    }
    return SOFTBUS_OK;
}

void LnnHbMediumMgrDeinit(void)
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

int32_t LnnHbMediumMgrSetParam(void *param)
{
    int32_t id, ret;

    if (param == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "set medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHeartbeatMediumParam *mediumParam = (LnnHeartbeatMediumParam *)param;
    id = LnnConvertHbTypeToId(mediumParam->type);
    if (id == HB_INVALID_TYPE_ID) {
        LNN_LOGE(LNN_HEART_BEAT, "set medium param convert type fail");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_hbMeidumMgr[id] == NULL || g_hbMeidumMgr[id]->onSetMediumParam == NULL) {
        LNN_LOGW(LNN_HEART_BEAT, "not support heartbeat type=%{public}d", mediumParam->type);
        return SOFTBUS_NETWORK_NOT_SUPPORT;
    }
    ret = g_hbMeidumMgr[id]->onSetMediumParam((const LnnHeartbeatMediumParam *)mediumParam);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "set medium param fail, type=%{public}d, ret=%{public}d", mediumParam->type, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
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
            LNN_LOGE(LNN_HEART_BEAT, "manager update send info fail, i=%{public}d", i);
            return SOFTBUS_NETWORK_HB_UPDATE_SEND_INFO_FAIL;
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
        LNN_LOGE(LNN_HEART_BEAT, "regist manager convert type fail");
        return false;
    }
    LNN_LOGD(LNN_HEART_BEAT, "Regeist medium manager id=%{public}d", id);
    g_hbMeidumMgr[id] = mgr;
    return true;
}

int32_t LnnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    // TODO: One-to-one correspondence between LnnHeartbeatMediumMgr and implementation.
    if (mgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "regist manager get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitRegistHeartbeatMediumMgr, &mgr->supportType, (void *)mgr)) {
        LNN_LOGE(LNN_HEART_BEAT, "regist manager fail");
        return SOFTBUS_NETWORK_HB_MGR_REG_FAIL;
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
    int32_t id = LnnConvertHbTypeToId(eachType);
    if (id == HB_INVALID_TYPE_ID) {
        LNN_LOGE(LNN_HEART_BEAT, "unregist manager convert type fail");
        return false;
    }
    g_hbMeidumMgr[id] = NULL;
    return true;
}

int32_t LnnUnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    if (mgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "unregist manager get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnVisitHbTypeSet(VisitUnRegistHeartbeatMediumMgr, &mgr->supportType, (void *)mgr)) {
        LNN_LOGE(LNN_HEART_BEAT, "unregist manager fail");
        return SOFTBUS_NETWORK_HB_MGR_UNREG_FAIL;
    }
    if (mgr->deinit != NULL) {
        mgr->deinit();
    }
    return SOFTBUS_OK;
}
