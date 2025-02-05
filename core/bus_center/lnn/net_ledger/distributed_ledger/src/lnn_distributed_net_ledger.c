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

#include "lnn_distributed_net_ledger_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "lnn_event.h"
#include "anonymizer.h"
#include "auth_common.h"
#include "auth_deviceprofile.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_fast_offline.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_lane_def.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_device_info_recovery.h"
#include "lnn_feature_capability.h"
#include "lnn_link_finder.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_crypto.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_crypto.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "bus_center_manager.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "bus_center_event.h"

DistributedNetLedger g_distributedNetLedger;

DistributedNetLedger* LnnGetDistributedNetLedger(void)
{
    return &g_distributedNetLedger;
}

static void UpdateNetworkInfo(const char *udid)
{
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
    }
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetBasicInfoByUdid fail.");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_NETWORK_INFO);
}

static void UpdateDeviceNameInfo(const char *udid, const char *oldDeviceName)
{
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
        return;
    }
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetBasicInfoByUdid fail.");
        return;
    }
    char *anonyOldDeviceName = NULL;
    Anonymize(oldDeviceName, &anonyOldDeviceName);
    char *anonyDeviceName = NULL;
    Anonymize(basic.deviceName, &anonyDeviceName);
    LNN_LOGI(LNN_LEDGER, "report deviceName update, name:%{public}s -> %{public}s.",
        AnonymizeWrapper(anonyOldDeviceName), AnonymizeWrapper(anonyDeviceName));
    AnonymizeFree(anonyOldDeviceName);
    AnonymizeFree(anonyDeviceName);
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
}

int32_t LnnSetAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

int32_t LnnClearAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) & (~(1 << (uint32_t)type));
    return SOFTBUS_OK;
}

NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id)
{
    if (map == NULL || id == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return NULL;
    }
    NodeInfo *info = NULL;
    if ((info = (NodeInfo *)LnnMapGet(&map->udidMap, id)) != NULL) {
        return info;
    }
    if ((info = (NodeInfo *)LnnMapGet(&map->macMap, id)) != NULL) {
        return info;
    }
    if ((info = (NodeInfo *)LnnMapGet(&map->ipMap, id)) != NULL) {
        return info;
    }
    LNN_LOGE(LNN_LEDGER, "id not exist!");
    return NULL;
}

static int32_t InitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&map->udidMap);
    LnnMapInit(&map->ipMap);
    LnnMapInit(&map->macMap);
    return SOFTBUS_OK;
}

static void DeinitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return;
    }
    LnnMapDelete(&map->udidMap);
    LnnMapDelete(&map->ipMap);
    LnnMapDelete(&map->macMap);
}

static int32_t InitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&cnnCode->connectionCode);
    return SOFTBUS_OK;
}

static void DeinitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return;
    }
    LnnMapDelete(&cnnCode->connectionCode);
    return;
}

void LnnDeinitDistributedLedger(void)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return;
    }
    g_distributedNetLedger.status = DL_INIT_UNKNOWN;
    DeinitDistributedInfo(&g_distributedNetLedger.distributedInfo);
    DeinitConnectionCode(&g_distributedNetLedger.cnnCode);
    if (SoftBusMutexUnlock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "unlock mutex fail!");
    }
    SoftBusMutexDestroy(&g_distributedNetLedger.lock);
}

static void NewWifiDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *macAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    newInfo->stateVersion = oldInfo->stateVersion;
    macAddr = LnnGetBtMac(newInfo);
    if (macAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetBtMac Fail!");
        return;
    }
    if (strcmp(macAddr, DEFAULT_MAC) == 0) {
        LnnSetBtMac(newInfo, LnnGetBtMac(oldInfo));
    }
}

static void NewBrBleDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *ipAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    ipAddr = LnnGetWiFiIp(newInfo);
    if (ipAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetWiFiIp Fail!");
        return;
    }
    if (strcmp(ipAddr, DEFAULT_IP) == 0 || strcmp(ipAddr, LOCAL_IP) == 0) {
        LnnSetWiFiIp(newInfo, LnnGetWiFiIp(oldInfo));
    }

    newInfo->connectInfo.authPort = oldInfo->connectInfo.authPort;
    newInfo->connectInfo.proxyPort = oldInfo->connectInfo.proxyPort;
    newInfo->connectInfo.sessionPort = oldInfo->connectInfo.sessionPort;
    (void)LnnSetNetCapability(&newInfo->netCapacity, BIT_WIFI);
    (void)LnnSetNetCapability(&newInfo->netCapacity, BIT_WIFI_P2P);
    if ((oldInfo->netCapacity & (1 << BIT_WIFI_5G)) != 0) {
        (void)LnnSetNetCapability(&(newInfo->netCapacity), BIT_WIFI_5G);
    }
    if ((oldInfo->netCapacity & (1 << BIT_WIFI_24G)) != 0) {
        (void)LnnSetNetCapability(&(newInfo->netCapacity), BIT_WIFI_24G);
    }
}

static void RetainOfflineCode(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    if (memcpy_s(newInfo->offlineCode, OFFLINE_CODE_BYTE_SIZE,
        oldInfo->offlineCode, OFFLINE_CODE_BYTE_SIZE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "memcpy offlineCode error!");
        return;
    }
}
static int32_t ConvertNodeInfoToBasicInfo(const NodeInfo *info, NodeBasicInfo *basic)
{
    if (info == NULL || basic == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(basic->deviceName, DEVICE_NAME_BUF_LEN, info->deviceInfo.deviceName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s name error!");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(basic->networkId, NETWORK_ID_BUF_LEN, info->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s networkID error!");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(basic->osVersion, OS_VERSION_BUF_LEN, info->deviceInfo.osVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s osVersion error!");
        return SOFTBUS_MEM_ERR;
    }
    basic->deviceTypeId = info->deviceInfo.deviceTypeId;
    basic->osType = info->deviceInfo.osType;
    return SOFTBUS_OK;
}

bool IsMetaNode(NodeInfo *info)
{
    if (info == NULL) {
        return false;
    }
    return info->metaInfo.isMetaNode;
}

static int32_t GetDLOnlineNodeNumLocked(int32_t *infoNum, bool isNeedMeta)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    MapIterator *it = LnnMapInitIterator(&map->udidMap);

    if (it == NULL) {
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    *infoNum = 0;
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return SOFTBUS_NETWORK_MAP_INIT_FAILED;
        }
        info = (NodeInfo *)it->node->value;
        if (!isNeedMeta) {
            if (LnnIsNodeOnline(info)) {
                (*infoNum)++;
            }
        } else {
            if (LnnIsNodeOnline(info) || IsMetaNode(info)) {
                (*infoNum)++;
            }
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static int32_t FillDLOnlineNodeInfoLocked(NodeBasicInfo *info, int32_t infoNum, bool isNeedMeta)
{
    NodeInfo *nodeInfo = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    int32_t i = 0;

    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    while (LnnMapHasNext(it) && i < infoNum) {
        it = LnnMapNext(it);
        if (it == NULL) {
            LnnMapDeinitIterator(it);
            return SOFTBUS_NETWORK_MAP_INIT_FAILED;
        }
        nodeInfo = (NodeInfo *)it->node->value;
        if (!isNeedMeta) {
            if (LnnIsNodeOnline(nodeInfo)) {
                ConvertNodeInfoToBasicInfo(nodeInfo, info + i);
                ++i;
            }
        } else {
            if (LnnIsNodeOnline(nodeInfo) || IsMetaNode(nodeInfo)) {
                ConvertNodeInfoToBasicInfo(nodeInfo, info + i);
                ++i;
            }
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static bool IsNetworkIdChanged(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (newInfo == NULL || oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return false;
    }
    if (strcmp(newInfo->networkId, oldInfo->networkId) == 0) {
        return false;
    }
    return true;
}

void PostOnlineNodesToCb(const INodeStateCb *callBack)
{
    NodeInfo *info = NULL;
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (callBack->onNodeOnline == NULL) {
        LNN_LOGE(LNN_LEDGER, "onNodeOnline IS null!");
        return;
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    if (it == NULL) {
        return;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return;
        }
        info = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(info)) {
            ConvertNodeInfoToBasicInfo(info, &basic);
            callBack->onNodeOnline(&basic);
        }
    }
    LnnMapDeinitIterator(it);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (id == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return info;
    }
    if (type == CATEGORY_UDID) {
        return GetNodeInfoFromMap(map, id);
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    LNN_CHECK_AND_RETURN_RET_LOGE(it != NULL, NULL, LNN_LEDGER, "LnnMapInitIterator is null");

    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        LNN_CHECK_AND_RETURN_RET_LOGE(it != NULL, info, LNN_LEDGER, "it next is null");
        info = (NodeInfo *)it->node->value;
        if (info == NULL) {
            continue;
        }
        if (type == CATEGORY_NETWORK_ID) {
            if (strcmp(info->networkId, id) == 0 ||
                (strlen(info->lastNetworkId) != 0 && strcmp(info->lastNetworkId, id) == 0)) {
                LnnMapDeinitIterator(it);
                return info;
            }
        } else if (type == CATEGORY_UUID) {
            if (strcmp(info->uuid, id) == 0) {
                LnnMapDeinitIterator(it);
                return info;
            }
        } else {
            LNN_LOGE(LNN_LEDGER, "type error");
        }
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

static NodeInfo *LnnGetNodeInfoByDeviceId(const char *id)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    NodeInfo *udidInfo = GetNodeInfoFromMap(map, id);
    if (udidInfo != NULL) {
        return udidInfo;
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    if (it == NULL) {
        return info;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return info;
        }
        info = (NodeInfo *)it->node->value;
        if (info == NULL) {
            continue;
        }
        if (strcmp(info->networkId, id) == 0 ||
            (strlen(info->lastNetworkId) != 0 && strcmp(info->lastNetworkId, id) == 0)) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (strcmp(info->uuid, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (StrCmpIgnoreCase(info->connectInfo.macAddr, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (strcmp(info->connectInfo.deviceIp, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        LNN_LOGE(LNN_LEDGER, "type error");
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    if (id == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        char *anonyId = NULL;
        Anonymize(id, &anonyId);
        LNN_LOGI(LNN_LEDGER, "can not find target node, id=%{public}s, type=%{public}d",
            AnonymizeWrapper(anonyId), type);
        AnonymizeFree(anonyId);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (memcpy_s(info, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

/* key means networkId/udid/uuid/macAddr/ip */
int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    if (key == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoByDeviceId(key);
    if (nodeInfo == NULL) {
        LNN_LOGI(LNN_LEDGER, "can not find target node");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (memcpy_s(info, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    bool state = false;
    if (!IsValidString(id, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "id is invalid");
        return state;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return state;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGI(LNN_LEDGER, "can not find target node");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return state;
    }
    state = (nodeInfo->status == STATUS_ONLINE) ? true : false;
    if (!state) {
        state = nodeInfo->metaInfo.isMetaNode;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return state;
}

static char *CreateCnnCodeKey(const char *uuid, DiscoveryType type)
{
    if (uuid == NULL || strlen(uuid) >= UUID_BUF_LEN) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return NULL;
    }
    char *key = (char *)SoftBusCalloc(INT_TO_STR_SIZE + UUID_BUF_LEN);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "SoftBusCalloc fail!");
        return NULL;
    }
    if (sprintf_s(key, INT_TO_STR_SIZE + UUID_BUF_LEN, "%d%s", type, uuid) == -1) {
        LNN_LOGE(LNN_LEDGER, "type convert char error!");
        goto EXIT_FAIL;
    }
    return key;
EXIT_FAIL:
    SoftBusFree(key);
    return NULL;
}

static void DestroyCnnCodeKey(char *key)
{
    if (key == NULL) {
        return;
    }
    SoftBusFree(key);
}


static int32_t AddCnnCode(Map *cnnCode, const char *uuid, DiscoveryType type, int64_t authSeqNum)
{
    short seq = (short)authSeqNum;
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return SOFTBUS_MEM_ERR;
    }
    if (LnnMapSet(cnnCode, key, (void *)&seq, sizeof(short)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnMapSet error!");
        DestroyCnnCodeKey(key);
        return SOFTBUS_NETWORK_MAP_SET_FAILED;
    }
    DestroyCnnCodeKey(key);
    return SOFTBUS_OK;
}

static void RemoveCnnCode(Map *cnnCode, const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return;
    }
    if (LnnMapErase(cnnCode, key) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnMapErase error!");
    }
    DestroyCnnCodeKey(key);
    return;
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return INVALID_CONNECTION_CODE_VALUE;
    }
    short *ptr = (short *)LnnMapGet(&g_distributedNetLedger.cnnCode.connectionCode, key);
    if (ptr == NULL) {
        LNN_LOGE(LNN_LEDGER, " KEY not exist.");
        DestroyCnnCodeKey(key);
        return INVALID_CONNECTION_CODE_VALUE;
    }
    DestroyCnnCodeKey(key);
    return (*ptr);
}

static void MergeLnnInfo(const NodeInfo *oldInfo, NodeInfo *info)
{
    int32_t i, j;

    for (i = 0; i < CONNECTION_ADDR_MAX; ++i) {
        info->relation[i] += oldInfo->relation[i];
        info->relation[i] &= LNN_RELATION_MASK;
        for (j = 0; j < AUTH_SIDE_MAX; ++j) {
            if (oldInfo->authChannelId[i][j] != 0 && info->authChannelId[i][j] == 0) {
                info->authChannelId[i][j] = oldInfo->authChannelId[i][j];
            }
        }
        if (oldInfo->authChannelId[i][AUTH_AS_CLIENT_SIDE] != 0 ||
            oldInfo->authChannelId[i][AUTH_AS_SERVER_SIDE] != 0 || info->authChannelId[i][AUTH_AS_CLIENT_SIDE] != 0 ||
            info->authChannelId[i][AUTH_AS_SERVER_SIDE] != 0) {
            LNN_LOGD(LNN_LEDGER,
                "Merge authChannelId. authChannelId:%{public}d|%{public}d->%{public}d|%{public}d, addrType=%{public}d",
                oldInfo->authChannelId[i][AUTH_AS_CLIENT_SIDE], oldInfo->authChannelId[i][AUTH_AS_SERVER_SIDE],
                info->authChannelId[i][AUTH_AS_CLIENT_SIDE], info->authChannelId[i][AUTH_AS_SERVER_SIDE], i);
        }
    }
    if (strcpy_s(info->lastNetworkId, NETWORK_ID_BUF_LEN, oldInfo->lastNetworkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "cpy lastNetworkId fail");
    }
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;

    udid = LnnGetDeviceUdid(newInfo);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "no online node newInfo!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_MAP_GET_FAILED;
    }
    if (strcpy_s(oldInfo->lastNetworkId, NETWORK_ID_BUF_LEN, oldInfo->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "old networkId cpy fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(oldInfo->networkId, NETWORK_ID_BUF_LEN, newInfo->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "networkId cpy fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

static void UpdateNewNodeAccountHash(NodeInfo *info)
{
    char accountString[LONG_TO_STRING_MAX_LEN] = {0};
    if (sprintf_s(accountString, LONG_TO_STRING_MAX_LEN, "%" PRId64, info->accountId) == -1) {
        LNN_LOGE(LNN_LEDGER, "long to string fail");
        return;
    }
    LNN_LOGD(LNN_LEDGER, "accountString=%{public}s", accountString);
    int ret = SoftBusGenerateStrHash((uint8_t *)accountString,
        strlen(accountString), (unsigned char *)info->accountHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "account hash fail, ret=%{public}d", ret);
        return;
    }
}

static void CheckUserIdCheckSumChange(NodeInfo *oldInfo, const NodeInfo *newInfo)
{
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    int32_t userIdCheckSum = 0;
    int32_t ret = memcpy_s(&userIdCheckSum, sizeof(int32_t), newInfo->userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy failed! userIdchecksum:%{public}d", userIdCheckSum);
        return;
    }
    if (userIdCheckSum == 0) {
        LNN_LOGW(LNN_LEDGER, "useridchecksum all zero");
        return;
    }
    bool isChange = false;
    ret = memcmp(newInfo->userIdCheckSum, oldInfo->userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != 0) {
        isChange = true;
    }
    NotifyForegroundUseridChange((char *)newInfo->networkId, newInfo->discoveryType, isChange);
    if (isChange) {
        LNN_LOGI(LNN_LEDGER, "userIdCheckSum changed!");
        LnnSetDLConnUserIdCheckSum((char *)newInfo->networkId, userIdCheckSum);
    }
}

static int32_t UpdateFileInfo(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    LnnDumpRemotePtk(oldInfo->remotePtk, newInfo->remotePtk, "update node info");
    if (memcpy_s(oldInfo->remotePtk, PTK_DEFAULT_LEN, newInfo->remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy ptk failed");
        return SOFTBUS_MEM_ERR;
    }
    if (memcmp(newInfo->cipherInfo.key, oldInfo->cipherInfo.key, SESSION_KEY_LENGTH) != 0 ||
        memcmp(newInfo->cipherInfo.iv, oldInfo->cipherInfo.iv, BROADCAST_IV_LEN) != 0) {
        LNN_LOGI(LNN_LEDGER, "remote link key change");
        if (memcpy_s(oldInfo->cipherInfo.key, SESSION_KEY_LENGTH, newInfo->cipherInfo.key, SESSION_KEY_LENGTH) != EOK ||
            memcpy_s(oldInfo->cipherInfo.iv, BROADCAST_IV_LEN, newInfo->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
            LNN_LOGE(LNN_LEDGER, "copy link key failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    if (memcmp(newInfo->rpaInfo.peerIrk, oldInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN) != 0) {
        LNN_LOGI(LNN_LEDGER, "remote irk change");
        if (memcpy_s(oldInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN, newInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN) != EOK) {
            LNN_LOGE(LNN_LEDGER, "copy irk failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    LNN_LOGI(LNN_LEDGER, "update file info success");
    return SOFTBUS_OK;
}

static int32_t UpdateRemoteNodeInfo(NodeInfo *oldInfo, NodeInfo *newInfo, int32_t connectionType, char *deviceName)
{
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnHasDiscoveryType(newInfo, DISCOVERY_TYPE_WIFI) || LnnHasDiscoveryType(newInfo, DISCOVERY_TYPE_LSA)) {
        oldInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
        oldInfo->connectInfo.authPort = newInfo->connectInfo.authPort;
        oldInfo->connectInfo.proxyPort = newInfo->connectInfo.proxyPort;
        oldInfo->connectInfo.sessionPort = newInfo->connectInfo.sessionPort;
    }
    if (deviceName != NULL) {
        if (strcpy_s(deviceName, DEVICE_NAME_BUF_LEN, oldInfo->deviceInfo.deviceName) != EOK) {
            LNN_LOGE(LNN_LEDGER, "strcpy_s fail");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.deviceName) != EOK ||
        strcpy_s(oldInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.nickName) != EOK ||
        strcpy_s(oldInfo->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.unifiedName) != EOK ||
        strcpy_s(oldInfo->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN,
            newInfo->deviceInfo.unifiedDefaultName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(oldInfo->accountHash, SHA_256_HASH_LEN, newInfo->accountHash, SHA_256_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy account hash failed");
        return SOFTBUS_MEM_ERR;
    }
    if (UpdateFileInfo(newInfo, oldInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update file info failed");
        return SOFTBUS_MEM_ERR;
    }
    oldInfo->accountId = newInfo->accountId;
    oldInfo->userId = newInfo->userId;
    if (connectionType == CONNECTION_ADDR_BLE) {
        oldInfo->localStateVersion = newInfo->localStateVersion;
        oldInfo->stateVersion = newInfo->stateVersion;
    }
    return SOFTBUS_OK;
}

static int32_t RemoteNodeInfoRetrieve(NodeInfo *newInfo, int32_t connectionType)
{
    if (newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)newInfo->deviceInfo.deviceUdid,
        strlen(newInfo->deviceInfo.deviceUdid), udidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate udidhash fail");
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
        SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert udidhash to hexstr fail");
        return ret;
    }
    ret = LnnRetrieveDeviceInfo(hashStr, &deviceInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "no this device info.");
        return ret;
    }
    ret = UpdateRemoteNodeInfo(&deviceInfo, newInfo, connectionType, NULL);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = LnnSaveRemoteDeviceInfo(&deviceInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save remote devInfo fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    bool isIrkChanged = false;
    char deviceName[DEVICE_NAME_BUF_LEN] = { 0 };
    UpdateNewNodeAccountHash(newInfo);
    UpdateDpSameAccount(newInfo->accountId, newInfo->deviceInfo.deviceUdid, newInfo->userId);
    udid = LnnGetDeviceUdid(newInfo);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "no online node newInfo!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_MAP_GET_FAILED;
    }
    if (memcmp(newInfo->rpaInfo.peerIrk, oldInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN) != 0) {
        isIrkChanged = true;
    }
    int32_t ret = UpdateRemoteNodeInfo(oldInfo, newInfo, connectionType, deviceName);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return ret;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    if (memcmp(deviceName, newInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN) != 0) {
        UpdateDeviceNameInfo(newInfo->deviceInfo.deviceUdid, deviceName);
    }
    if (isIrkChanged) {
        LnnInsertLinkFinderInfo(oldInfo->networkId);
    }
    CheckUserIdCheckSumChange(oldInfo, newInfo);
    ret = RemoteNodeInfoRetrieve(newInfo, connectionType);
    return ret;
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnAddMetaInfo lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL && strcmp(oldInfo->networkId, info->networkId) == 0) {
        LNN_LOGI(LNN_LEDGER, "old capa=%{public}u new capa=%{public}u", oldInfo->netCapacity, info->netCapacity);
        oldInfo->connectInfo.sessionPort = info->connectInfo.sessionPort;
        oldInfo->connectInfo.authPort = info->connectInfo.authPort;
        oldInfo->connectInfo.proxyPort = info->connectInfo.proxyPort;
        oldInfo->netCapacity = info->netCapacity;
        if (strcpy_s(oldInfo->connectInfo.deviceIp, IP_LEN, info->connectInfo.deviceIp) != EOK) {
            LNN_LOGE(LNN_LEDGER, "strcpy ip fail!");
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcpy_s(oldInfo->uuid, UUID_BUF_LEN, info->uuid) != EOK) {
            LNN_LOGE(LNN_LEDGER, "strcpy uuid fail!");
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_STRCPY_ERR;
        }
        MetaInfo temp = info->metaInfo;
        if (memcpy_s(info, sizeof(NodeInfo), oldInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "LnnAddMetaInfo copy fail!");
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_MEM_ERR;
        }
        info->metaInfo.isMetaNode = true;
        info->metaInfo.metaDiscType = info->metaInfo.metaDiscType | temp.metaDiscType;
    }
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    LNN_LOGI(LNN_LEDGER, "LnnAddMetaInfo success");
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type)
{
    NodeInfo *info = NULL;
    DiscoveryType discType = ConvertToDiscoveryType(type);
    if (discType == DISCOVERY_TYPE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "DeleteMetaInfo type error fail!");
        return SOFTBUS_NETWORK_DELETE_INFO_ERR;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "DeleteAddMetaInfo lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "DeleteAddMetaInfo para error!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_DELETE_INFO_ERR;
    }
    info->metaInfo.metaDiscType = (uint32_t)info->metaInfo.metaDiscType & ~(1 << (uint32_t)discType);
    if (info->metaInfo.metaDiscType == 0) {
        info->metaInfo.isMetaNode = false;
    }
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    (void)memset_s(info->remoteMetaPtk, PTK_DEFAULT_LEN, 0, PTK_DEFAULT_LEN);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    LNN_LOGI(LNN_LEDGER, "LnnDeleteMetaInfo success, discType=%{public}d", discType);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

static void OnlinePreventBrConnection(const NodeInfo *info)
{
    int32_t osType = 0;
    if (LnnGetOsTypeByNetworkId(info->networkId, &osType)) {
        LNN_LOGE(LNN_LEDGER, "get remote osType fail");
    }
    if (osType != HO_OS_TYPE) {
        LNN_LOGD(LNN_LEDGER, "not pend br connection");
        return;
    }
    const NodeInfo *localNodeInfo = LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get local node info fail");
        return;
    }
    ConnectOption option;
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, info->connectInfo.macAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy br mac fail");
        return;
    }
    bool preventFlag = false;
    do {
        LNN_LOGI(LNN_LEDGER, "check the ble start timestamp, local=%{public}" PRId64", peer=%{public}" PRId64"",
            localNodeInfo->bleStartTimestamp, info->bleStartTimestamp);
        if (localNodeInfo->bleStartTimestamp < info->bleStartTimestamp) {
            LNN_LOGI(LNN_LEDGER, "peer later, prevent br connection");
            preventFlag = true;
            break;
        }
        if (localNodeInfo->bleStartTimestamp > info->bleStartTimestamp) {
            LNN_LOGI(LNN_LEDGER, "local later, do not prevent br connection");
            break;
        }
        if (strcmp(info->softBusVersion, SOFTBUS_VERSION_FOR_INITCONNECTFLAG) < 0) {
            LNN_LOGI(LNN_LEDGER, "peer is old version, peerVersion=%{public}s", info->softBusVersion);
            preventFlag = true;
            break;
        }
        if (strcmp(info->networkId, localNodeInfo->networkId) <= 0) {
            LNN_LOGI(LNN_LEDGER, "peer network id is smaller");
            preventFlag = true;
            break;
        }
    } while (false);
    if (preventFlag) {
        LNN_LOGI(LNN_LEDGER, "prevent br connection for a while");
        ConnPreventConnection(&option, CONNECTION_FREEZE_TIMEOUT_MILLIS);
    }
}

static void NotifyMigrateUpgrade(NodeInfo *info)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(info->deviceInfo.deviceUdid, &basic) == SOFTBUS_OK) {
        LnnNotifyMigrate(true, &basic);
    } else {
        LNN_LOGE(LNN_LEDGER, "NotifyMigrateUpgrade, GetBasicInfoByUdid fail!");
    }
}

static void FilterWifiInfo(NodeInfo *info)
{
    (void)LnnClearDiscoveryType(info, DISCOVERY_TYPE_WIFI);
    info->authChannelId[CONNECTION_ADDR_WLAN][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[CONNECTION_ADDR_WLAN][AUTH_AS_SERVER_SIDE] = 0;
}

static void FilterBrInfo(NodeInfo *info)
{
    (void)LnnClearDiscoveryType(info, DISCOVERY_TYPE_BR);
    info->authChannelId[CONNECTION_ADDR_BR][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[CONNECTION_ADDR_BR][AUTH_AS_SERVER_SIDE] = 0;
}

static bool IsDeviceInfoChanged(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGI(LNN_LEDGER, "invalid param");
        return false;
    }
    NodeInfo deviceInfo;
    if (memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
        return false;
    }
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "generate udidhash fail");
        return false;
    }
    if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
        SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "convert udidhash to hexstr fail");
        return false;
    }
    int32_t ret = LnnRetrieveDeviceInfo(hashStr, &deviceInfo);
    if (ret == SOFTBUS_NETWORK_NOT_FOUND) {
        return true;
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "get deviceInfo by udidhash fail");
        return false;
    }
    return memcmp(info, &deviceInfo, (size_t)&(((NodeInfo *)0)->relation)) != 0 ? true : false;
}

static void GetAndSaveRemoteDeviceInfo(NodeInfo *deviceInfo, NodeInfo *info)
{
    if (strcpy_s(deviceInfo->networkId, sizeof(deviceInfo->networkId), info->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
        return;
    }
    if (strcpy_s(deviceInfo->uuid, sizeof(deviceInfo->uuid), info->uuid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s uuid fail");
        return;
    }
    if (memcpy_s(deviceInfo->rpaInfo.peerIrk, sizeof(deviceInfo->rpaInfo.peerIrk), info->rpaInfo.peerIrk,
            sizeof(info->rpaInfo.peerIrk)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s Irk fail");
        return;
    }
    if (memcpy_s(deviceInfo->cipherInfo.key, sizeof(deviceInfo->cipherInfo.key), info->cipherInfo.key,
            sizeof(info->cipherInfo.key)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo.key fail");
        return;
    }
    if (memcpy_s(deviceInfo->cipherInfo.iv, sizeof(deviceInfo->cipherInfo.iv), info->cipherInfo.iv,
            sizeof(info->cipherInfo.iv)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo.iv fail");
        return;
    }
    LnnDumpRemotePtk(deviceInfo->remotePtk, info->remotePtk, "get and save remote device info");
    if (memcpy_s(deviceInfo->remotePtk, PTK_DEFAULT_LEN, info->remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s ptk fail");
        return;
    }
    deviceInfo->netCapacity = info->netCapacity;
    deviceInfo->accountId = info->accountId;
    if (LnnSaveRemoteDeviceInfo(deviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save remote devInfo fail");
        return;
    }
    return;
}

static void BleDirectlyOnlineProc(NodeInfo *info)
{
    if (!LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)) {
        NodeInfo deviceInfo;
        if (memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
        }
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
        if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
            strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate udidhash fail");
            return;
        }
        if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
            SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "convert udidhash to hexstr fail");
            return;
        }
        if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "get deviceInfo by udidhash fail");
            return;
        }
        char *anonyDevNetworkId = NULL;
        char *anonyNetworkId = NULL;
        Anonymize(deviceInfo.networkId, &anonyDevNetworkId);
        Anonymize(info->networkId, &anonyNetworkId);
        LNN_LOGI(LNN_LEDGER, "oldNetworkId=%{public}s, newNetworkid=%{public}s",
            AnonymizeWrapper(anonyDevNetworkId), AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyDevNetworkId);
        AnonymizeFree(anonyNetworkId);
        GetAndSaveRemoteDeviceInfo(&deviceInfo, info);
        (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        return;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI)) {
        FilterWifiInfo(info);
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        FilterBrInfo(info);
    }
    if (IsDeviceInfoChanged(info)) {
        LNN_LOGI(LNN_LEDGER, "device info changed");
        if (LnnSaveRemoteDeviceInfo(info) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "save remote devInfo fail");
        }
    } else {
        LnnUpdateRemoteDeviceInfo(info);
    }
}

static void NodeOnlineProc(NodeInfo *info)
{
    NodeInfo nodeInfo;
    if (memcpy_s(&nodeInfo, sizeof(nodeInfo), info, sizeof(NodeInfo)) != EOK) {
        return;
    }
    BleDirectlyOnlineProc(&nodeInfo);
}

static void GetNodeInfoDiscovery(NodeInfo *oldInfo, NodeInfo *info, NodeInfoAbility *infoAbility)
{
    infoAbility->isOffline = true;
    infoAbility->oldWifiFlag = false;
    infoAbility->oldBrFlag = false;
    infoAbility->oldBleFlag = false;
    infoAbility->isChanged = false;
    infoAbility->isMigrateEvent = false;
    infoAbility->isNetworkChanged = false;
    infoAbility->newWifiFlag = LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI);
    infoAbility->newBleBrFlag =
        LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE) || LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR);
    if (oldInfo != NULL) {
        info->metaInfo = oldInfo->metaInfo;
    }
    if (oldInfo != NULL && LnnIsNodeOnline(oldInfo)) {
        char *anonyUuid = NULL;
        Anonymize(oldInfo->uuid, &anonyUuid);
        LNN_LOGI(LNN_LEDGER, "addOnlineNode find online node, uuid=%{public}s", AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        infoAbility->isOffline = false;
        infoAbility->isChanged = IsNetworkIdChanged(info, oldInfo);
        infoAbility->oldWifiFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_WIFI);
        infoAbility->oldBleFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BLE);
        infoAbility->oldBrFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BR);
        if ((infoAbility->oldBleFlag || infoAbility->oldBrFlag) && infoAbility->newWifiFlag) {
            NewWifiDiscovered(oldInfo, info);
            infoAbility->isNetworkChanged = true;
        } else if (infoAbility->oldWifiFlag && infoAbility->newBleBrFlag) {
            RetainOfflineCode(oldInfo, info);
            NewBrBleDiscovered(oldInfo, info);
            infoAbility->isNetworkChanged = true;
        } else {
            RetainOfflineCode(oldInfo, info);
            LNN_LOGE(LNN_LEDGER, "flag error, oldBleFlag=%{public}d, oldBrFlag=%{public}d, oldWifiFlag=%{public}d,"
                "newWifiFlag=%{public}d, newBleBrFlag=%{public}d", infoAbility->oldBleFlag, infoAbility->oldBrFlag,
                infoAbility->oldWifiFlag, infoAbility->newBleBrFlag, infoAbility->newBleBrFlag);
        }
        if ((infoAbility->oldBleFlag || infoAbility->oldBrFlag) && !infoAbility->oldWifiFlag &&
            infoAbility->newWifiFlag) {
            infoAbility->isMigrateEvent = true;
        }
        // update lnn discovery type
        info->discoveryType |= oldInfo->discoveryType;
        info->AuthTypeValue = oldInfo->AuthTypeValue;
        info->heartbeatTimestamp = oldInfo->heartbeatTimestamp;
        MergeLnnInfo(oldInfo, info);
        UpdateProfile(info);
    }
}

static void DfxRecordLnnSetNodeOfflineEnd(const char *udid, int32_t onlineNum, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.onlineNum = onlineNum;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    char udidData[UDID_BUF_LEN] = { 0 };
    if (udid != NULL && strnlen(udid, UDID_BUF_LEN) != UDID_BUF_LEN && strncpy_s(udidData,
        UDID_BUF_LEN, udid, UDID_BUF_LEN - 1) == EOK) {
        extra.peerUdid = udidData;
    }
    LNN_EVENT(EVENT_SCENE_LEAVE_LNN, EVENT_STAGE_LEAVE_LNN, extra);
}

static void TryUpdateDeviceSecurityLevel(NodeInfo *info)
{
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate udidhash fail");
        return;
    }
    if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
        SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert udidhash to hexstr fail");
        return;
    }
    if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get deviceInfo by udidhash fail");
        return;
    }
    LNN_LOGI(LNN_LEDGER, "deviceSecurityLevel new=%{public}d, old=%{public}d",
        info->deviceSecurityLevel, deviceInfo.deviceSecurityLevel);
    if (deviceInfo.deviceSecurityLevel > 0) {
        info->deviceSecurityLevel = deviceInfo.deviceSecurityLevel;
    }
}

static void ReversionLastAuthSeq(NodeInfo *info)
{
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate udidhash fail");
        return;
    }
    if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
        SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert udidhash to hexstr fail");
        return;
    }
    if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get deviceInfo by udidhash fail");
        return;
    }
    if (info->lastAuthSeq == 0 && deviceInfo.lastAuthSeq != 0) {
        info->lastAuthSeq = deviceInfo.lastAuthSeq;
        LNN_LOGI(LNN_LEDGER, "reversion lastAuthSeq:0->%{public}" PRId64, info->lastAuthSeq);
    }
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    if (info == NULL) {
        return REPORT_NONE;
    }
    // judge map
    info->onlinetTimestamp = (uint64_t)LnnUpTimeMs();
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        LNN_LOGI(LNN_LEDGER, "DiscoveryType = BR.");
        AddCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR, info->authSeqNum);
    }

    NodeInfoAbility infoAbility;
    const char *udid = LnnGetDeviceUdid(info);
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return REPORT_NONE;
    }
    NodeInfo *oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    GetNodeInfoDiscovery(oldInfo, info, &infoAbility);
    LnnSetNodeConnStatus(info, STATUS_ONLINE);
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    UpdateNewNodeAccountHash(info);
    TryUpdateDeviceSecurityLevel(info);
    ReversionLastAuthSeq(info);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    NodeOnlineProc(info);
    UpdateDpSameAccount(info->accountId, info->deviceInfo.deviceUdid, info->userId);
    if (infoAbility.isNetworkChanged) {
        UpdateNetworkInfo(info->deviceInfo.deviceUdid);
    }
    if (infoAbility.isOffline) {
        if (!infoAbility.oldWifiFlag && !infoAbility.newWifiFlag && infoAbility.newBleBrFlag) {
            OnlinePreventBrConnection(info);
        }
        InsertToProfile(info);
        return REPORT_ONLINE;
    }
    if (infoAbility.isMigrateEvent) {
        NotifyMigrateUpgrade(info);
    }
    if (infoAbility.isChanged) {
        return REPORT_CHANGE;
    }
    return REPORT_NONE;
}

int32_t LnnUpdateAccountInfo(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);

    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        oldInfo->accountId = info->accountId;
        UpdateNewNodeAccountHash(oldInfo);
        oldInfo->userId = info->userId;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    bool isNeedUpdate = false;
    udid = LnnGetDeviceUdid(info);

    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);

    do {
        if (oldInfo == NULL) {
            LNN_LOGE(LNN_LEDGER, "oldInfo is null");
            break;
        }
        isNeedUpdate = (strcmp(oldInfo->deviceInfo.deviceName, info->deviceInfo.deviceName) != 0);
        if (!isNeedUpdate) {
            LNN_LOGI(LNN_LEDGER, "devicename not change");
            break;
        }
        if (strcpy_s(oldInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN,
            info->deviceInfo.deviceName) != EOK) {
            isNeedUpdate = false;
            LNN_LOGE(LNN_LEDGER, "strcpy_s fail");
            break;
        }
        if (ConvertNodeInfoToBasicInfo(oldInfo, &basic) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "ConvertNodeInfoToBasicInfo fail");
            isNeedUpdate = false;
            break;
        }
    } while (false);

    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    if (isNeedUpdate) {
        char *anonyDeviceName = NULL;
        Anonymize(basic.deviceName, &anonyDeviceName);
        LNN_LOGI(LNN_LEDGER, "report deviceName update, name=%{public}s", AnonymizeWrapper(anonyDeviceName));
        AnonymizeFree(anonyDeviceName);
        LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    }
    return SOFTBUS_OK;
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);
    uint32_t groupType = AuthGetGroupType(udid, info->uuid);
    LNN_LOGI(LNN_LEDGER, "groupType=%{public}u", groupType);
    int32_t ret = SOFTBUS_NETWORK_MAP_GET_FAILED;
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        oldInfo->groupType = groupType;
        ret = SOFTBUS_OK;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

static void NotifyMigrateDegrade(const char *udid)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) == SOFTBUS_OK) {
        LnnNotifyMigrate(false, &basic);
    } else {
        LNN_LOGE(LNN_LEDGER, "NotifyMigrateDegrade, GetBasicInfoByUdid fail!");
    }
}

static ReportCategory ClearAuthChannelId(NodeInfo *info, ConnectionAddrType type, int32_t authId)
{
    if ((LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_WIFI) ||
        (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_BLE)) {
        if (info->authChannelId[type][AUTH_AS_CLIENT_SIDE] == authId) {
            info->authChannelId[type][AUTH_AS_CLIENT_SIDE] = 0;
        }
        if (info->authChannelId[type][AUTH_AS_SERVER_SIDE] == authId) {
            info->authChannelId[type][AUTH_AS_SERVER_SIDE] = 0;
        }
        if (info->authChannelId[type][AUTH_AS_CLIENT_SIDE] != 0 ||
            info->authChannelId[type][AUTH_AS_SERVER_SIDE] != 0) {
            LNN_LOGI(LNN_LEDGER,
                "authChannelId not clear, not need to report offline. authChannelId=%{public}d|%{public}d",
                info->authChannelId[type][AUTH_AS_CLIENT_SIDE], info->authChannelId[type][AUTH_AS_SERVER_SIDE]);
            return REPORT_NONE;
        }
    }
    info->authChannelId[type][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[type][AUTH_AS_SERVER_SIDE] = 0;
    return REPORT_OFFLINE;
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    NodeInfo *info = NULL;

    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return REPORT_NONE;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    if (type != CONNECTION_ADDR_MAX && info->relation[type] > 0) {
        info->relation[type]--;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_BR) {
        RemoveCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR);
    }
    if (ClearAuthChannelId(info, type, authId) == REPORT_NONE) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    if (LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_WIFI) {
        LnnSetWiFiIp(info, LOCAL_IP);
    }
    LnnClearDiscoveryType(info, LnnConvAddrTypeToDiscType(type));
    if (info->discoveryType != 0) {
        LNN_LOGI(LNN_LEDGER, "after clear, not need to report offline. discoveryType=%{public}u", info->discoveryType);
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        UpdateNetworkInfo(udid);
        if (type == CONNECTION_ADDR_WLAN) {
            NotifyMigrateDegrade(udid);
        }
        return REPORT_NONE;
    }
    if (!LnnIsNodeOnline(info)) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        LNN_LOGI(LNN_LEDGER, "the state is already offline, no need to report offline");
        return REPORT_NONE;
    }
    LnnSetNodeConnStatus(info, STATUS_OFFLINE);
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGI(LNN_LEDGER, "need to report offline");
    DfxRecordLnnSetNodeOfflineEnd(udid, (int32_t)MapGetSize(&map->udidMap), SOFTBUS_OK);
    return REPORT_OFFLINE;
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    if (udid == NULL || basicInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return SOFTBUS_INVALID_PARAM;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    int32_t ret = ConvertNodeInfoToBasicInfo(info, basicInfo);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

void LnnRemoveNode(const char *udid)
{
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (udid == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return;
    }
    LnnMapErase(&map->udidMap, udid);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    NodeInfo *info = NULL;
    if (id == NULL) {
        return NULL;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "uuid not find node info.");
        return NULL;
    }
    return LnnGetDeviceUdid(info);
}

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    NodeInfo *info = NULL;
    const char *id = NULL;
    int32_t rc = SOFTBUS_OK;

    if (srcId == NULL || dstIdBuf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(srcId, srcIdType);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "no node info srcIdType=%{public}d", srcIdType);
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    switch (dstIdType) {
        case CATEGORY_UDID:
            id = info->deviceInfo.deviceUdid;
            break;
        case CATEGORY_UUID:
            id = info->uuid;
            break;
        case CATEGORY_NETWORK_ID:
            id = info->networkId;
            break;
        default:
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(dstIdBuf, dstIdBufLen, id) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy id fail");
        rc = SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return rc;
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    NodeInfo *info = NULL;

    if (id == NULL || relation == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL || !LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node not online");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(relation, len, info->relation, CONNECTION_ADDR_MAX) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy relation fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

static void UpdateDevBasicInfoToDLedger(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (strcmp(newInfo->networkId, oldInfo->networkId) == 0 || oldInfo->status != STATUS_ONLINE ||
        !LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BLE)) {
        oldInfo->stateVersion = newInfo->stateVersion;
    }

    if (strcpy_s(oldInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.deviceName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceName to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.unifiedName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s unifiedName to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.unifiedDefaultName) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s unifiedDefaultName to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.nickName) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s nickName to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceUdid, UDID_BUF_LEN, newInfo->deviceInfo.deviceUdid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceUdid to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, newInfo->deviceInfo.deviceVersion) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s deviceVersion to distributed ledger fail");
    }
    oldInfo->deviceInfo.deviceTypeId = newInfo->deviceInfo.deviceTypeId;
    oldInfo->isBleP2p = newInfo->isBleP2p;
    oldInfo->supportedProtocols = newInfo->supportedProtocols;
    oldInfo->wifiVersion = newInfo->wifiVersion;
    oldInfo->bleVersion = newInfo->bleVersion;
    oldInfo->accountId = newInfo->accountId;
    oldInfo->feature = newInfo->feature;
    oldInfo->connSubFeature = newInfo->connSubFeature;
    oldInfo->authCapacity = newInfo->authCapacity;
    oldInfo->deviceInfo.osType = newInfo->deviceInfo.osType;
    oldInfo->updateTimestamp = newInfo->updateTimestamp;
    oldInfo->deviceSecurityLevel = newInfo->deviceSecurityLevel;
}

static void UpdateDistributedLedger(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (newInfo == NULL || oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return;
    }
    if (strcpy_s(oldInfo->softBusVersion, VERSION_MAX_LEN, newInfo->softBusVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s softBusVersion to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->pkgVersion, VERSION_MAX_LEN, newInfo->pkgVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s pkgVersion to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->connectInfo.macAddr, MAC_LEN, newInfo->connectInfo.macAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s macAddr to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->deviceInfo.osVersion, OS_VERSION_BUF_LEN, newInfo->deviceInfo.osVersion) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s osVersion to distributed ledger fail");
    }
    if (strcpy_s(oldInfo->p2pInfo.p2pMac, MAC_LEN, newInfo->p2pInfo.p2pMac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s p2pMac to distributed ledger fail");
    }
    if (memcpy_s((char *)oldInfo->rpaInfo.peerIrk, LFINDER_IRK_LEN, (char *)newInfo->rpaInfo.peerIrk,
        LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s peerIrk to distributed ledger fail");
    }
    if (memcpy_s((char *)oldInfo->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, (char *)newInfo->rpaInfo.publicAddress,
        LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s publicAddress to distributed ledger fail");
    }
    if (memcpy_s((char *)oldInfo->cipherInfo.key, SESSION_KEY_LENGTH, newInfo->cipherInfo.key, SESSION_KEY_LENGTH) !=
        EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo key to distributed ledger fail");
    }
    if (memcpy_s((char *)oldInfo->cipherInfo.iv, BROADCAST_IV_LEN, newInfo->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s cipherInfo iv to distributed ledger fail");
    }
    UpdateDevBasicInfoToDLedger(newInfo, oldInfo);
}

static bool IsIgnoreUpdateToLedger(
    int32_t oldStateVersion, uint64_t oldTimestamp, int32_t newStateVersion, uint64_t newTimestamp)
{
    bool isIgnore = oldTimestamp > newTimestamp || (oldTimestamp == 0 && oldStateVersion > newStateVersion);
    if (isIgnore) {
        LNN_LOGE(LNN_BUILDER,
            "sync info is older, oldDLeger.stateVersion=%{public}d, oldDLegerTimestamp=%{public}" PRIu64
            ", newSyncInfo.stateVersion=%{public}d, newTimestamp=%{public}" PRIu64 "",
            oldStateVersion, oldTimestamp, newStateVersion, newTimestamp);
    }
    return isIgnore;
}

int32_t LnnUpdateDistributedNodeInfo(NodeInfo *newInfo, const char *udid)
{
    if (newInfo == NULL || udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        LNN_LOGI(LNN_LEDGER, "no this device info in ledger, need to insert");
        int32_t ret = LnnMapSet(&map->udidMap, udid, newInfo, sizeof(NodeInfo));
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_NETWORK_MAP_SET_FAILED;
        }
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        LNN_LOGD(LNN_LEDGER, "DB data new device nodeinfo insert to distributed ledger success.");
        return SOFTBUS_OK;
    }
    if (IsIgnoreUpdateToLedger(oldInfo->stateVersion, oldInfo->updateTimestamp, newInfo->stateVersion,
        newInfo->updateTimestamp)) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_OK;
    }
    UpdateDistributedLedger(newInfo, oldInfo);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGD(LNN_LEDGER, "DB data update to distributed ledger success.");
    return SOFTBUS_OK;
}

static int32_t GetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum, bool isNeedMeta)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGE(LNN_LEDGER, "key params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    do {
        *info = NULL;
        if (GetDLOnlineNodeNumLocked(infoNum, isNeedMeta) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "get online node num failed");
            break;
        }
        if (*infoNum == 0) {
            ret = SOFTBUS_OK;
            break;
        }
        *info = (NodeBasicInfo*)SoftBusCalloc((*infoNum) * sizeof(NodeBasicInfo));
        if (*info == NULL) {
            LNN_LOGE(LNN_LEDGER, "malloc node info buffer failed");
            break;
        }
        if (FillDLOnlineNodeInfoLocked(*info, *infoNum, isNeedMeta) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "fill online node num failed");
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    if (ret != SOFTBUS_OK) {
        if (*info != NULL) {
            SoftBusFree(*info);
            *info = NULL;
        }
        *infoNum = 0;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    NodeInfo *nodeInfo = LnnGetNodeInfoById(info->networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo != NULL && LnnHasDiscoveryType(nodeInfo, DISCOVERY_TYPE_LSA)) {
        return true;
    }
    return false;
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    if (nodeNum == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    /* node num include meta node */
    if (GetDLOnlineNodeNumLocked(nodeNum, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get online node num failed");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetAllOnlineAndMetaNodeInfo(info, infoNum, false);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetAllOnlineAndMetaNodeInfo(info, infoNum, true);
}

int32_t SoftBusDumpBusCenterRemoteDeviceInfo(int32_t fd)
{
    SOFTBUS_DPRINTF(fd, "-----RemoteDeviceInfo-----\n");
    NodeBasicInfo *remoteNodeInfo = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&remoteNodeInfo, &infoNum) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetAllOnlineNodeInfo failed");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    }
    SOFTBUS_DPRINTF(fd, "remote device num = %d\n", infoNum);
    for (int32_t i = 0; i < infoNum; i++) {
        SOFTBUS_DPRINTF(fd, "\n[NO.%d]\n", i + 1);
        SoftBusDumpBusCenterPrintInfo(fd, remoteNodeInfo + i);
    }
    SoftBusFree(remoteNodeInfo);
    return SOFTBUS_OK;
}

int32_t LnnInitDistributedLedger(void)
{
    if (g_distributedNetLedger.status == DL_INIT_SUCCESS) {
        LNN_LOGI(LNN_LEDGER, "Distributed Ledger already init");
        return SOFTBUS_OK;
    }

    int32_t ret = InitDistributedInfo(&g_distributedNetLedger.distributedInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "InitDistributedInfo ERROR");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return ret;
    }

    ret = InitConnectionCode(&g_distributedNetLedger.cnnCode);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "InitConnectionCode ERROR");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return ret;
    }
    if (SoftBusMutexInit(&g_distributedNetLedger.lock, NULL) != SOFTBUS_OK) {
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_LOCK_ERR;
    }
    ret = SoftBusRegBusCenterVarDump((char*)SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO,
        &SoftBusDumpBusCenterRemoteDeviceInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftBusRegBusCenterVarDump regist fail");
        return ret;
    }
    g_distributedNetLedger.status = DL_INIT_SUCCESS;
    return SOFTBUS_OK;
}

const NodeInfo *LnnGetOnlineNodeByUdidHash(const char *recvUdidHash)
{
    int32_t i;
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    unsigned char shortUdidHash[SHORT_UDID_HASH_LEN + 1] = {0};

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all online node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        if (info != NULL) {
            SoftBusFree(info);
        }
        return NULL;
    }
    for (i = 0; i < infoNum; ++i) {
        const NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            LNN_LOGI(LNN_LEDGER, "nodeInfo is null");
            continue;
        }
        if (GenerateStrHashAndConvertToHexString((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
            SHORT_UDID_HASH_LEN, shortUdidHash, SHORT_UDID_HASH_LEN + 1) != SOFTBUS_OK) {
            continue;
        }
        if (memcmp(shortUdidHash, recvUdidHash, SHORT_UDID_HASH_LEN) == 0) {
            char *anoyUdid = NULL;
            char *anoyUdidHash = NULL;
            Anonymize(nodeInfo->deviceInfo.deviceUdid, &anoyUdid);
            Anonymize((const char *)shortUdidHash, &anoyUdidHash);
            LNN_LOGI(LNN_LEDGER, "node is online. nodeUdid=%{public}s, shortUdidHash=%{public}s",
                AnonymizeWrapper(anoyUdid), AnonymizeWrapper(anoyUdidHash));
            AnonymizeFree(anoyUdid);
            AnonymizeFree(anoyUdidHash);
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static void RefreshDeviceOnlineStateInfo(DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    if (additions->medium == COAP || additions->medium == BLE) {
        device->isOnline = ((LnnGetOnlineNodeByUdidHash(device->devId)) != NULL) ? true : false;
    }
}

void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions)
{
    (void)pkgName;
    RefreshDeviceOnlineStateInfo(device, additions);
    if (device->devId[0] != '\0') {
        char *anoyUdidHash = NULL;
        Anonymize(device->devId, &anoyUdidHash);
        LNN_LOGI(LNN_LEDGER, "device found. medium=%{public}d, udidhash=%{public}s, onlineStatus=%{public}d",
            additions->medium, AnonymizeWrapper(anoyUdidHash), device->isOnline);
        AnonymizeFree(anoyUdidHash);
    }
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    if (networkId == NULL || osType == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LEDGER, "get info by networkId=%{public}s failed", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NOT_FIND;
    }
    *osType = nodeInfo->deviceInfo.osType;
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

bool IsAvailableMeta(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetAuthType fail, ret=%{public}d", ret);
        return false;
    }
    return ((uint32_t)value & (1 << ONLINE_METANODE));
}

bool IsRemoteDeviceSupportBleGuide(const char *id, IdCategory type)
{
    if (id == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return true;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return true;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        char *anonyUuid = NULL;
        Anonymize(id, &anonyUuid);
        LNN_LOGW(LNN_LEDGER, "get info by id=%{public}s, type=%{public}d", AnonymizeWrapper(anonyUuid), type);
        AnonymizeFree(anonyUuid);
        return false;
    }
    if (!nodeInfo->isSupportSv && !nodeInfo->isBleP2p && nodeInfo->deviceInfo.deviceTypeId == TYPE_TV_ID) {
        LNN_LOGI(LNN_LEDGER,
            "peer device unsupport ble guide, isSupportSv=%{public}d, isBleP2p=%{public}d, deviceTypeId=%{public}d",
            nodeInfo->isSupportSv, nodeInfo->isBleP2p, nodeInfo->deviceInfo.deviceTypeId);
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return false;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
}